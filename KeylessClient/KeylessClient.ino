#include <ESP8266WiFi.h>
#include <LittleFS.h>
#include <SimpleFTPServer.h>
#include <OPTIGATrustM.h>

// MbedTLS includes
#include "mbedtls/config.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include "csr.h"

#define OPTIGA_TRUST_M_RESET_GPIO  12
#define OPTIGA_TRUST_M_POWER_GPIO  13
#define FTP_MODE_GPIO              14
#define KEY_LEN    256       // Bytes (2048 bit)
#define KEY_MAXLEN 300
#define SIG_LEN    KEY_LEN
#define HASH_LEN    32       // SHA256
#define UID_LENGTH  27

// WiFi settings
const char* ssid     = "xxxxxxxxxx";
const char* password = "xxxxxxxxxx";

// Keyless server
const char* servername = "192.168.1.9";

// CSR/certificate settings
const char* countryName      = "DE";
const char* state            = "BW";
const char* locality         = "Heimsheim";
const char* organizationName = "Geiger";
const char* commonName       = "Key";

FtpServer ftpSrv;
WiFiClient client;

uint8_t ftp_mode;
uint8_t request_service_buf[1000];
uint8_t challenge_buf[HASH_LEN + 3];
uint8_t authgrant_buf[1];
uint8_t sig_buf[SIG_LEN + 3];
uint16_t sig_bytes = SIG_LEN;

enum MessageId
{
    REQUEST_SERVICE_MSG           = 0x40,
    SIGNATURE_MSG                 = 0x41
}; 

enum RequestServiceResponseCode
{
    VALID_CHALLENGE               = 0x60,
    UNEXPECTED_ERROR_OCCURED_1    = 0x61,
    VALUE_ERROR                   = 0x62,
    ERROR_LOADING_CERTIFICATE     = 0x63,
    INVALID_CA_AUTHENTICATION     = 0x64,
    INVALID_CERTIFICATE_DATA      = 0x65,
    EXPIRED_CERTIFICATE           = 0x66,
    TIME_DELAY_NOT_EXPIRED        = 0x67,
    REVOKED_CERTIFICATE           = 0x68
};

enum SignatureResponseCode
{
    AUTHORIZATION_GRANTED         = 0x70,
    UNEXPECTED_ERROR_OCCURED_2    = 0x71,
    SIGNATURE_VERIFICATION_FAILED = 0x72
};

void dumpHex(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;

    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        if ((i % 16) == 0)
        {
            Serial.printf("%06X: ", i); 
        }
        Serial.printf("%02X ", ((unsigned char*)data)[i]);
        if ((((unsigned char*)data)[i] >= ' ') && (((unsigned char*)data)[i] <= '~'))
        {
            ascii[i % 16] = ((unsigned char*)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((((i + 1) % 8) == 0) || ((i + 1) == size))
        {
            Serial.printf(" ");
            if (((i + 1) % 16) == 0)
            {
                Serial.printf("|  %s \n", ascii);
            }
            else if ((i + 1) == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if (((i + 1) % 16) <= 8)
                {
                    Serial.printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    Serial.printf("   ");
                }
                Serial.printf("|  %s \n", ascii);
            }
        }
    }
}

void _callback(FtpOperation ftpOperation, unsigned int freeSpace, unsigned int totalSpace)
{
    switch (ftpOperation)
    {
    case FTP_CONNECT:
        Serial.println(F("FTP: Connected!"));
        break;
    case FTP_DISCONNECT:
        Serial.println(F("FTP: Disconnected!"));
        break;
    case FTP_FREE_SPACE_CHANGE:
        Serial.printf("FTP: Free space change, free %u of %u!\n", freeSpace, totalSpace);
        break;
    default:
        break;
    }
}

void _transferCallback(FtpTransferOperation ftpOperation, const char* name, unsigned int transferredSize)
{
    switch (ftpOperation)
    {
    case FTP_UPLOAD_START:
        Serial.println(F("FTP: Upload start!"));
        break;
    case FTP_UPLOAD:
        Serial.printf("FTP: Upload of file %s byte %u\n", name, transferredSize);
        break;
    case FTP_TRANSFER_STOP:
        Serial.println(F("FTP: Finish transfer!"));
        break;
    case FTP_TRANSFER_ERROR:
        Serial.println(F("FTP: Transfer error!"));
        break;
    default:
        break;
    }
}

void unlock(void)
{
    int32_t ret;
    uint16_t challenge_bytes;
    unsigned long startTime;
    const unsigned long timeout = 200;   // 200ms timeout
    int index;

    // Connect to the server
    if (client.connect(servername, 8881))
    {
        Serial.println("Connected to server.");

        // Open the cerificate
        File crt_file = LittleFS.open("/key.crt", "r");
        if (!crt_file)
        {
            Serial.println("Failed to open CRT file for reading!");
        }
        else
        {
            // Read the cerificate
            uint16_t request_service_bytes = crt_file.read(request_service_buf + 3, sizeof(request_service_buf) - 3);
            crt_file.close();

            // Send binary data to the server
            request_service_buf[0] = REQUEST_SERVICE_MSG;
            request_service_buf[1] = (uint8_t)(request_service_bytes >> 8);
            request_service_buf[2] = (uint8_t)(request_service_bytes >> 0);
            client.write(request_service_buf, request_service_bytes + 3);

            // Wait for response
            startTime = millis();
            index = 0;
            while (client.connected())
            {
                if ((millis() - startTime) >= timeout)
                {
                    Serial.println("Error response timeout.");
                    Serial.println("Disconnected from server.");
                    client.stop();
                    return;
                }

                if (client.available())
                {
                    challenge_buf[index ++] = client.read();
                    startTime = millis();   // Reset the timeout counter
                    if ((index >= sizeof(challenge_buf)) || (challenge_buf[0] != ((uint8_t)VALID_CHALLENGE)))
                    {
                        // Response received
                        break;
                    }
                }
            }

            switch(challenge_buf[0])
            {
            case (uint8_t)VALID_CHALLENGE:
                challenge_bytes = (((uint16_t)challenge_buf[1]) << 8) | ((uint16_t)challenge_buf[2]);
                if (challenge_bytes == HASH_LEN)
                {
                    Serial.println("Challenge received.");
                    //dumpHex(challenge_buf + 3, HASH_LEN);
                }

                // calculate the RSASSA-PKCS1-v1_5 2048bit signature (takes ~400ms on the ESP8266 with an OPTIGA Trust M)
                ret = trustM.calculateSignatureRSA(&challenge_buf[3], HASH_LEN, OPTIGA_KEY_ID_E0FD, sig_buf + 3, sig_bytes);
                Serial.println("Signature sent.");
                //dumpHex(sig_buf + 3, sig_bytes);

                // send signature to the server
                sig_buf[0] = SIGNATURE_MSG;
                sig_buf[1] = (uint8_t)(sig_bytes >> 8);
                sig_buf[2] = (uint8_t)(sig_bytes >> 0);
                client.write(sig_buf, sig_bytes + 3);
                break;

            case (uint8_t)ERROR_LOADING_CERTIFICATE:
                Serial.println("Error loading user certificate.");
                break;

            case (uint8_t)VALUE_ERROR:
                Serial.println("Value error.");
                break;

            case (uint8_t)INVALID_CA_AUTHENTICATION:
                Serial.println("Invalid CA authentication.");
                break;

            case (uint8_t)INVALID_CERTIFICATE_DATA:
                Serial.println("Invalid certificate data.");
                break;

            case (uint8_t)EXPIRED_CERTIFICATE:
                Serial.println("Expired certificate.");
                break;

            case (uint8_t)UNEXPECTED_ERROR_OCCURED_1:
            default:
                Serial.println("Unexpected error occured.");
                break;
            }

            startTime = millis();
            index = 0;
            while (client.connected())
            {
                if ((millis() - startTime) >= timeout)
                {
                    Serial.println("Error response timeout.");
                    Serial.println("Disconnected from server");
                    client.stop();
                    return;
                }

                if (client.available())
                {
                    authgrant_buf[index ++] = client.read();
                    startTime = millis();   // Reset the timeout counter
                    if (index >= sizeof(authgrant_buf))
                    {
                        // Response received
                        break;
                    }
                }
            }

            switch(authgrant_buf[0])
            {
            case (uint8_t)AUTHORIZATION_GRANTED:
                Serial.println("Authorization granted!");
                break;
            case (uint8_t)SIGNATURE_VERIFICATION_FAILED:
                Serial.println("Authorization not granted!");
                break;
            case (uint8_t)UNEXPECTED_ERROR_OCCURED_2:
            default:
                Serial.println("Unexpected error occured. Authorization not granted!");
                break;
            }

            // Disconnect from the server
            client.stop();
            Serial.println("Disconnected from server");
        }
    }
    else
    {
        Serial.println("Connection to server failed");
    }
}

void enterDeepSleep(void)
{
    Serial.println("Entering into deep sleep ...");

    // wait 1 sec before going to deep sleep (recover from deep sleep with the reset button)
    delay(1000);

    // consume less than 20µA in deep sleep
    ESP.deepSleep(0);
    delay(1000);
}

void setup(void)
{
    int32_t   ret;
    uint8_t   *csr_start;
    uint16_t  csr_len;
    File      csr_file;
    bool      csr_file_exists;

    // GPIO pin modes
    pinMode(OPTIGA_TRUST_M_POWER_GPIO, OUTPUT);
    pinMode(OPTIGA_TRUST_M_RESET_GPIO, OUTPUT);
    pinMode(FTP_MODE_GPIO, INPUT_PULLUP);

    // read jumper setting for FTP mode: 0 - inactive (jumper), 1 - active (no jumper)
    ftp_mode = digitalRead(FTP_MODE_GPIO);

    // keep OPTIGA Trust M in reset
    digitalWrite(OPTIGA_TRUST_M_RESET_GPIO, LOW);

    if (ftp_mode == 1)
    {
        // power off the OPTIGA Trust M
        digitalWrite(OPTIGA_TRUST_M_POWER_GPIO, LOW);
    }
    else
    {
        // power on the OPTIGA Trust M
        digitalWrite(OPTIGA_TRUST_M_POWER_GPIO, HIGH);

        // release the OPTIGA Trust M from reset
        digitalWrite(OPTIGA_TRUST_M_RESET_GPIO, HIGH);
    }

    // initialize UART for logging
    Serial.begin(115200);
    Serial.println();

    // start LittleFS before ftp server
    if (LittleFS.begin())
    {
        Serial.println("LittleFS opened!");

        // store if CSR file exists
        csr_file_exists = LittleFS.exists("/key.csr");

        if ((ftp_mode == 1) || (csr_file_exists == false))
        {
            Serial.println("Slow Wifi init.");

            // slow and bad for flash life, only CSR does not exist yet (initially) or when in FTP mode
            WiFi.persistent(true);
            WiFi.begin(ssid, password);
        }
        else
        {
            Serial.println("Fast Wifi init.");

            // fast, use last stored wifi settings
            WiFi.begin();
        }

        while (WiFi.status() != WL_CONNECTED)
        {
            delay(100);
            Serial.print(".");
        }
        Serial.println("");
        Serial.print("Connected to ");
        Serial.println(ssid);
        Serial.print("IP address: ");
        Serial.println(WiFi.localIP());

        if (ftp_mode == 1)
        {
            // initialize FTP client
            Serial.println("Starting FTP client ...");
            ftpSrv.setCallback(_callback);
            ftpSrv.setTransferCallback(_transferCallback);
            ftpSrv.begin("user","password");    //username, password for ftp.   (default 21, 50009 for PASV)
        }
        else
        {
            Serial.print("Begin to trust ... ");
            ret = trustM.begin();
            if (ret != 0)
            {
                Serial.println("Failed");
                enterDeepSleep();
            }
            else
            {
                Serial.println("Ok");
            }

            Serial.print("Limiting Current consumption (12mA - means max what a GPIO of the ESP8266 can deliver) ... ");
            ret = trustM.setCurrentLimit(12);
            if (ret != 0)
            {
                Serial.println("Failed");
                enterDeepSleep();
            }
            else
            {
                Serial.println("Ok");
            }

            if (csr_file_exists == false)
            {
                Serial.print("Generate Cerificate Signing Request ... ");
                ret = generateCertificateSigningRequestRSA2048((char*)countryName, (char*)state, (char*)locality, (char*)organizationName, NULL, (char*)commonName, &csr_start, &csr_len);
                if (ret != 0)
                {
                    Serial.println("Failed");
                    enterDeepSleep();
                }
                else
                {
                    Serial.println("Ok");
                }

                Serial.println("Cerificate Signing Request:");
                dumpHex(csr_start, csr_len);

                csr_file = LittleFS.open("/key.csr", "w");
                if (!csr_file)
                {
                    Serial.println("Failed to open CSR file for writing!");
                    enterDeepSleep();
                }

                if (csr_file.write(csr_start, csr_len) != csr_len)
                {
                    Serial.println("Failed to write data to CSR file!");
                    csr_file.close();
                    enterDeepSleep();
                }

                csr_file.close();
            }
            else
            {
                Serial.println("CSR file already created and present.");
            }
        }
    }

    if (ftp_mode == 0)
    {
        unlock();

        // power down the OPTIGA Trust M chip
        digitalWrite(OPTIGA_TRUST_M_POWER_GPIO, LOW);

        enterDeepSleep();
    }
}

void loop(void)
{
    if (ftp_mode == 1)
    {
        ftpSrv.handleFTP();
    }
}
