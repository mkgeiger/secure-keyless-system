# Introduction

If you want to develop a wireless keyless system yourself that consists of a remote control for locking and unlocking doors with a high level of security, then you are on the right page.

The handheld remote control is hereinafter referred to as the `keyless client`, whereby the controller that is responsible for locking and unlocking the locking cylinder is hereinafter referred to as the `keyless server`. The system uses inexpensive and widely available electronic components that you can order from your local electronics retailer. The wireless medium used for communication is Wi-Fi, either the Wi-Fi of your existing home network or the Wi-Fi of an access point running on the `keyless server`. The security of the system is based on the asymmetric cryptographic method RSA-2048, which implements a challenge-response authentication algorithm between the `keyless client` and the `keyless server`.

Please understand this project as an experiment and feel free to improve and extend it to your own needs. It is fully working but neither completely penetration tested nor measures were taken to prevent all kind of side channel attacks. The reproduction is therefore at your own risk. I assume no liability whatsoever.

# Hardware

## Components

### Raspberry Pi Zero W

Any board or PC can be used as the `keyless server`, which is able to run the Python server script. If it is a headless system it is useful to activate SSH to be able to connect to the board in a secure way for configuration, up- and downloading files, maintenance, etc. I'm using the Raspberry Pi Zero W for the `keyless server` with the Raspberry Pi OS installed. Python version 3.7.x or newer is required.

<img src="/KeylessServer/Hardware/RaspberryPI_ZeroW.png" alt="Raspberry PI Zero W" width="512"/>

### Microcontroller

I decided to use an ESP-12F ESP8266 Wi-Fi module from Adafruit Industries for the `keyless client`. It has a small form factor, enough CPU performance, all the required pins needed for this project, and most important no wakeup problems from deep sleep like many other ESP8266 boards had which I tested. The ESP-12F can be ordered with a white breakout PCB which can be seen in the following picture. The breakout board has already resistors mounted to pull LOW the GPIO15 pin and pull HIGH the Chip-Enable pin.

<img src="/KeylessClient/Hardware/ESP8266.png" alt="ESP8266" width="512"/>

### High-End Security Controller

There don't exist many standalone security controllers on the market. Often they are integrated only into high-end microcontollers. The standalone Optiga Trust M SLS32AIA chip from Infineon Technolgies was the best choice because of its well supported and easy to use Arduino software library. The asymmetric cryptographic method RSA-2048 is perfectly supported including a secure private keystore. The chip comes on a breakout board from Adafruit Industries with pins for I²C. Pull-up resistors for the I²C lines SCL and SDA are already installed on the breakout board.

<img src="/KeylessClient/Hardware/TrustM.png" alt="ESP8266" width="384"/>

### 3.3V Step-Up Voltage Regulator

The Pololu 3.3V step-up voltage regulator U1V10F3 is perfectly suited for powering with two alkaline cells. The module is equipped with Texas Instruments' TPS61201 low-input synchronous boost converter.
The small form factor, the high input voltage range down to 0.5V and the low quiescent current of ~50µA makes it perfectly suited for the `keyless client`.

<img src="/KeylessClient/Hardware/U1V10F3.png" alt="U1V10F3" width="150"/>

### USB – Serial UART (TTL) Development Module

As the `keyless client` is built only with a naked ESP-12F and without a USB chip for SW flashing and its UART needs to be contacted directly. Apart from RXD and TXD also RTS (Request To Send) and DTR (Data Terminal Ready) signals are required to connect. These two additional pins are not brought out on most USB – Serial UART (TTL) converter boards. The UM232R development module provides access to all UART interface pins of the FTDI FT232R unit, which can also be configured for 3.3V levels via a jumper setting.
 
<img src="/KeylessClient/Hardware/FTDI-UM232R.png" alt="FTDI-UM232R" width="384"/>

## Schematic

On the right side the pin header can be seen to connect to the UM232R module for flashing. Two additional 10 kOhm resistors are needed to pull HIGH the GPIO0 (flash/normal boot mode) and to pull HIGH the reset pin. The jumper on the left side connected to GPIO14 is responsible to select either the file transfer mode (jumper opened, with FTP client, without deep sleep) or the normal operation mode (jumper closed, without FTP client, with deep sleep). The push button wakes-up the ESP-12F from deep sleep. The Optiga Trust M is not powered permanently, instead, to keep the power consumption at a minimum during deep sleep, it is powered through the GPIO13 of the ESP-12F. The current consumption of the Optiga Trust M needs to be limited to 12 mA, because this current is the maximum what a single GPIO of the ESP-12F can deliver. There is also a possibility to reset the Optiga Trust M with GPIO12.

<img src="/KeylessClient/Hardware/Schematic.png" alt="Schematic" width="1024"/>

# Software

## Certificate Authority

### Chain Of Trust

The RSA signature scheme RSASSA-PKCS1-v1.5 (Public-Key Cryptography Standards #1 with deterministic signature) with 2048 bit key length is used throughout the project, because longer RSA key lengths are not supported by the Optiga Trust M chip.

The client key pair is generated inside the Optiga Trust M, whereas only the client public key is exposed to the outside for embedding it into the client Certificate Signing Request (CSR). The client private key is stored securely inside the Optiga Trust M in a key slot, which is referenced for self-signing the CSR and signing later the exchanged nonce data.

On the server the CA key pair is generated by the Certificate Authority (CA), which is owned by the owner (maybe you ;-?) of this `keyless system`. The CA public key is embedded into the CA certificate to verify the signature of the client certificate (chain of trust). The CA private key is used to self-sign the CA certificate and to sign the CSR/client certificate. The CA private key should be stored then in a secure place as any hacker who has this file could break into the system.

The client public key, which is embedded into the client certificate, is used later to verify the signature of the exchanged nonce data.

<img src="/CertificateAuthority/ChainOfTrust.png" alt="Chain Of Trust" width="1024"/>

### Certification Sequence

_Note: OpenSSL 3.2.0 has been used for following steps._

1. As you are your own Certificate Authority (CA) you create first your CA key pair. Make sure this CA key is stored at a secure place that it cannot be stolen.
```
sudo openssl genrsa -out ca.key 2048
```
2. Now create a self-signed certificate for the CA using the CA key. Enter your personal attributes into the requested form fields of the CA certificate generation.
```
sudo openssl req -new -x509 -days 15000 -key ca.key -out ca.crt
```
3. Hand out the CA certificate to the `keyless server` and store it in the same folder as the Python script `KeylessServer.py`.
4. Start the `keyless client` in FTP mode (jumper opened) and connect with a FTP server to it (IP address is printed on the serial console) from the Certificate Authority (CA). Make sure that the client certificate (key.crt) and the client CSR (key.csr) are deleted from the client file-system.
5. Start the `keyless client` in normal mode (jumper closed). A new client key pair is generated inside the Optiga Trust M and the client CSR is generated automatically and stored as the file key.csr in the client file-system. The form attributes of the CSR are hard coded inside the source code of the `keyless client` and need to be adapted by its owner.
6. Start the `keyless client` in FTP mode (jumper opened) again and connect with a FTP server to it from the Certificate Authority (CA). Upload the client CSR (key.csr) to the Certificate Authority (CA).
7. Now create from the client CSR (key.csr) the client certificate (key.crt) signed with the CA key. The valid period in the following example is 1 year. The options.ext file can be found [here](/CertificateAuthority/options.ext).
```
sudo openssl x509 -req -inform der -in key.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile options.ext -outform der -out key.crt -days 365
```
8. Now download the client certificate (key.crt) to the `keyless client` via FTP.
9. Start the `keyless client` in normal mode (jumper closed) again and restart also the `keyless server`. The certification process is finished now.

_Note: whenever you need to re-generate the client key/certificate you need to repeat only steps 4 to 9._ 

<img src="/Diagrams/CertificationProcess.png" alt="Chain Of Trust" width="1024"/>

Some other useful OpenSSL commands to verify and dump the client CSR/certificate:
```
sudo openssl req -inform der -in key.csr -noout -verify
sudo openssl asn1parse -inform der -in key.csr
sudo openssl req -inform der -in key.csr -noout -text
sudo openssl verify -CAfile ca.crt key.crt
sudo openssl x509 -in key.crt -noout -text
```

## Keyless System

The message exchange of the `keyless system` is based on the Challenge Response Authentication mechanism.

1. When the `keyless client` wakes up from deep sleep a request is sent to the `keyless server`. Along with the request the client certificate is sent for different kind of certificate verifications, e.g. chain of trust, time expiration, etc.
2. The challenge is sent by the `keyless server` to the `keyless client` containing a nonce. In our case the nonce is the secure hash (SHA-256) of the combination of a large random number and a sequence number. The sequence number is a monotonic up-counter, which makes it safe against replay attacks.
3. The response is the RSASSA-PKCS1-v1.5 signature of the nonce calculated by `keyless client` and sent to the `keyless server`.
4. The `keyless server` verifies the signature with the client public key (received with the client certificate) and on success the door is unlocked. The `keyless client` will be informed if access has been granted.

<img src="/Diagrams/ChallengeResponseAuthentication.png" alt="Challenge Response Authentication" width="1024"/>

### Keyless Client

* install Arduino IDE 2.x
* enter "https://arduino.esp8266.com/stable/package_esp8266com_index.json" into the File>Preferences>Additional Boards Manager URLs field
* open boards manager from Tools>Board menu and install the esp8266 platform
* install library "SimpleFTPServer" v2.1.7 or newer
* install library "OPTIGA Trust M" v1.1.0. The included Mbed TLS stack is very old and buggy. So very important is the patching of file ~\Arduino\libraries\OPTIGA_Trust_M\src\mbedtls\asn1write.c with my [asn1write.c](/KeylessClient/Patch/asn1write.c). It contains several bugfixes based on Mbed TLS 3.6.0 LTS related to ASN.1 tag handling.
* select board: NodeMCU 1.0 (ESP-12E Module)
* select flash size with filesystem space: 4MB (FS:1MB or 2MB)
* the CSR handling is located in files [csr.h](/KeylessClient/csr.h) and [csr.cpp](/KeylessClient/csr.cpp)
* the main functionality is located in file [KeylessClient.ino](/KeylessClient/KeylessClient.ino). Please adjust following parameters on the top of that file:
  * Wi-Fi settings
    * const char* ssid = "xxxxxxxxxx";
    * const char* password = "xxxxxxxxxx";
  * `keyless server` settings
    * const char* servername = "192.168.1.9";
  * Client CSR/certificate settings
    * const char* countryName = "DE";
    * const char* state = "BW";
    * const char* locality = "Heimsheim";
    * const char* organizationName = "Geiger";
    * const char* commonName = "Key";

### Keyless Server

* configure the same static IP address which has been configured in the `keyless client` as servername 
* install Python 3.7.x or newer
* install the OpenSSL wrapper "pyOpenSSL" 24.x.x or newer
* the monotonic counter class is located in file [monotoniccounter.py](/KeylessServer/monotoniccounter.py). It will store and update the monotonic counter value in file [counter.txt](/KeylessServer/counter.txt).
* the main functionality is located in file [KeylessServer.py](/KeylessServer/KeylessServer.py).
