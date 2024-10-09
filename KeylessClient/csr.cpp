#include <OPTIGATrustM.h>

// MbedTLS includes
#include "mbedtls/config.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include "csr.h"

#define KEY_LEN    256       // Bytes (2048 bit)
#define KEY_MAXLEN 300
#define SIG_LEN    KEY_LEN
#define HASH_LEN    32       // SHA256
#define UID_LENGTH  27

#define ASN1_CHK_ADD(l, d, f)     \
    do {                          \
        if( ( ret = f ) < 0 )     \
            return( ret );        \
        else                      \
            l[d] += ret;          \
    } while( 0 )

uint8_t buffer[0x300];
uint8_t pubKey[300];

static int32_t fillUnsignedCertificateSigningRequestRSA2048(char *countryName, char *state, char *locality, char *organizationName, char *organizationalUnitName, char *commonName, uint8_t *serialNumber, uint8_t serialNumber_len,
                                                            uint8_t *pk_modulus, int32_t pk_exponent, uint8_t **to_sign_start, uint16_t *to_sign_len, uint8_t **signature, uint8_t **csr_start, uint16_t *csr_len)
{
    int32_t ret;
    int32_t len[6] = {0};
    uint8_t *c = buffer + sizeof(buffer);  // walk from end towards begin of buffer
    uint8_t *to_sign_end;
    static uint8_t sig[SIG_LEN];

    // signature BIT STRING (2048 bit) (@level 1)
    ASN1_CHK_ADD(len, 1, mbedtls_asn1_write_bitstring(&c, buffer, sig, SIG_LEN * 8));
    *signature = c + 5;

    // null tag with zero data (@level 2)
    // algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1) (@level 2)
    // signatureAlgorithm AlgorithmIdentifier SEQUENCE (2 elem) (@level 1)
    ASN1_CHK_ADD(len, 1, mbedtls_asn1_write_algorithm_identifier(&c, buffer, MBEDTLS_OID_PKCS1_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_SHA256), 0));
    to_sign_end = c;

    // Attributes [?] [0] (0 elem) (@level 2)
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_len(&c, buffer, len[2]));
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    // INTEGER public key exponent (@level 5)
    ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_int(&c, buffer, pk_exponent));

    // INTEGER (2048 bit) public key modulus (@level 5)
    c -= KEY_LEN;
    *--c = 0x00;
    memcpy (&c[1], pk_modulus, KEY_LEN);
    len[5] += (KEY_LEN + 1);
    ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_len(&c, buffer, KEY_LEN + 1));
    ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_INTEGER));

    // SEQUENCE(2 elem) (@level 4)
    len[4] += len[5];
    ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
    ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    // subjectPublicKey BIT STRING (2160 bit) (@level 4)
    *--c = 0x00;
    len[4]++;
    len[3] += len[4];
    ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
    ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_BIT_STRING));

    // null tag with zero data (@level 4)
    // algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1) (@level 4)
    // algorithm AlgorithmIdentifier SEQUENCE (2 elem) (@level 3)
    ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_algorithm_identifier(&c, buffer, MBEDTLS_OID_PKCS1_RSA, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_RSA), 0));

    // subjectPKInfo SubjectPublicKeyInfo SEQUENCE (2 elem) (@level 2)
    len[2] += len[3];
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_len(&c, buffer, len[3]));
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len[3] = 0;

    if (serialNumber != NULL)
    {
        // value AttributeValue [?] PrintableString (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_printable_string(&c, buffer, (char*)serialNumber, serialNumber_len));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_SERIAL_NUMBER)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (commonName != NULL)
    {
        // value AttributeValue [?] UTF8String (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_utf8_string(&c, buffer, commonName, strlen(commonName)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_CN, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (organizationalUnitName != NULL)
    {
        // value AttributeValue [?] UTF8String (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_utf8_string(&c, buffer, organizationalUnitName, strlen(organizationalUnitName)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (organizationName != NULL)
    {
        // value AttributeValue [?] UTF8String (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_utf8_string(&c, buffer, organizationName, strlen(organizationName)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORGANIZATION)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (locality != NULL)
    {
        // value AttributeValue [?] UTF8String (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_utf8_string(&c, buffer, locality, strlen(locality)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.7 locality (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_LOCALITY, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_LOCALITY)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (state != NULL)
    {
        // value AttributeValue [?] UTF8String (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_utf8_string(&c, buffer, state, strlen(state)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.8 state (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_STATE, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_STATE)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    if (countryName != NULL)
    {
        // value AttributeValue [?] PrintableString (@level 5)
        len[4] = 0;
        len[5] = 0;
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_printable_string(&c, buffer, countryName, strlen(countryName)));
        // type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component) (@level 5)
        ASN1_CHK_ADD(len, 5, mbedtls_asn1_write_oid(&c, buffer, MBEDTLS_OID_AT_COUNTRY, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_COUNTRY)));
        // AttributeTypeAndValue SEQUENCE (2 elem) (@level 4)
        len[4] += len[5];
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_len(&c, buffer, len[5]));
        ASN1_CHK_ADD(len, 4, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        // RelativeDistinguishedName SET(1 elem) (@level 3)
        len[3] += len[4];
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_len(&c, buffer, len[4]));
        ASN1_CHK_ADD(len, 3, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    }

    // subject Name SEQUENCE (6 elem) (@level 2)
    len[2] += len[3];
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_len(&c, buffer, len[3]));
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    // version INTEGER 0 (@level 2)
    ASN1_CHK_ADD(len, 2, mbedtls_asn1_write_int(&c, buffer, 0));

    // certificationRequestInfo CertificationRequestInfo SEQUENCE (4 elem) (@level 1)
    len[1] += len[2];
    ASN1_CHK_ADD(len, 1, mbedtls_asn1_write_len(&c, buffer, len[2]));
    ASN1_CHK_ADD(len, 1, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    *to_sign_start = c;
    *to_sign_len = (uint16_t)(to_sign_end - *to_sign_start);

    // CertificationRequest SEQUENCE (3 elem) (@level 0)
    len[0] += len[1];
    ASN1_CHK_ADD(len, 0, mbedtls_asn1_write_len(&c, buffer, len[1]));
    ASN1_CHK_ADD(len, 0, mbedtls_asn1_write_tag(&c, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    *csr_start = c;
    *csr_len = (uint16_t)len[0];

    return 0;
}

int32_t generateCertificateSigningRequestRSA2048(char *countryName, char *state, char *locality, char *organizationName, char *organizationalUnitName, char *commonName, uint8_t **csr_start, uint16_t *csr_len)
{
    int32_t  ret;
    uint8_t  uid[UID_LENGTH];
    uint16_t uidLen = UID_LENGTH;
    uint16_t pubKeyLen = KEY_MAXLEN; 
    uint8_t  *to_sign_start;          // pointer to begin of to be signed data
    uint16_t to_sign_len;             // length of to be signed data
    uint8_t  *signature;              // pointer to signature (256 bytes/2048 bits)
    uint8_t  hash[HASH_LEN];
    uint16_t signLen = SIG_LEN;

    Serial.print("    Getting co-processor Unique ID ... ");
    ret = trustM.getUniqueID(uid, uidLen);
    if (ret != 0)
    {
        Serial.println("Failed");
        return 1;
    }
    else
    {
        Serial.println("Ok");
    }
    //Serial.println("Unique ID:");
    //dumpHex(uid, uidLen);

    Serial.print("    Generate Key Pair RSA 2048. Store Private Key on Board ... ");
    ret = trustM.generateKeypairRSA2048(pubKey, pubKeyLen, OPTIGA_KEY_ID_E0FD);
    if (ret != 0)
    {
        Serial.println("Failed");
        return 1;
    }
    else
    {
        Serial.println("Ok");
    }
    //Serial.println("Public Key (DER):");
    //dumpHex(pubKey, pubKeyLen);

    Serial.print("    Fill unsigned CSR ... ");
    ret = fillUnsignedCertificateSigningRequestRSA2048(countryName, 
                                                       state,
                                                       locality,
                                                       organizationName,
                                                       organizationalUnitName,
                                                       commonName, 
                                                       uid,
                                                       uidLen,
                                                       &pubKey[14], 65537,
                                                       &to_sign_start, &to_sign_len, &signature,
                                                       csr_start, csr_len);
    if (ret != 0)
    {
        Serial.println("Failed");
        return 1;
    }
    else
    {
        Serial.println("Ok");
    }

    Serial.print("    Calculate Hash of data ... ");
    ret = trustM.sha256(to_sign_start, to_sign_len, hash);
    if (ret != 0)
    {
        Serial.println("Failed");
        return 1;
    }
    else
    {
        Serial.println("Ok");
    }

    Serial.print("    Signing the hash ... ");
    ret = trustM.calculateSignatureRSA(hash, HASH_LEN, OPTIGA_KEY_ID_E0FD, signature, signLen);
    if (ret != 0)
    {
        Serial.println("Failed");
        return 1;
    }
    else
    {
        Serial.println("Ok");
    }
    //Serial.println("Signature:");
    //dumpHex(signature, SIG_LEN);

    return 0;
}
