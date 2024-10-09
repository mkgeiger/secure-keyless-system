#ifndef CSR_H
#define CSR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <Arduino.h>

int32_t generateCertificateSigningRequestRSA2048(char *countryName, char *state, char *locality, char *organizationName, char *organizationalUnitName, char *commonName, uint8_t **csr_start, uint16_t *csr_len);

#ifdef __cplusplus
}
#endif

#endif
