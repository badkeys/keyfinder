#include <stdio.h>

/*
 ECDSA/P256 key from RFC 9500
 spkisha256:b2b04340cfaee616ec9c2c62d261b208e54bb197498df52e8cadede23ac0ba5e
*/

int main(void) {
  char *pkey =
      "-----BEGIN EC PRIVATE KEY-----\n"
      "MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49\n"
      "AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV\n"
      "uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==\n"
      "-----END EC PRIVATE KEY-----\n";

  printf("%s", pkey);
}
