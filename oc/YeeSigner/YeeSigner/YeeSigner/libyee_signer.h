#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

void yee_signer_key_pair_free(unsigned int *key_pair, unsigned int *_err);

unsigned int *yee_signer_key_pair_from_mini_secret_key(const unsigned char *mini_secret_key,
                                                       unsigned int mini_secret_key_len,
                                                       unsigned int *err);

unsigned int *yee_signer_key_pair_from_secret_key(const unsigned char *secret_key,
                                                  unsigned int secret_key_len,
                                                  unsigned int *err);

void yee_signer_public_key(unsigned int *key_pair,
                           unsigned char *out,
                           unsigned int out_len,
                           unsigned int *_err);

void yee_signer_secret_key(unsigned int *key_pair,
                           unsigned char *out,
                           unsigned int out_len,
                           unsigned int *_err);

void yee_signer_sign(unsigned int *key_pair,
                     const unsigned char *message,
                     unsigned int message_len,
                     unsigned char *out,
                     unsigned int out_len,
                     unsigned int *_err);

void yee_signer_verifier_free(unsigned int *verifier, unsigned int *_err);

unsigned int *yee_signer_verifier_from_public_key(const unsigned char *public_key,
                                                  unsigned int public_key_len,
                                                  unsigned int *err);

void yee_signer_verify(unsigned int *verifier,
                       const unsigned char *signature,
                       unsigned int signature_len,
                       const unsigned char *message,
                       unsigned int message_len,
                       unsigned int *err);
