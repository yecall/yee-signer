#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

unsigned int *yee_signer_build_call(unsigned int module,
                                    unsigned int method,
                                    const unsigned char *params,
                                    unsigned int params_len,
                                    unsigned int *error);

unsigned int *yee_signer_build_tx(const unsigned char *secret_key,
                                  unsigned int secret_key_len,
                                  unsigned long nonce,
                                  unsigned long period,
                                  unsigned long current,
                                  const unsigned char *current_hash,
                                  unsigned int current_hash_len,
                                  unsigned int *call,
                                  unsigned int module,
                                  unsigned int method,
                                  unsigned int *error);

void yee_signer_call_free(unsigned int *call,
                          unsigned int module,
                          unsigned int method,
                          unsigned int *error);

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
                     const unsigned char *ctx,
                     unsigned int ctx_len,
                     unsigned int *_err);

unsigned int *yee_signer_tx_decode(const unsigned char *raw,
                                   unsigned int raw_len,
                                   unsigned int *module_holder,
                                   unsigned int *method_holder,
                                   unsigned int *error);

void yee_signer_tx_encode(unsigned int *tx,
                          unsigned int module,
                          unsigned int method,
                          unsigned char *buffer,
                          unsigned int buffer_len,
                          unsigned int *error);

void yee_signer_tx_free(unsigned int *tx,
                        unsigned int module,
                        unsigned int method,
                        unsigned int *error);

unsigned int yee_signer_tx_length(unsigned int *tx,
                                  unsigned int module,
                                  unsigned int method,
                                  unsigned int *error);

void yee_signer_verifier_free(unsigned int *verifier, unsigned int *_err);

unsigned int *yee_signer_verifier_from_public_key(const unsigned char *public_key,
                                                  unsigned int public_key_len,
                                                  unsigned int *err);

void yee_signer_verify(unsigned int *verifier,
                       const unsigned char *signature,
                       unsigned int signature_len,
                       const unsigned char *message,
                       unsigned int message_len,
                       const unsigned char *ctx,
                       unsigned int ctx_len,
                       unsigned int *err);

void yee_signer_verify_tx(unsigned int *tx,
                          unsigned int module,
                          unsigned int method,
                          const unsigned char *current_hash,
                          unsigned int current_hash_len,
                          unsigned int *error);
