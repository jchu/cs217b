#ifndef _ccn_enc_h_
#define _ccn_enc_h_

/*
 * 
 * Based on demo/maurice/example2.c
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

// OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>


int
ccn_pubkey_encrypt(const struct ccn_pkey *public_key,
                   unsigned char *data,
                   size_t data_length,
                   unsigned char **encrypted_output,
                   size_t *encrypted_output_length);

static int
ccn_privkey_decrypt( const struct ccn_pkey *private_key,
                     const unsigned char *ciphertext,
                     size_t ciphertext_length,
                     unsigned char **decrypted_output,
                     size_t *decrypted_output_length);

#endif /* _ccn_enc_h_ */
