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
                   size_t *encrypted_output_length)
{

    int result = 0;
    EVP_PKEY *pkey = (EVP_PKEY*)public_key;

    unsigned char *encrypted = NULL;

    // Sanitization
    if( (data == NULL) || (data_length == 0) || (public_key == NULL) )
        return EINVAL;

    if( (encrypted_output == NULL) || (encrypted_output_length == NULL) ||
        ( (*encrypted_output != NULL) && (*encrypted_output_length < ccn_pubkey_size(public_key)) ) )
        return ENOBUFS;

    // Encrypt

    if (*encrypted_output != NULL)
        encrypted = *encrypted_output;
    else {
        encrypted = (unsigned char *)malloc(ccn_pubkey_size(public_key));
        if (encrypted == NULL)
            return ENOMEM;
    }

    result = RSA_public_encrypt(data_length+1,data,encrypted,pkey->pkey.rsa,RSA_PKCS1_PADDING);

    if( result != ccn_pubkey_size(public_key) ) {
        fprintf(stderr, "encrypt failed: ciphertext should match length of key\n");
        if (*encrypted_output == NULL)
            free(encrypted);
        return result;
    }

    *encrypted_output = encrypted;
    *encrypted_output_length = result;
    return 0;
}

static int
ccn_privkey_decrypt( const struct ccn_pkey *private_key,
                     const unsigned char *ciphertext,
                     size_t ciphertext_length,
                     unsigned char **decrypted_output,
                     size_t *decrypted_output_length)
{

    int result = 0;

    EVP_PKEY *pkey = (EVP_PKEY*)private_key;

    unsigned char *decrypted = NULL;

    // Sanitization
    if( (ciphertext == NULL) || (ciphertext_length == 0) || ( private_key == NULL) )
        return EINVAL;

    if( (decrypted_output == NULL) || (decrypted_output_length == NULL) ||
        ( (*decrypted_output != NULL) && (*decrypted_output_length < EVP_PKEY_size(pkey)) ) )
        return ENOBUFS;

    if (*decrypted_output != NULL)
        decrypted = *decrypted_output;
    else {
        decrypted = (unsigned char *)malloc(EVP_PKEY_size(pkey));
        if (decrypted == NULL)
            return ENOMEM;
    }

    result = RSA_private_decrypt(ciphertext_length, ciphertext, decrypted, pkey->pkey.rsa, RSA_PKCS1_PADDING);

    if( result < 0 ) {
        fprintf(stderr, "decrypted failed\n");
        if ( *decrypted_output == NULL )
            free(decrypted);
        return result;
    }

    *decrypted_output = decrypted;
    *decrypted_output_length = result;
    return 0;
}
