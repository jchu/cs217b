#ifndef _utils_h_
#define _utils_h_

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

// CCN
#include <ccn/ccn.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>

static size_t ccn_mac_length() {
    return AES_BLOCK_SIZE;
}

void
print_ccnb_name(struct ccn_upcall_info *info) {
    int i = 0;
    const unsigned char *comp_ptr;
    size_t comp_size;

    while( ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                i, &comp_ptr, &comp_size) == 0 ) {
        printf("(%d) %.*s | ",i,comp_size,(const char*)comp_ptr);
        i++;
    }
    printf("\n");
}

void
print_ccnb_charbuf(struct ccn_charbuf *namebuf) {
    struct ccn_indexbuf *components = ccn_indexbuf_create();
    int result = ccn_name_split(namebuf,components);
    if( result < 0 ) {
        fprintf(stderr,"error splitting charbuf\n");
        exit(-1);
    }

    int i = 0;
    const unsigned char *comp_ptr;
    size_t comp_size;

    while( ccn_name_comp_get(namebuf->buf, components,
                i, &comp_ptr, &comp_size) == 0 ) {
        printf("(%d) %.*s | ",i,comp_size,(const char*)comp_ptr);
        i++;
    }
    printf("\n");
}

/* KEYS */
static struct ccn_keystore *
init_keystore()
{
    struct ccn_keystore *keystore = NULL;
    int res;
    /* XXX - missing mutex? */
    struct ccn_charbuf *temp = ccn_charbuf_create();
    keystore = ccn_keystore_create();
    ccn_charbuf_putf(temp, "%s/.ccnx/.ccnx_keystore", getenv("HOME"));
    res = ccn_keystore_init(keystore,
            ccn_charbuf_as_string(temp),
            "Th1s1sn0t8g00dp8ssw0rd.");
    if (res != 0) {
        fprintf(stderr,"Failed to initialize keystore %s\n", ccn_charbuf_as_string(temp));
        exit(1);
    }
    ccn_charbuf_destroy(&temp);
    return keystore;
}

static const struct ccn_pkey *
get_my_private_key(struct ccn_keystore *cached_keystore)
{
    if (cached_keystore == NULL) exit(1);
    return (ccn_keystore_private_key(cached_keystore));
}

static const struct ccn_pkey *
get_my_public_key(struct ccn_keystore *cached_keystore)
{
    if (cached_keystore == NULL) exit(1);
    return (ccn_keystore_public_key(cached_keystore));
}

static const struct ccn_certificate *
get_my_certificate(struct ccn_keystore *cached_keystore)
{
    if (cached_keystore == NULL) exit(1);
    return (ccn_keystore_certificate(cached_keystore));
}

static const unsigned char *
get_my_publisher_key_id(struct ccn_keystore *cached_keystore)
{
    if (cached_keystore == NULL) exit(1);
    return (ccn_keystore_public_key_digest(cached_keystore));
}

static ssize_t
get_my_publisher_key_id_length(struct ccn_keystore *cached_keystore)
{
    if (cached_keystore == NULL) exit(1);
    return (ccn_keystore_public_key_digest_length(cached_keystore));
}

/* pkeyp result of get_public_key must be ccn_pubkey_free'd by caller */
int
get_public_key(struct ccn* ccn, const char *host, struct ccn_pkey **pkeyp) {

    struct ccn_charbuf *name = ccn_charbuf_create();
    int res = 0;
    struct ccn_parsed_ContentObject parsed = {0};
    struct ccn_parsed_ContentObject *pco = &parsed;
    struct ccn_charbuf *resultbuf = NULL;

    if (name == NULL || ccn_name_init(name) == -1) {
        fprintf(stderr, "Failed to allocate or initialize key name.\n");
        return (-1);
    }

    /* put users under keys, to make it easier to make an interest
       that watches for new data and caches it... */
    ccn_name_append_str(name, host);
    ccn_name_append_str(name, "ssh");
    ccn_name_append_str(name, "KEYS");
    ccn_name_append_str(name, "host");

    resultbuf = ccn_charbuf_create();
    if (resultbuf == NULL) {
        fprintf(stderr, "Failed to allocate resultbuf for public key.\n");
        return (-1);
    }
    res = ccn_get(ccn, name, NULL, 3000, resultbuf, pco, NULL, 0);
    if (res < 0)
        fprintf(stderr, "Cannot access public key for SSH via ccn\n");
    else {
        const unsigned char *p = NULL;
        size_t size = 0;
        ccn_content_get_value(resultbuf->buf, resultbuf->length, pco, &p, &size);
        *pkeyp = ccn_d2i_pubkey(p, size);
    }
    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&resultbuf);
    return (res);
}

static int
ccn_create_keylocator(struct ccn_charbuf *c, const struct ccn_pkey *k)
{
    int res;
    ccn_charbuf_append_tt(c, CCN_DTAG_KeyLocator, CCN_DTAG);
    ccn_charbuf_append_tt(c, CCN_DTAG_Key, CCN_DTAG);
    res = ccn_append_pubkey_blob(c, k);
    if (res < 0)
        return (res);
    else {
        ccn_charbuf_append_closer(c); /* </Key> */
        ccn_charbuf_append_closer(c); /* </KeyLocator> */
    }
    return (0);
}

static int
ccn_publish_key(struct ccn* ccn, struct ccn_keystore *cached_keystore, const char *host) {

    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *signed_info = NULL;
    struct ccn_charbuf *keylocator = NULL;
    long expire = -1;
    int res = 0;
    const struct ccn_pkey *pk = get_my_public_key(cached_keystore);
    unsigned char *encoded_public_key = NULL;
    size_t encoded_public_key_len = 0;
    struct ccn_charbuf *message = NULL;

    if ((encoded_public_key_len = i2d_PUBKEY((EVP_PKEY *)pk, &encoded_public_key)) < 0)
        return (encoded_public_key_len);

    keylocator = ccn_charbuf_create();
    res = ccn_create_keylocator(keylocator, pk);
    if (res < 0)
        return (res);
    signed_info = ccn_charbuf_create();
    signed_info->length = 0;
    res = ccn_signed_info_create(signed_info,
                                 /*pubkeyid*/get_my_publisher_key_id(cached_keystore),
                                 /*publisher_key_id_size*/get_my_publisher_key_id_length(cached_keystore),
                                 /*datetime*/NULL,
                                 /*type*/CCN_CONTENT_KEY,
                                 /*freshness*/ expire,
				 /*finalblockid*/NULL,
                                 /*keylocator*/keylocator);

    if (res != 0) {
        fprintf(stderr, "Failed to create signed_info (res == %d)\n", res);
        return res;
    }

    name = ccn_charbuf_create();
    if (name == NULL || ccn_name_init(name) == -1) {
        fprintf(stderr, "Failed to allocate or initialize key name.\n");
        return -1;
    }

    /* put users under keys, to make it easier to make an interest
       that watches for new data and caches it... */
    ccn_name_append_str(name, host);
    ccn_name_append_str(name, "ssh");
    ccn_name_append_str(name, "KEYS");
    ccn_name_append_str(name, "host");

    message = ccn_charbuf_create();

    if (NULL == message) {
        fprintf(stderr, "Failed to create mesage output charbuf.\n");
        return -1;
    }
    res = ccn_encode_ContentObject(message,
                                   name,
                                   signed_info,
                                   encoded_public_key, encoded_public_key_len,
                                   /*algorithm*/NULL,
                                   get_my_private_key(cached_keystore));
    if (res != 0) {
        fprintf(stderr, "Failed to encode ContentObject (res == %d)\n", res);
        return res;
    }
    res = ccn_put(ccn, message->buf, message->length);
    if (res < 0) {
        fprintf(stderr, "ccn_put failed (res == %d)\n", res);
        return res;
    }

    ccn_charbuf_destroy(&name);
    ccn_charbuf_destroy(&signed_info);
    ccn_charbuf_destroy(&keylocator);
    ccn_charbuf_destroy(&message);
    return 0;
}

// Encrypt/Decrypt

int ccn_pubkey_encrypt(const struct ccn_pkey *public_key,
                       unsigned char *data, size_t data_length,
                       unsigned char **encrypted_output,
                       size_t *encrypted_output_length) {

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

static int ccn_privkey_decrypt(
                               const struct ccn_pkey *private_key,
                               const unsigned char *ciphertext, size_t ciphertext_length,
                               unsigned char **decrypted_output,
                               size_t *decrypted_output_length) {

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

#endif /* _utils_h_ */
