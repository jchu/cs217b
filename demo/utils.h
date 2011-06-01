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

static size_t ccn_mac_length() {                                                   return AES_BLOCK_SIZE;                                                     
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

static int                                                                     ccn_create_keylocator(struct ccn_charbuf *c, const struct ccn_pkey *k)
{
    int res;
    ccn_charbuf_append_tt(c, CCN_DTAG_KeyLocator, CCN_DTAG);                       ccn_charbuf_append_tt(c, CCN_DTAG_Key, CCN_DTAG);
    res = ccn_append_pubkey_blob(c, k);                                            if (res < 0)
        return (res);
    else {                                                                             ccn_charbuf_append_closer(c); /* </Key> */
        ccn_charbuf_append_closer(c); /* </KeyLocator> */                          }                                                                              return (0);
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

int ccn_pubkey_encrypt(struct ccn_pkey *public_key,
                       unsigned char *data, size_t data_length,
                       unsigned char **ekey, size_t *eklen,
                       unsigned char **encrypted_output,
                       size_t *encrypted_output_length) {

    fprintf(stderr,"Encrypting...\n");
    int result = 0;

    EVP_CIPHER_CTX ctx;
    EVP_PKEY *pkey = (EVP_PKEY*)public_key;

    unsigned char *ek = NULL;
    int ekeylen;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    unsigned char *encrypted = NULL;

    memset(iv,0,sizeof(iv));

    int len_out;

    // Sanitization
    if( (data == NULL) || (data_length == 0) || (public_key == NULL) )
        return EINVAL;

    if( (encrypted_output == NULL) || (encrypted_output_length == NULL) ||
        ( (*encrypted_output != NULL) && (*encrypted_output_length < ccn_pubkey_size(public_key)) ) )
        return ENOBUFS;

    //EVP_CIPHER_CTX_init(&ctx);
    
    // Initialize symmetric encryption key
    ek = (unsigned char*)malloc(ccn_pubkey_size(public_key));
    if( !ek )
        return ENOMEM;

    result = EVP_SealInit(&ctx,
            EVP_aes_128_cbc(),
            &ek,
            &ekeylen,
            iv,
            &pkey,
            1);

    if( result == 0 ) {
        fprintf(stderr, "EVP_SealInit: failed.\n");
        return result;
    }

    *eklen = ekeylen;
    *ekey = ek;

    // Encrypt

    if (*encrypted_output != NULL)
        encrypted = *encrypted_output;
    else {
        encrypted = (unsigned char *)malloc(EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        if (NULL == encrypted)
            return ENOMEM;
    }

    memset(encrypted, 0, *encrypted_output_length);

    result = EVP_SealUpdate(&ctx,
            encrypted,
            &len_out,
            data,
            data_length);

    if( result == 0 ) {
        fprintf(stderr, "EVP_SealUpdate: failed.\n");
        if (*encrypted_output == NULL)
            free(encrypted);
        return result;
    }

    result = EVP_SealFinal(&ctx, encrypted, &len_out);

    if( result == 0 ) {
        fprintf(stderr, "EVP_SealFinal: failed.\n");
        if (*encrypted_output == NULL)
            free(encrypted);
        return result;
    }

    *encrypted_output = encrypted;
    *encrypted_output_length = len_out;
    return 0;
}

static int ccn_privkey_decrypt(
                               EVP_PKEY *private_key,
                               const unsigned char *keytext, size_t keytext_length,
                               const unsigned char *ciphertext, size_t ciphertext_length,
                               unsigned char **decrypted_output,
                               size_t *decrypted_output_length) {

    fprintf(stderr,"Decrypting...\n");
    int result = 0;

    EVP_CIPHER_CTX ctx;
    EVP_PKEY *pkey = (EVP_PKEY*)private_key;

    unsigned char iv[EVP_MAX_IV_LENGTH];
    memset(iv,0,sizeof(iv));

    int len_out;

    unsigned char *decrypted = NULL;

    // Sanitization
    if( (ciphertext == NULL) || (ciphertext_length == 0) || ( private_key == NULL) || (keytext == NULL) || (keytext_length == 0) )
        return EINVAL;

    if( (decrypted_output == NULL) || (decrypted_output_length == NULL) ||
        ( (*decrypted_output != NULL) && (*decrypted_output_length < EVP_PKEY_size(private_key)) ) )
        return ENOBUFS;

    //EVP_CIPHER_CTX_init(&ctx);
    result = EVP_OpenInit(&ctx,
            EVP_aes_128_cbc(),
            keytext,
            keytext_length,
            iv,
            pkey);

    if( result == 0 ) {
        fprintf(stderr, "EVP_OpenInit: failed.\n");
        return result;
    }

    if (*decrypted_output != NULL)
        decrypted = *decrypted_output;
    else {
        decrypted = (unsigned char *)malloc(sizeof(char) * keytext_length);
        if (decrypted == NULL)
            return ENOMEM;
    }

    memset(decrypted, 0, *decrypted_output_length);

    result = EVP_OpenUpdate(&ctx,
            decrypted,
            &len_out,
            ciphertext,
            ciphertext_length);

    if( result == 0 ) {
        fprintf(stderr, "EVP_OpenUpdate: failed. \n");
        if ( *decrypted_output == NULL )
            free(decrypted);
        return result;
    }

    result = EVP_OpenFinal(&ctx, decrypted, &len_out);

    if( result == 0 ) {
        fprintf(stderr, "EVP_OpenFinal: failed. \n");
        if (*decrypted_output == NULL )
            free(decrypted);
        return result;
    }


    *decrypted_output = decrypted;
    *decrypted_output_length = len_out;
    return 0;
}

int ccn_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *ciphertext, 
                size_t ciphertext_length,
                unsigned char **plaintext, 
                size_t *plaintext_length, 
                size_t plaintext_padding) {

    EVP_CIPHER_CTX ctx;
    unsigned char *pptr = *plaintext;
    const unsigned char *dptr = NULL;
    size_t plaintext_buf_len = ciphertext_length + plaintext_padding;
    size_t decrypt_len = 0;

    if ((NULL == ciphertext) || (NULL == plaintext_length) || (NULL == key) || (NULL == plaintext))
        return EINVAL;

    if (NULL == iv) {
        plaintext_buf_len -= AES_BLOCK_SIZE;
    }

    if ((NULL != *plaintext) && (*plaintext_length < plaintext_buf_len))
        return ENOBUFS;

    if (NULL == pptr) {
        pptr = calloc(1, plaintext_buf_len);
        if (NULL == pptr)
            return ENOMEM;
    }

    if (NULL == iv) {
        iv = ciphertext;
        dptr = ciphertext + AES_BLOCK_SIZE;
        ciphertext_length -= AES_BLOCK_SIZE;
    } else {
        dptr = ciphertext;
    }

    /*
      print_block("ccn_decrypt: key:", key, AES_BLOCK_SIZE);
      print_block("ccn_decrypt: iv:", iv, AES_BLOCK_SIZE);
      print_block("ccn_decrypt: ciphertext:", dptr, ciphertext_length);
    */
    if (1 != EVP_DecryptInit(&ctx, EVP_aes_128_cbc(),
                             key, iv)) {
        if (NULL == *plaintext)
            free(pptr);
        return -128;
    }

    if (1 != EVP_DecryptUpdate(&ctx, pptr, (int *)&decrypt_len, dptr, ciphertext_length)) {
        if (NULL == *plaintext)
            free(pptr);
        return -127;
    }
    *plaintext_length = decrypt_len + plaintext_padding;
    if (1 != EVP_DecryptFinal(&ctx, pptr+decrypt_len, (int *)&decrypt_len)) {
        if (NULL == *plaintext)
            free(pptr);
        return -126;
    }
    *plaintext_length += decrypt_len;
    *plaintext = pptr;
    /* this is supposed to happen automatically, but sometimes we seem to be running over the end... */
    memset(*plaintext + *plaintext_length - plaintext_padding, 0, plaintext_padding);
    return 0;
}

int ccn_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *plaintext, 
                size_t plaintext_length,
                unsigned char **ciphertext, 
                size_t *ciphertext_length,
                size_t ciphertext_padding) {
    EVP_CIPHER_CTX ctx;
    unsigned char *cptr = *ciphertext;
    unsigned char *eptr = NULL;
    /* maximum length of ciphertext plus user-requested extra */
    size_t ciphertext_buf_len = plaintext_length + AES_BLOCK_SIZE-1 + ciphertext_padding;
    size_t encrypt_len = 0;
    size_t alloc_buf_len = ciphertext_buf_len;
    size_t alloc_iv_len = 0;

    if ((NULL == ciphertext) || (NULL == ciphertext_length) || (NULL == key) || (NULL == plaintext))
        return EINVAL;

    if (NULL == iv) {
        alloc_buf_len += AES_BLOCK_SIZE;
    }

    if ((NULL != *ciphertext) && (*ciphertext_length < alloc_buf_len))
        return ENOBUFS;

    if (NULL == cptr) {
        cptr = calloc(1, alloc_buf_len);
        if (NULL == cptr)
            return ENOMEM;
    }
    *ciphertext_length = 0;

    if (NULL == iv) {
        iv = cptr;
        eptr = cptr + AES_BLOCK_SIZE; /* put iv at start of block */

        if (1 != RAND_bytes((unsigned char *)iv, AES_BLOCK_SIZE)) {
            if (NULL == *ciphertext)
                free(cptr);
            return -1;
        }

        alloc_iv_len = AES_BLOCK_SIZE;
        fprintf(stderr, "ccn_encrypt: Generated IV\n");
    } else {
        eptr = cptr;
    }

    if (1 != EVP_EncryptInit(&ctx, EVP_aes_128_cbc(),
                             key, iv)) {
        if (NULL == *ciphertext)
            free(cptr);
        return -128;
    }

    if (1 != EVP_EncryptUpdate(&ctx, eptr, (int *)&encrypt_len, plaintext, plaintext_length)) {
        if (NULL == *ciphertext)
            free(cptr);
        return -127;
    }
    *ciphertext_length += encrypt_len;

    if (1 != EVP_EncryptFinal(&ctx, eptr+encrypt_len, (int *)&encrypt_len)) {
        if (NULL == *ciphertext)
            free(cptr);
        return -126;
    }

    /* don't include padding length in ciphertext length, caller knows its there. */
    *ciphertext_length += encrypt_len;
    *ciphertext = cptr;							   

    /*
      print_block("ccn_encrypt: key:", key, AES_BLOCK_SIZE);
      print_block("ccn_encrypt: iv:", iv, AES_BLOCK_SIZE);
      print_block("ccn_encrypt: ciphertext:", eptr, *ciphertext_length);
    */
    /* now add in any generated iv */
    *ciphertext_length += alloc_iv_len;
    return 0;
}

int ccn_add_mac(const unsigned char *key,
                size_t key_length,
                const unsigned char *message,
                size_t message_length,
                unsigned char *mac) {


    size_t outbuf_len = ccn_mac_length();

    HMAC(EVP_sha1(), key, key_length, message, message_length,
         mac, &outbuf_len);

    return 0;
}

int ccn_verify_mac(const unsigned char *key,
                   size_t key_length,
                   const unsigned char *message,
                   size_t message_length,
                   const unsigned char *mac) {

    unsigned char mac_buffer[2*AES_BLOCK_SIZE];

    ccn_add_mac(key, key_length, message, message_length, &mac_buffer[0]);

    return memcmp(&mac_buffer[0], mac, ccn_mac_length());
}
				

#endif /* _utils_h_ */
