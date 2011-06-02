#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/********************************
 * CCNx specific headers
 ********************************/
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/header.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>

#include "ccn-keys.h"
#include "ccn-enc.h"

/*******************************
 * CCNx specific constants
 ******************************/
#define CCN_CHUNK_SIZE 4096
#define CCN_VERSION_TIMEOUT 400
#define CCN_HEADER_TIMEOUT 400

/******************************
 * Local Declarations
 *****************************/
struct ccn_state_t {
    struct ccn *ccn;
    int state;

    const char *server;
    struct ccn_charbuf *server_mountpoint;

    const char *client;
    unsigned int clientid;

    struct ccn_keystore *cached_keystore;
    struct ccn_pkey *server_publickey;
};

enum ccn_upcall_res
ccn_handleConnect(struct ccn_closure *selfp,
                  enum ccn_upcall_kind kind,
                  struct ccn_upcall_info *info);

static struct ccn_closure ccn_connectHandler =
{
    .p = &ccn_handleConnect
};

enum ccn_upcall_res
ccn_handleServer(struct ccn_closure *selfp,
                  enum ccn_upcall_kind kind,
                  struct ccn_upcall_info *info);

static struct ccn_closure ccn_serverHandler =
{
    .p = &ccn_handleServer
};

typedef struct ccn_state_t *ssh_ccn_state;

static ssh_ccn_state ccn_state;

enum ccn_upcall_res
ccn_handleConnect(struct ccn_closure *selfp,
                  enum ccn_upcall_kind kind,
                  struct ccn_upcall_info *info) {
    int result = 0;

    unsigned char *encrypted_reply = NULL;
    size_t encrypted_reply_length = 0;
    unsigned char *reply = NULL;
    size_t reply_length = 0;

    // Sanity check
    switch (kind) {
        case CCN_UPCALL_FINAL:
            // No more chunks
            return CCN_UPCALL_RESULT_OK;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            // Daemon notified server timed out. Reexpress interest
            return CCN_UPCALL_RESULT_REEXPRESS;
        case CCN_UPCALL_CONTENT_UNVERIFIED:
            return CCN_UPCALL_RESULT_VERIFY;
        case CCN_UPCALL_CONTENT:
            break;
        default:
            return CCN_UPCALL_RESULT_ERR;
    }

    // Process init data
    //
    // Setup new server name
    result = ccn_unwrap_content(info,&encrypted_reply,&encrypted_reply_length);
    if( result < 0 ) {
        fprintf(stderr,"Could not retrieve content from interest (res == %d)\n");
        return CCN_UPCALL_RESULT_ERR;
    }

    result = ccn_privey_decrypt(ccn_get_my_public_key(cached_keystore),
                                encrypted_reply,
                                encrypted_reply_length,
                                &reply, &reply_length);
    if( result < 0 ) {
        fprintf(stderr,"Could not retrieve decrypt init message (res == %d)\n");
        return CCN_UPCALL_RESULT_ERR;
    }

    if( sscanf(reply, "SSH-%d.%d-%[^\n]\n",
                &remote_major, &remote_minor, remote_version) != 3 ) {
    }

    // Set global indicator for connection status
    

    return CCN_UPCALL_RESULT_OK;
}

enum ccn_upcall_res
ccn_handleServer(struct ccn_closure *selfp,
                  enum ccn_upcall_kind kind,
                  struct ccn_upcall_info *info) {
    int result = 0;

    unsigned char *reply = NULL;
    size_t reply_length = 0;

    // Sanity check
    switch (kind) {
        case CCN_UPCALL_FINAL:
            // No more chunks
            return CCN_UPCALL_RESULT_OK;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            // Daemon notified server timed out. Reexpress interest
            return CCN_UPCALL_RESULT_REEXPRESS;
        case CCN_UPCALL_CONTENT_UNVERIFIED:
            return CCN_UPCALL_RESULT_VERIFY;
        case CCN_UPCALL_CONTENT:
            break;
        default:
            return CCN_UPCALL_RESULT_ERR;
    }

    // Queue data into read buffer
    return CCN_UPCALL_RESULT_OK;
}

int
ccn_connect_remote(const char* remotehost,
                   const char* localhost,
                   unsigned int localid)
{
    int result;

    struct charbuf *client_mountpoint;

    struct charbuf *remote_name;
    struct charbuf *init_interest_template;
    unsigned char *init_block;
    size_t init_block_length;
.
    // Initialize ccn state
    ccn_state = (ssh_ccn_state) malloc(sizeof(struct ccn_state_t));
    ccn_state->ccn = ccn_create();
    ccn_state->server = localhost;
    result = ccn_get_public_key(ccn_state->ccn,
                                ccn_state->server,
                                &(ccn_state->server_publickey));
    if( result < 0 ) {
        fprintf(stderr,"Cannot retrieve server public key (res == %d)\n",result);
        return result;
    }

    // Publish client mountpoint
    ccn_state->client = localhost;
    ccn_state->clientid = localid;

    client_mountpoint = ccn_charbuf_create();
    result = ccn_name_from_uri(client_mountpoint,localhost);
    if( result < 0 ) {
        fprintf(stderr,"Could not resolve local client location (res == %d)\n",reslt);
        return result;
    }
    ccn_name_append_str(client_mountpoint,"ssh");
    ccn_name_append_numeric(client_mountpoint,CCN_MARKER_NONE,localid);

    result = ccn_set_interest_filter(ccn_state->ccn,
            client_mountpoint,
            ccn_serverHandler);
    if( result < 0 ) {
        fprintf(stderr,"Could not set client mountpoint (res == %d)\n",result);
        return result;
    }

    ccn_state->state = CCN_STATE_INIT;

    // Send INIT
    result = ccn_name_from_uri(remote_name,remotehost);
    if( result < 0 ) {
        fprintf(stderr,"Could not resolve remote host location (res == %d)\n",result);
        return result;
    }

    ccn_name_append_str(remote_name,"ssh");
    ccn_name_append_str(remote_name,"client");

    ccn_name_append_str(remote_name,localhost);
    ccn_name_append_str(remote_name,"ssh");
    ccn_name_append_numeric(remote_name,CCN_MARKER_NONE,localid);

    result = create_init_block(&init_block,&init_block_length);
    if( result < 0 ) {
        fprintf(stderr,"Could not create encrypted init_block (res == %d)\n",result);
        return result;
    }

    ccn_name_append(remote_name,(char *)init_block,init_block_length);

    init_interest_template = ccn_make_init_template();

    result = ccn_express_interest(ccn,
                                  remote_name,
                                  &ccn_connectHandler,
                                  init_interest_template);
    if( result < 0 ) {
        fprintf(stderr,"Could not express initial interest (res == %d)\n",result);
        return result;
    }
    ccn_state->state = CCN_STATE_PENDING;

    // Loop until connected
    while( ccn_state->state == CCN_STATE_PENDING )
        ccn_run(cnn,1);

    if( ccn_state->state == CCN_STATE_CONNECTED )
        return 0;
    else /* Should not get here */
        return -1;
}

int
ccn_wrap_content(struct ccn_charbuf *interest_name,
               unsigned char *writebuf,
               size_t writebuf_len,
               struct ccn_charbuf **content)
{
    struct ccn_charbuf *signed_info, *contentObject;
    int result;

    signed_info = ccn_charbuf_create();
    contentObject = ccn_charbuf_create();
    
    result = ccn_signed_info_create(signed_info,
            get_my_publisher_key_id(cached_keystore),
            get_my_publisher_key_id_length(cached_keystore),
            NULL,
            CCN_CONTENT_DATA,
            -1,
            NULL,
            NULL);
    if( result < 0 ) {
        fprintf(stderr,"failed to create signed info (res == %d)\n",result);
        result;
    }

    result = ccn_encode_ContentObject(
            contentObject,
            interest_path,
            signed_info,
            writebuf,
            writebuf_len,
            NULL, get_my_private_key(cached_keystore));
    if( result < 0 ) {
        fprintf(stderr,"failed to encode content (res == %d)\n",result);
        return result;
    }

    *content = contentObject;
    return 0;
}

int
ccn_unwrap_content(struct ccn_upcall_info *info,
                   unsigned char *readbuf,
                   size_t readbuf_len,
                   size_t *written)
{
    int result;

    const unsigned char *ccnb = NULL;
    size_t ccnb_size = 0;
    const unsigned char *data = NULL;
    size_t data_size = 0;

    unsigned int maxlen;

    ccnb = info->content_ccnb;
    ccnb_size = info->pco->offset[CCN_PCO_E];
    result = ccn_content_get_value(ccnb, ccnb_size,
                                   info->pco,
                                   &data, &data_size);
    if (result < 0 ) {
        fprintf(stderr,"failed to recover content from interest reply (res == %d)\n",result);
        return result;
    }

    if( data_size > readbuf_len ) {
        fprintf(stderr,"not enough memory in read buffer\n");
        return ENOMEM;
    }

    *readbuf = data;
    *written = data_size;
    return 0;
}

int
ccn_create_init_block(unsigned char **init_block,
                  size_t *init_block_length)
{
    int result;

    unsigned char *init_data;
    size_t init_data_length = 0;
    unsigned char *encrypted_init = NULL;
    size_t encrypted_init_length = 0;

    char *protocol_version;
    
    protocol_version = CCN_SSH_VERSION;

    result = ccn_pubkey_encrypt(ccn_state->server_publickey,
                                (unsigned char*)protocol_version,
                                (size_t)strlen(protocool_version),
                                &encrypted_init, &encrypted_init_length);
    if( result < 0 ) {
        fprintf(stderr,"Could not create init block (res == %d)\n",result);
        return result;
    }

    *init_block = encrypted_init;
    *init_block_length = encrypted_init_length;
    return result;
}

struct ccn_charbuf *
ccn_make_init_template()
{
    struct ccn_charbuf *templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG); /* <Interest> */
    ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG); /* <Name> */
    ccn_charbuf_append_closer(templ); /* </Name> */

    ccn_charbuf_append_tt(templ, CCN_DTAG_ChildSelector, CCN_DTAG);
    ccnb_append_number(templ,1);
    ccn_charbuf_append_closer(templ);
    
    ccn_charbuf_append_closer(templ); /* </Interest> */
    return templ;
}
