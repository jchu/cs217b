#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/********************************
 * CCNx specific headers
 *******************************/
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/header.h>

#include "messages.h"

/*******************************
 * CCNx specific constants
 ******************************/
#define CCN_CHUNK_SIZE 4096
#define CCN_VERSION_TIMEOUT 400
#define CCN_HEADER_TIMEOUT 400

/******************************
 * Local prototypes
 *****************************/
struct ccn_sys_t {
    struct ccn *ccn;
    struct ccn_closure *newClient;
    struct ccn_closure *existingClient;
    struct ccn_charbuf *mountpoint;
    struct ccn_charbuf *interest_template;
};

enum ccn_upcall_res
handleNewClient(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info);

typedef struct ccn_sys_t *ccn_sys;

static struct ccn_closure newClientAction = {
    .p = &handleNewClient
};

ccn_sys sys;
char* mountpoint;

/*
 * handleNewClient
 *
 * New client interest on server mountpoint
 *
 * Using csrc/cmd/dataresponsetest.c
 *
 */
enum ccn_upcall_res
handleNewClient(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info) {
    int result;

    printf("Got interest matching %d components, kind = %d\n", info->matched_comps, kind);
    // Sanity check
    switch (kind) {
        case CCN_UPCALL_INTEREST:
            // This is an interest
            break;
        default:
            // Only deal with interest
            return CCN_UPCALL_RESULT_ERR;
    }

    // REFER TO: voccn/libeXosip2/src/eXtl_ccn.c:346
    
    printf("%s",info->interest_ccnb);

    // Parse interest name
    // Expecting /domain/ssh/client/<return path: /domain/ssh/id/>/<init msg>
    // TODO: /domain/ should be configurable length
    if( ccn_name_comp_strcmp(info->interest_ccnb, info->interest_comps,info->matched_comps, "client" )  == 0 ) {

        const unsigned char* msg;
        size_t msg_size;

        // Ensure there is nothing after init msg
        result = ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                info->matched_comps + 8, &msg, &msg_size );
        if( result == 0 ) {
            // Interest with unrecongized name format
            printf("Unrecognized interest name. Missing client path.\n");
            return CCN_UPCALL_RESULT_ERR;
        }

        //printf("Received client message (len %u)\n",msg_size);

        // TODO: Handle encrypted init
        // result = ccn_privkey_decrypt( (EVP_PKEY *)get_my_private_key(),
        // key_block, key_block_length,
        // &key_buffer, &key_len);
        //
        // result = ccn_verify_mac
        // result = ccn_decrypt

        // TODO: Use client path when forking process
        // NOTE: Assuming  path: /domain/ssh/id
        struct ccn_charbuf *client_path = ccn_charbuf_create();
        ccn_name_init(client_path);
        ccn_name_append_components(client_path, info->interest_ccnb,
                info->interest_comps->buf[3], info->interest_comps->buf[6]);

        // Respond with SSH version number
        /* For signing
        struct ccn_charbuf *signed_info, *name, *content;
        signed_info = ccn_charbuf_create();
        result = ccn_signed_info_create(signed_info,
                get_my_publisher_key_id(),
                get_my_publisher_key_id_length,
                NULL,
                CCN_CONTENT_DATA,
                -1
                NULL,
                NUL);
        if( result < 0 ) {
            // TODO: error
        }
        */

        // TODO: forked process send new interest to initiate user authentication?
        printf("Sending back message.\n");
        //struct ccn_charbuf *name = ccn_charbuf_create();
        struct ccn_charbuf *content = ccn_charbuf_create();
        ccn_charbuf_append_string(content, "SSH-2.0-NDN"); // TODO: use real content
        //ccn_encode_ContentObject(content, client_path, signed_info,
        //        "",0,NULL, get_my_private_key());
        result = ccn_put(info->h, content->buf, content->length);
        ccn_charbuf_destroy(&client_path);
        ccn_charbuf_destroy(&content);

        if( result == -1 ) {
            message_on_send_failure(sys->ccn);
            return CCN_UPCALL_RESULT_ERR;
        } else {
            //ccn_charbuf_destroy(&signed_info);
            return CCN_UPCALL_RESULT_INTEREST_CONSUMED;
        }
    } else {
        // Interest with unrecongized name format
        printf("Unrecognized interest name\n");
        return CCN_UPCALL_RESULT_ERR;
    }


    return CCN_UPCALL_RESULT_OK;
}
/*
static const struct ccn_pkey *
get_my_private_key(void)
{
    if (cached_keystore == NULL) init_cached_keystore();
    return (ccn_keystore_private_key(cached_keystore));
}

static const struct ccn_certificate *
get_my_certificate(void)
{
    if (cached_keystore == NULL) init_cached_keystore();
    return (ccn_keystore_certificate(cached_keystore));
}

static const unsigned char *
get_my_publisher_key_id(void)
{
    if (cached_keystore == NULL) init_cached_keystore();
    return (ccn_keystore_public_key_digest(cached_keystore));
}


static ssize_t
get_my_publisher_key_id_length(void)
{
    if (cached_keystore == NULL) init_cached_keystore();
    return (ccn_keystore_public_key_digest_length(cached_keystore));
}
*/

void
setup(int argc, char** argv) {
    int retvalue = EXIT_FAILURE;

    // TODO: handle arguments properly

    // CCN Handle
    sys->ccn = ccn_create();
    if( sys->ccn == NULL || ccn_connect(sys->ccn,NULL) == -1 ) {
        message_on_ccnd_connect_failure(sys->ccn);
        ccn_destroy(&(sys->ccn));
        exit(retvalue);
    }

    // Publish server mountpoint
    sys->mountpoint = ccn_charbuf_create();
    if( sys->mountpoint == NULL ) {
        message_on_charbuf_nomem(sys->ccn,"mountpoint");
        exit(retvalue);
    }

    char* location = argv[1];
    retvalue = ccn_name_from_uri(sys->mountpoint,location);
    if( retvalue < 0 ) {
        message_on_name_failure(sys->ccn,"server mountpoint");
        exit(retvalue);
    }
    ccn_name_append_str(sys->mountpoint,"ssh");

    sys->newClient = &newClientAction;
    retvalue = ccn_set_interest_filter(sys->ccn,sys->mountpoint,
            sys->newClient);
    if( retvalue < 0 ) {
        //message_on_route_failure();
        exit(retvalue);
    }
}

int
main(int argc, char** argv) {
    sys = (ccn_sys) malloc(sizeof(struct ccn_sys_t));
    setup(argc,argv);
    ccn_run(sys->ccn,-1);

    return 0;
}
