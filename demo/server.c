

/********************************
 * CCNx specific headers
 *******************************/
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/uri.h>
#include <ccn/header.h>

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

ccn_sys_t *ccn_sys;

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

    // Sanity check
    switch (kind) {
        case CCN_UPCALL_INTEREST:
            // This is an interest
            break;
        default:
            // Only deal with interest
            return CCN_UPCALL_RESTUL_ERR;
    }

    // Interpret interest name for client
    struct ccn_parsed_interest * pi = info->pi;

    // Get name is encrypted to server private key and must be decrypted


    // Respond with SSH version number
    ccn_put(info->h, contents, size);

    // Send new interest to initiate user authentication
}

void
setup() {
    int retvalue = EXIT_FAILURE;
    // CCN Handle
    ccn_sys->ccn = ccn_create();
    if( ccn_sys->ccn == NULL || ccn_connect(ccn_sys->ccn,NULL) == -1 ) {
        message_on_ccnd_connect_failure();
        exit(retvalue)
    }

    // Publish server mountpoint
    ccn_sys->mountpoint = ccn_charbuf_create();
    if( ccn_sys->mountpoint == NULL ) {
        message_on_charbuf_nomem("mountpoint");
        exit(retvalue);
    }
    // TODO:location
    retvalue = ccn_name_from_uri(ccn_sys->mountpoint,location);
    if( retvalue < 0 ) {
        message_on_name_failure("server mountpoint");
        exit(retvalue);
    }

    retvalue = ccn_set_interest_filter(ccn_sys->ccn,ccn_sys->mountpoint,
            ccn_sys->newClient);
    if( retvalue < 0 ) {
        message_on_route_failure();
        exit(retvalue);
    }
}
