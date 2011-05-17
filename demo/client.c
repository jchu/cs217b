

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
    struct ccn_closure *reponseHandler; // Handle server interests
    struct ccn_charbuf *mountpoint; // Server response target
    struct ccn_charbuf *interest_template;
};

enum ccn_upcall_res
handleServer(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info);

struct interest_header_t {
};

ccn_sys_t *ccn_sys;

/*
 * handleServer
 *
 * Server response
 *
 */
enum ccn_upcall_res
handleServer(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info) {
    struct ccn_charbuf *name = NULL;
    struct ccn_charbuf *temp1 = NULL;
    const unsigned char *ccnb = NULL;
    size_t ccnb_size = 0;
    const unsigned char *data = NULL;
    size_t data_size = 0;
    size_t written = 0;
    const unsigned char *ib = NULL;
    struct ccn_indexbuf *ic = NULL;
    int retvalue;

    // TODO: Does a server need this?
    // Sanity check
    switch (kind) {
        case CCN_UPCALL_FINAL:
            // No more chunks
            return CCN_UPCALL_RESULT_OK;
        case CCN_UPCALL_INTEREST_TIMED_OUT:
            // Daemon notified server timed out. Reexpress interest
            return CCN_UPCALL_RESULT_REEXPRESS;
        case CCN_UPCALL_CONTENT_UNVERIFIED:
            // Requires verification
            return CCN_UPCALL_RESULT_VERIFY;
        case CCN_UPCALL_CONTENT:
            //return CCN_UPCALL_RESULT_OK;
            break;
        default:
            return CCN_UPCALL_RESULT_ERR;
    }
    
    // Localize content
    ccnb = info->content_ccnb;
    ccnb_size = info->pco->offset[CCN_PCO_E];
    ib = info->interest_ccnb;
    ic = info->interest_comps;
    retvalue = ccn_content_get_value(ccnb, ccnb_size, info->pco, &data, &data_size);
    if (retvalue < 0 ) {
        message_on_new_client();
        exit(retvalue);
    }

    // Interpret content
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

    // Publish client mountpoint
    ccn_sys->mountpoint = ccn_charbuf_create();
    if( ccn_sys->mountpoint == NULL ) {
        message_on_charbuf_nomem("mountpoint");
        exit(retvalue);
    }
    // TODO:location
    // Take from input + random session id
    retvalue = ccn_name_from_uri(ccn_sys->mountpoint,location);
    if( retvalue < 0 ) {
        message_on_name_failure("server mountpoint");
        exit(retvalue);
    }

    retvalue = ccn_set_interest_filter(ccn_sys->ccn,ccn_sys->mountpoint,
            ccn_sys->responseHandler);
    if( retvalue < 0 ) {
        message_on_route_failure();
        exit(retvalue);
    }
}

/*
 * connect()
 *
 * Send initial interest to server
 */
void
connect() {
    int retvalue;
    struct ccn_charbuf *templ = NULL;
    struct interest_header_t *header = NULL;

    // Build name
    server_name = ccn_charbuf_create();
    // TODO:location
    retvalue = ccn_name_from_uri(server_name,location);
    if( retvalue < 0 ) {
        message_on_name_failure("server name");
        exit(retvalue);
    }

    // Build interest
    templ = make_interest_template(header,NULL);
    
    ccn_express_interest(ccn_sys->ccn, server_name, ccn_sys->responseHandler, templ);

    ccn_charbuf_destroy(&templ);
    ccn_charbuf_destroy(&server_name);
}
