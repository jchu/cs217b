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
    struct ccn_closure *responseHandler; // Handle server interests
    struct ccn_charbuf *mountpoint; // Server response target
    struct ccn_charbuf *interest_template;
};

enum ccn_upcall_res
handleServer(struct ccn_closure *selfp,
        enum ccn_upcall_kind kind,
        struct ccn_upcall_info *info);

struct interest_header_t {
};

typedef struct ccn_sys_t *ccn_sys;

ccn_sys sys;

int client_id;

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

    printf("Got interest matching %d components, kind = %d\n", info->matched_comps, kind);

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
        message_on_new_client(sys->ccn);
        exit(retvalue);
    }

    // Interpret content

    return CCN_UPCALL_RESULT_OK;
}

struct ccn_charbuf *
make_interest_template()
{
    struct ccn_charbuf *templ = ccn_charbuf_create();
    ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG); /* <Interest> */
    ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG); /* <Name> */
    ccn_charbuf_append_closer(templ); /* </Name> */

    // TODO: consider min/max suffix components
    // TODO: AnswerOriginKind
    
    ccn_charbuf_append_closer(templ); /* </Interest> */
    return templ;
}

void
setup(int argc, char** argv) {
    int retvalue = EXIT_FAILURE;

    // CCN Handle
    sys->ccn = ccn_create();
    if( sys->ccn == NULL || ccn_connect(sys->ccn,NULL) == -1 ) {
        message_on_ccnd_connect_failure(sys->ccn);
        ccn_destroy(&(sys->ccn));
        exit(retvalue);
    }

    // Publish client mountpoint
    sys->mountpoint = ccn_charbuf_create();
    if( sys->mountpoint == NULL ) {
        message_on_charbuf_nomem(sys->ccn,"mountpoint");
        exit(retvalue);
    }
    // TODO: auto generate local domain
    // Take from input + random session id
    char* client_location = argv[1];
    retvalue = ccn_name_from_uri(sys->mountpoint,client_location);
    if( retvalue < 0 ) {
        message_on_name_failure(sys->ccn,"server mountpoint");
        exit(retvalue);
    }
    ccn_name_append_str(sys->mountpoint,"ssh");

    client_id = rand();
    ccn_name_append_numeric(sys->mountpoint,CCN_MARKER_NONE,client_id);

    retvalue = ccn_set_interest_filter(sys->ccn,sys->mountpoint,
            sys->responseHandler);
    if( retvalue < 0 ) {
        message_on_route_failure(sys->ccn);
        exit(retvalue);
    }
}

/*
 * remote_connect()
 *
 * Send initial interest to server
 */
void
remote_connect(int argc, char** argv) {
    int retvalue;
    struct ccn_charbuf *templ = NULL;
    struct interest_header_t *header = NULL;

    char* client_location = argv[1];
    char* server_location = argv[2];

    // Build remote name
    struct ccn_charbuf *server_name = ccn_charbuf_create();
    // TODO:location
    retvalue = ccn_name_from_uri(server_name,server_location);
    if( retvalue < 0 ) {
        message_on_name_failure(sys->ccn,"server name");
        exit(retvalue);
    }
    ccn_name_append_str(server_name,"ssh");
    ccn_name_append_str(server_name,"client");

    // Add return path and init message to server name
    ccn_name_append_str(server_name,client_location);
    ccn_name_append_str(server_name,"ssh");
    ccn_name_append_numeric(server_name,CCN_MARKER_NONE,client_id);
    // Init message

    // Build interest
    templ = make_interest_template(header,NULL);
    
    printf("Expressing interest to server\n");
    ccn_express_interest(sys->ccn, server_name, sys->responseHandler, templ);

    ccn_charbuf_destroy(&templ);
    ccn_charbuf_destroy(&server_name);
}

int main(int argc, char** argv) {
    sys = (ccn_sys) malloc(sizeof(struct ccn_sys_t));
    srand(time(NULL));
    setup(argc,argv);
    remote_connect(argc,argv);
    ccn_run(sys->ccn,-1);
    
    return 0;
}
