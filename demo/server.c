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

    // Parse interest name
    // Expecting /domain/clinet/<init msg>
    if( ccn_name_comp_strcmp(info->interest_ccnb, info->interest_comps,info->matched_comps + 1, "client" )  == 0 ) {

        const unsigned char* msg;
        size_t msg_size;
        result = ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                info->matched_comps + 2, &msg, &msg_size );
        if( result <= 0 ) {
            // Interest with unrecongized name format
            return CCN_UPCALL_RESULT_ERR;
        }

        printf("Received client message (len%d)\n",msg_lenth);

        // Respond with SSH version number
        //ccn_put(info->h, contents, size);
        // return CCN_IPCALL_RESULT_INTEREST_CONSUMED

        // Send new interest to initiate user authentication
    

    } else {
        // Interest with unrecongized name format
        return CCN_UPCALL_RESULT_ERR;
    }


    return CCN_UPCALL_RESULT_OK;
}

void
setup(int argc, char** argv) {
    int retvalue = EXIT_FAILURE;
    // CCN Handle
    sys->ccn = ccn_create();
    if( sys->ccn == NULL || ccn_connect(sys->ccn,NULL) == -1 ) {
        message_on_ccnd_connect_failure(sys->ccn);
        ccn_destroy(sys->ccn);
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
}
