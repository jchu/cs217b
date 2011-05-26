#ifndef _messages_h_
#define _messages_h_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <ccn/ccn.h>

// use ccn_perror?

static inline void
message_on_ccnd_connect_failure(struct ccn* ccn) {
    ccn_perror(ccn,"Failure to connect to ccnd\n");
}

static inline void
message_on_charbuf_nomem(struct ccn* ccn, char * var) {
    ccn_perror(ccn,"Failure to allocate charbuf:");
    ccn_perror(ccn,var);
    ccn_perror(ccn,"\n");
}

static inline void
message_on_name_failure(struct ccn* ccn, char * var) {
    ccn_perror(ccn,"Could not resolve ccn name:");
    ccn_perror(ccn,var);
    ccn_perror(ccn,"\n");
}

static inline void
message_on_route_failure(struct ccn* ccn) {
    ccn_perror(ccn,"Could not setup interest filter");
}

static inline void
message_on_new_client(struct ccn* ccn) {
    ccn_perror(ccn,"Failed to understand server");
}

static inline void
message_on_send_failure(struct ccn* ccn) {
    ccn_perror(ccn,"Failed to send data");
}

#endif /* _messages_h_ */
