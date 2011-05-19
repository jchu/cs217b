#ifndef _messages_h_
#define _messages_h_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <ccn/ccn.h>

// use ccn_perror?

static inline void
message_on_ccnd_connect_failure(struct ccn* ccn) {
    cnn_perror(ccn,"Failure to connect to ccnd\n");
}

static inline void
message_on_charbuf_nomem(struct ccn*, char * var) {
    ccn_perror(sys->ccn,"Failure to allocate %s\n",var);
}

static inline void
message_on_name_failure(struct ccn*, char * var) {
    ccn_perror(sys->ccn,"Could not resolve %s\n",var);
}

#endif /* _messages_h_ */
