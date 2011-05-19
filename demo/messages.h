#ifndef _messages_h_
#define _messages_h_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static inline void
message_on_ccnd_connect_failure() {
    fprintf(stderr,"Failure to connect to ccnd\n");
}

static inline void
message_on_charbuf_nomem(char * var) {
    fprintf(stderr,"Failure to allocate %s\n",var);
}

static inline void
message_on_name_failure(char * var) {
    fprintf(stderr,"Could not resolve %s\n",var);
}

#endif /* _messages_h_ */
