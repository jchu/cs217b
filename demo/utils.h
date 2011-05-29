#ifndef _utils_h_
#define _utils_h_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <ccn/ccn.h>

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

#endif /* _utils_h_ */
