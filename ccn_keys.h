/*
 * 
 * Borrowed and modified from VoCCN
 *
 */

#ifndef _ccn_keys_h_
#define _ccn_keys_h_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <ccn/ccn.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>

static struct ccn_keystore *
init_keystore();

static const struct ccn_pkey *
get_my_private_key(struct ccn_keystore *cached_keystore);

static const struct ccn_pkey *
get_my_public_key(struct ccn_keystore *cached_keystore);

int
get_public_key(struct ccn* ccn, const char *host, struct ccn_pkey **pkeyp);

static int
ccn_create_keylocator(struct ccn_charbuf *c, const struct ccn_pkey *k);

static int
ccn_publish_key(struct ccn* ccn, struct ccn_keystore *cached_keystore, const char *host, int type, int id);

#endif /* _ccn_keys_h_ */
