#ifndef _ccn_common_h_
#define _ccn_common_h_

#define CCN_SSH_VERSION         "SSH-2.0-CCN"

/* CCN State */
#define CCN_STATE_INIT          0
#define CCN_STATE_PENDING       1
#define CCN_STATE_TIMEOUT       2
#define CCN_STATE_CLOSED        3
#define CCN_STATE_CONNECTED     4

/* CCN Packets */
struct ccn_init_packet_t {
    char[256] protoocl_version;
};

#endif /* _ccn_common_h_ */
