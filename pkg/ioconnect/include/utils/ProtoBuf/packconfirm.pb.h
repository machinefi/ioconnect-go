/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.7 */

#ifndef PB_PACKCONFIRM_PB_H_INCLUDED
#define PB_PACKCONFIRM_PB_H_INCLUDED
#include "include/utils/ProtoBuf/pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Struct definitions */
typedef PB_BYTES_ARRAY_T(32) Confirm_owner_t;
typedef PB_BYTES_ARRAY_T(128) Confirm_signature_t;
typedef struct _Confirm {
    Confirm_owner_t owner;
    uint32_t timestamp;
    Confirm_signature_t signature;
    uint32_t channel;
} Confirm;


#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define Confirm_init_default                     {{0, {0}}, 0, {0, {0}}, 0}
#define Confirm_init_zero                        {{0, {0}}, 0, {0, {0}}, 0}

/* Field tags (for use in manual encoding/decoding) */
#define Confirm_owner_tag                        1
#define Confirm_timestamp_tag                    2
#define Confirm_signature_tag                    3
#define Confirm_channel_tag                      4

/* Struct field encoding specification for nanopb */
#define Confirm_FIELDLIST(X, a) \
X(a, STATIC,   SINGULAR, BYTES,    owner,             1) \
X(a, STATIC,   SINGULAR, UINT32,   timestamp,         2) \
X(a, STATIC,   SINGULAR, BYTES,    signature,         3) \
X(a, STATIC,   SINGULAR, UINT32,   channel,           4)
#define Confirm_CALLBACK NULL
#define Confirm_DEFAULT NULL

extern const pb_msgdesc_t Confirm_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define Confirm_fields &Confirm_msg

/* Maximum encoded size of messages (where known) */
#define Confirm_size                             177

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
