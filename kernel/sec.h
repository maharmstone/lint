#pragma once

#include <linux/types.h>

typedef struct _SID {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[1];
} SID;

typedef struct _SECURITY_DESCRIPTOR {
    uint8_t Revision;
    uint8_t Sbz1;
    uint16_t Control;
    uint32_t OffsetOwner;
    uint32_t OffsetGroup;
    uint32_t OffsetSacl;
    uint32_t OffsetDacl;
} SECURITY_DESCRIPTOR;

typedef struct {
    uint8_t AclRevision;
    uint8_t Sbz1;
    uint16_t AclSize;
    uint16_t AceCount;
    uint16_t Sbz2;
} ACL;

typedef struct {
    uint8_t AceType;
    uint8_t AceFlags;
    uint16_t AceSize;
} ACE_HEADER;

typedef struct {
    ACE_HEADER Header;
    uint32_t Mask;
} ACCESS_ALLOWED_ACE;
