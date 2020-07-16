#pragma once

#include <linux/types.h>

#define SE_OWNER_DEFAULTED          0x0001
#define SE_GROUP_DEFAULTED          0x0002
#define SE_DACL_PRESENT             0x0004
#define SE_DACL_DEFAULTED           0x0008
#define SE_SACL_PRESENT             0x0010
#define SE_SACL_DEFAULTED           0x0020
#define SE_DACL_AUTO_INHERIT_REQ    0x0100
#define SE_SACL_AUTO_INHERIT_REQ    0x0200
#define SE_DACL_AUTO_INHERITED      0x0400
#define SE_SACL_AUTO_INHERITED      0x0800
#define SE_DACL_PROTECTED           0x1000
#define SE_SACL_PROTECTED           0x2000
#define SE_RM_CONTROL_VALID         0x4000
#define SE_SELF_RELATIVE            0x8000

#define OBJECT_INHERIT_ACE          0x01
#define CONTAINER_INHERIT_ACE       0x02
#define NO_PROPAGATE_INHERIT_ACE    0x04
#define INHERIT_ONLY_ACE            0x08
#define INHERITED_ACE               0x10

#define ACCESS_ALLOWED_ACE_TYPE     0x0

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
