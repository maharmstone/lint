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

#define TOKEN_ASSIGN_PRIMARY        0x0001
#define TOKEN_DUPLICATE             0x0002
#define TOKEN_IMPERSONATE           0x0004
#define TOKEN_QUERY                 0x0008
#define TOKEN_QUERY_SOURCE          0x0010
#define TOKEN_ADJUST_PRIVILEGES     0x0020
#define TOKEN_ADJUST_GROUPS         0x0040
#define TOKEN_ADJUST_DEFAULT        0x0080
#define TOKEN_ADJUST_SESSIONID      0x0100

#define TOKEN_GENERIC_READ TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | \
                           READ_CONTROL

#define TOKEN_GENERIC_WRITE TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | \
                            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | \
                            READ_CONTROL

#define TOKEN_GENERIC_EXECUTE TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | \
                              READ_CONTROL

#define TOKEN_ALL_ACCESS TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | \
                         TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | \
                         TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | \
                         TOKEN_ADJUST_SESSIONID | DELETE | READ_CONTROL | WRITE_DAC | \
                         WRITE_OWNER

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001
#define SE_PRIVILEGE_ENABLED            0x00000002
#define SE_PRIVILEGE_REMOVED            0x00000004
#define SE_PRIVILEGE_USED_FOR_ACCESS    0x80000000

#define SE_CREATE_TOKEN_PRIVILEGE            2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE      3
#define SE_LOCK_MEMORY_PRIVILEGE             4
#define SE_INCREASE_QUOTA_PRIVILEGE          5
#define SE_MACHINE_ACCOUNT_PRIVILEGE         6
#define SE_TCB_PRIVILEGE                     7
#define SE_SECURITY_PRIVILEGE                8
#define SE_TAKE_OWNERSHIP_PRIVILEGE          9
#define SE_LOAD_DRIVER_PRIVILEGE            10
#define SE_SYSTEM_PROFILE_PRIVILEGE         11
#define SE_SYSTEMTIME_PRIVILEGE             12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    13
#define SE_INC_BASE_PRIORITY_PRIVILEGE      14
#define SE_CREATE_PAGEFILE_PRIVILEGE        15
#define SE_CREATE_PERMANENT_PRIVILEGE       16
#define SE_BACKUP_PRIVILEGE                 17
#define SE_RESTORE_PRIVILEGE                18
#define SE_SHUTDOWN_PRIVILEGE               19
#define SE_DEBUG_PRIVILEGE                  20
#define SE_AUDIT_PRIVILEGE                  21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     22
#define SE_CHANGE_NOTIFY_PRIVILEGE          23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        24
#define SE_UNDOCK_PRIVILEGE                 25
#define SE_SYNC_AGENT_PRIVILEGE             26
#define SE_ENABLE_DELEGATION_PRIVILEGE      27
#define SE_MANAGE_VOLUME_PRIVILEGE          28
#define SE_IMPERSONATE_PRIVILEGE            29
#define SE_CREATE_GLOBAL_PRIVILEGE          30
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE 31
#define SE_RELABEL_PRIVILEGE                32
#define SE_INC_WORKING_SET_PRIVILEGE        33
#define SE_TIME_ZONE_PRIVILEGE              34
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   35

#define SE_GROUP_MANDATORY          0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT 0x00000002
#define SE_GROUP_ENABLED            0x00000004

typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
} LUID, *PLUID;

typedef struct {
    LUID Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES;

typedef struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _SID {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[1];
} SID, *PSID;

typedef struct {
    PSID Sid;
    DWORD Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _TOKEN_GROUPS {
    DWORD GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

#define TOKEN_SOURCE_LENGTH 8

typedef struct _TOKEN_SOURCE {
    CHAR SourceName[TOKEN_SOURCE_LENGTH];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef struct {
    uint8_t AclRevision;
    uint8_t Sbz1;
    uint16_t AclSize;
    uint16_t AceCount;
    uint16_t Sbz2;
} ACL, *PACL;

typedef struct _TOKEN_DEFAULT_DACL {
    PACL DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef enum {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL;

typedef struct _token_object {
    object_header header;
    struct rw_semaphore sem;
    SID* user;
    SID* primary_group;
    SID* owner;
    TOKEN_PRIVILEGES* privs;
    int64_t expiry;
    LUID auth_id;
    TOKEN_GROUPS* groups;
    TOKEN_SOURCE source;
    PACL default_dacl;
    TOKEN_TYPE type;
    SECURITY_IMPERSONATION_LEVEL impersonation_level;
    LUID token_id;
    LUID modified_id;
} token_object;

typedef struct {
    uint8_t AceType;
    uint8_t AceFlags;
    uint16_t AceSize;
} ACE_HEADER;

typedef struct {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_ALLOWED_ACE;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_OWNER {
    PSID Owner;
} TOKEN_OWNER, *PTOKEN_OWNER;

typedef struct _TOKEN_PRIMARY_GROUP {
    PSID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;

typedef struct {
    LUID TokenId;
    LUID AuthenticationId;
    LARGE_INTEGER ExpirationTime;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    DWORD DynamicCharged;
    DWORD DynamicAvailable;
    DWORD GroupCount;
    DWORD PrivilegeCount;
    LUID ModifiedId;
} TOKEN_STATISTICS;

typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE;

typedef struct {
    DWORD Length;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    BOOLEAN EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE;
