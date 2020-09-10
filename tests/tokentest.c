#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#ifdef _WIN32

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

NTSTATUS __stdcall NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                                 PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                                 PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                                 PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                                 PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                                 PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource);

NTSTATUS __stdcall NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      PHANDLE TokenHandle);

NTSTATUS __stdcall NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                     BOOLEAN OpenAsSelf, PHANDLE TokenHandle);

NTSTATUS __stdcall NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                           PTOKEN_PRIVILEGES TokenPrivileges,
                                           ULONG PreviousPrivilegesLength,
                                           PTOKEN_PRIVILEGES PreviousPrivileges,
                                           PULONG RequiredLength);

NTSTATUS __stdcall NtQueryInformationToken(HANDLE TokenHandle,
                                           TOKEN_INFORMATION_CLASS TokenInformationClass,
                                           PVOID TokenInformation, ULONG TokenInformationLength,
                                           PULONG ReturnLength);

NTSTATUS __stdcall NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                     const OBJECT_ATTRIBUTES* ObjectAttributes, LONG InitialCount,
                                     LONG MaximumCount);

NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                         PULONG LengthNeeded);

NTSTATUS __stdcall NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                          PVOID ThreadInformation, ULONG ThreadInformationLength);

#else

#define SYSTEM_LUID { 0x3e7, 0x0 }

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001
#define SE_PRIVILEGE_ENABLED            0x00000002

typedef enum {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL;

typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE;

typedef struct {
    DWORD Length;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
    BOOLEAN EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE;

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

typedef struct {
    BYTE AceType;
    BYTE AceFlags;
    WORD AceSize;
} ACE_HEADER;

#define ACCESS_ALLOWED_ACE_TYPE 0

typedef struct {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
} ACCESS_ALLOWED_ACE;

typedef struct {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY;

typedef struct {
    BYTE Revision;
    BYTE SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[1];
} SID;

typedef WORD SECURITY_DESCRIPTOR_CONTROL;

typedef struct {
    BYTE Revision;
    BYTE Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;

#define OWNER_SECURITY_INFORMATION  0x00000001
#define GROUP_SECURITY_INFORMATION  0x00000002
#define DACL_SECURITY_INFORMATION   0x00000004
#define SACL_SECURITY_INFORMATION   0x00000008

#define SE_GROUP_ENABLED    0x00000004

#endif

#define STATUS_NOT_ALL_ASSIGNED (NTSTATUS)0x00000106

typedef struct {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[2];
} SID2;

static const SID2 user_sid = { 1, 2, { 0, 0, 0, 0, 0, 22 }, { 1, 1000 } }; // S-1-22-1-1000

static const SID2 group_sid = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, 544} }; // S-1-5-32-544 (Administrators)

static void sid_to_string(SID* sid, char* s) {
    uint64_t auth;

    static const char prefix[] = "S-1-";

    memcpy(s, prefix, sizeof(prefix));

    auth = ((uint64_t)sid->IdentifierAuthority.Value[0] << 40) |
        ((uint64_t)sid->IdentifierAuthority.Value[1] << 32) |
        ((uint64_t)sid->IdentifierAuthority.Value[2] << 24) |
        ((uint64_t)sid->IdentifierAuthority.Value[3] << 16) |
        ((uint64_t)sid->IdentifierAuthority.Value[4] << 8) |
        (uint64_t)sid->IdentifierAuthority.Value[5];

#pragma GCC diagnostic ignored "-Wrestrict"
#ifdef _WIN32
    sprintf(s, "%s%I64u", s, auth);
#else
    sprintf(s, "%s%lu", s, auth);
#endif

    for (unsigned int i = 0; i < sid->SubAuthorityCount; i++) {
        sprintf(s, "%s-%u", s, sid->SubAuthority[i]);
    }
#pragma GCC diagnostic pop
}

static void print_acl(PACL acl) {
    ACE_HEADER* ace;
    char s[255];

    printf("\tAclRevision: %x\n", acl->AclRevision);
    printf("\tSbz1: %x\n", acl->Sbz1);
    printf("\tAclSize: %x\n", acl->AclSize);
    printf("\tAceCount: %x\n", acl->AceCount);
    printf("\tSbz2: %x\n", acl->Sbz2);

    ace = (ACE_HEADER*)&acl[1];

    for (unsigned int i = 0; i < acl->AceCount; i++) {
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)ace;

            sid_to_string((PSID)&aaa->SidStart, s);

            printf("\tACE (flags = %u, size = %u): allow %s (mask = %x)\n", aaa->Header.AceFlags,
                   aaa->Header.AceSize, s, aaa->Mask);
        } else {
            printf("\tACE (flags = %u, size = %u): unhandled type %u\n", ace->AceFlags,
                   ace->AceSize, ace->AceType);
        }

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }
}

static void get_token_info(HANDLE h) {
    NTSTATUS Status;
    uint8_t buf[1024];
    char s[255];
    ULONG retlen;

    Status = NtQueryInformationToken(h, TokenUser, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenUser\n", (int32_t)Status);
    else {
        sid_to_string(((TOKEN_USER*)buf)->User.Sid, s);

        printf("user = %s\n", s);
    }

    Status = NtQueryInformationToken(h, TokenOwner, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenOwner\n", (int32_t)Status);
    else {
        sid_to_string(((TOKEN_OWNER*)buf)->Owner, s);

        printf("owner = %s\n", s);
    }

    Status = NtQueryInformationToken(h, TokenPrimaryGroup, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenPrimaryGroup\n", (int32_t)Status);
    else {
        sid_to_string(((TOKEN_PRIMARY_GROUP*)buf)->PrimaryGroup, s);

        printf("primary group = %s\n", s);
    }

    Status = NtQueryInformationToken(h, TokenGroups, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenGroups\n", (int32_t)Status);
    else {
        TOKEN_GROUPS* tg = (TOKEN_GROUPS*)buf;

        printf("groups:\n");

        for (unsigned int i = 0; i < tg->GroupCount; i++) {
            sid_to_string(tg->Groups[i].Sid, s);

            printf("\t%s (%x)\n", s, tg->Groups[i].Attributes);
        }
    }

    Status = NtQueryInformationToken(h, TokenPrivileges, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenPrivileges\n", (int32_t)Status);
    else {
        TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)buf;

        printf("privileges:\n");

        for (unsigned int i = 0; i < tp->PrivilegeCount; i++) {
            printf("\t{%u, %u} (%u)\n", tp->Privileges[i].Luid.LowPart,
                   tp->Privileges[i].Luid.HighPart, tp->Privileges[i].Attributes);
        }
    }

    Status = NtQueryInformationToken(h, TokenImpersonationLevel, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenImpersonationLevel\n", (int32_t)Status);
    else
        printf("impersonation level: %u\n", *(SECURITY_IMPERSONATION_LEVEL*)buf);

    // FIXME - TokenLogonSid

    Status = NtQueryInformationToken(h, TokenStatistics, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenStatistics\n", (int32_t)Status);
    else {
        TOKEN_STATISTICS* ts = (TOKEN_STATISTICS*)buf;
        printf("statistics:\n");

        printf("\ttoken ID = {%u, %u}\n", ts->TokenId.LowPart, ts->TokenId.HighPart);
        printf("\tauth ID = {%u, %u}\n", ts->AuthenticationId.LowPart, ts->AuthenticationId.HighPart);
        printf("\texpiry = %lld\n", (long long)ts->ExpirationTime.QuadPart);
        printf("\ttype = %u\n", ts->TokenType);
        printf("\timpersonation level = %u\n", ts->ImpersonationLevel);
        printf("\tdynamic charged = %u\n", ts->DynamicCharged);
        printf("\tdynamic available = %u\n", ts->DynamicAvailable);
        printf("\tgroup count = %u\n", ts->GroupCount);
        printf("\tprivilege count = %u\n", ts->PrivilegeCount);
        printf("\tmodified ID = {%u, %u}\n", ts->ModifiedId.LowPart, ts->ModifiedId.HighPart);
    }

    Status = NtQueryInformationToken(h, TokenType, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenType\n", (int32_t)Status);
    else
        printf("token type: %u\n", *(TOKEN_TYPE*)buf);

    Status = NtQueryInformationToken(h, TokenDefaultDacl, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenDefaultDacl\n", (int32_t)Status);
    else {
        PACL acl = ((TOKEN_DEFAULT_DACL*)buf)->DefaultDacl;

        printf("default DACL:\n");

        if (acl)
            print_acl(acl);
        else
            printf("\t(null)\n");
    }

    Status = NtQueryInformationToken(h, TokenLogonSid, buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtQueryInformationToken returned %08x for TokenLogonSid\n", (int32_t)Status);
    else {
        TOKEN_GROUPS* tg = (TOKEN_GROUPS*)buf;

        printf("Logon SIDs:\n");

        for (unsigned int i = 0; i < tg->GroupCount; i++) {
            sid_to_string(tg->Groups[i].Sid, s);

            printf("\t%s (%x)\n", s, tg->Groups[i].Attributes);
        }
    }
}

static void test_object_sd() {
    NTSTATUS Status;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    uint8_t buf[1024];
    SECURITY_DESCRIPTOR_RELATIVE* sd = (SECURITY_DESCRIPTOR_RELATIVE*)buf;
    ULONG needed;

    static const char16_t path[] = u"\\testobj";

    us.Length = us.MaximumLength = sizeof(path) - sizeof(char16_t);
    us.Buffer = (WCHAR*)path;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateSemaphore(&h, MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY, &oa, 2, 2);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateSemaphore returned %08x\n", (int32_t)Status);
        return;
    }

    Status = NtQuerySecurityObject(h, OWNER_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd,
                                   sizeof(buf), &needed);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySecurityObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    if (sd->Owner == 0)
        fprintf(stderr, "SD owner not set.\n");
    else {
        char s[255];

        sid_to_string((SID*)((uint8_t*)sd + (int)sd->Owner), s);

        printf("object owner = %s\n", s);
    }

    Status = NtQuerySecurityObject(h, GROUP_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd,
                                   sizeof(buf), &needed);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySecurityObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    if (sd->Group == 0)
        fprintf(stderr, "SD group not set.\n");
    else {
        char s[255];

        sid_to_string((SID*)((uint8_t*)sd + (int)sd->Group), s);

        printf("object group = %s\n", s);
    }

    Status = NtQuerySecurityObject(h, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd,
                                   sizeof(buf), &needed);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySecurityObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    if (sd->Dacl == 0)
        fprintf(stderr, "SD DACL not set.\n");
    else {
        ACL* acl = (ACL*)((uint8_t*)sd + (int)sd->Dacl);

        printf("object DACL:\n");
        print_acl(acl);
    }

    Status = NtQuerySecurityObject(h, SACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)sd,
                                   sizeof(buf), &needed);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySecurityObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    if (sd->Sacl == 0)
        fprintf(stderr, "SD SACL not set.\n");
    else {
        ACL* acl = (ACL*)((uint8_t*)sd + (int)sd->Sacl);

        printf("object SACL:\n");
        print_acl(acl);
    }

    NtClose(h);
}

int main() {
    NTSTATUS Status;
    HANDLE proc_token, thread_token, h;
    TOKEN_PRIVILEGES* thread_privs;
    TOKEN_PRIVILEGES* privs;
    LARGE_INTEGER expiry;
    TOKEN_USER user;
    LUID luid = SYSTEM_LUID;
    TOKEN_GROUPS groups;
    TOKEN_OWNER owner;
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_SOURCE source = { "muw test", { 42, 0 } };
    OBJECT_ATTRIBUTES oa;
    SECURITY_QUALITY_OF_SERVICE qos;

    Status = NtOpenProcessToken(NtCurrentProcess(), MAXIMUM_ALLOWED, &proc_token);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtOpenProcessToken returned %08x\n", (int32_t)Status);
    else {
        printf("process token:\n");
        get_token_info(proc_token);
        printf("---\n\n");
    }

    thread_privs = malloc(offsetof(TOKEN_PRIVILEGES, Privileges) + (3 * sizeof(LUID_AND_ATTRIBUTES)));

    thread_privs->PrivilegeCount = 3;
    thread_privs->Privileges[0].Luid.LowPart = 2; // SeCreateTokenPrivilege
    thread_privs->Privileges[0].Luid.HighPart = 0;
    thread_privs->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    thread_privs->Privileges[1].Luid.LowPart = 8; // SeSecurityPrivilege
    thread_privs->Privileges[1].Luid.HighPart = 0;
    thread_privs->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    thread_privs->Privileges[2].Luid.LowPart = 29; // SeImpersonatePrivilege
    thread_privs->Privileges[2].Luid.HighPart = 0;
    thread_privs->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;

    Status = NtAdjustPrivilegesToken(proc_token, false, thread_privs, 0, NULL, NULL);
    if (Status == STATUS_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "NtAdjustPrivilegesToken returned STATUS_NOT_ALL_ASSIGNED\n");
        free(thread_privs);
        NtClose(proc_token);
        return 1;
    } else if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtAdjustPrivilegesToken returned %08x\n", (int32_t)Status);
        free(thread_privs);
        NtClose(proc_token);
        return 1;
    }

    free(thread_privs);
    NtClose(proc_token);

    printf("object SD:\n");
    test_object_sd();
    printf("---\n\n");

    expiry.QuadPart = 0;

    user.User.Attributes = 0;
    user.User.Sid = (PSID)&user_sid;

    groups.GroupCount = 1;
    groups.Groups[0].Attributes = SE_GROUP_ENABLED;
    groups.Groups[0].Sid = (PSID)&group_sid;

    privs = malloc(offsetof(TOKEN_PRIVILEGES, Privileges) + (3 * sizeof(LUID_AND_ATTRIBUTES)));
    privs->PrivilegeCount = 3;
    privs->Privileges[0].Luid.LowPart = 30; // SeCreateGlobalPrivilege
    privs->Privileges[0].Luid.HighPart = 0;
    privs->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    privs->Privileges[1].Luid.LowPart = 23; // SeChangeNotifyPrivilege
    privs->Privileges[1].Luid.HighPart = 0;
    privs->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
    privs->Privileges[2].Luid.LowPart = 8; // SeSecurityPrivilege
    privs->Privileges[2].Luid.HighPart = 0;
    privs->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;

    owner.Owner = (PSID)&user_sid;

    primary_group.PrimaryGroup = (PSID)&group_sid;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.SecurityQualityOfService = &qos;

    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = SecurityDelegation;
    qos.ContextTrackingMode = false;
    qos.EffectiveOnly = false;

    Status = NtCreateToken(&h, MAXIMUM_ALLOWED, &oa, TokenImpersonation, &luid, &expiry, &user,
                           &groups, privs, &owner, &primary_group, NULL/*FIXME - default DACL*/,
                           &source);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateToken returned %08x\n", (int32_t)Status);
        free(privs);
        return 1;
    }

    free(privs);

    printf("created token:\n");
    get_token_info(h);
    printf("---\n\n");

    Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &h,
                                    sizeof(HANDLE));
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationThread returned %08x\n", (int32_t)Status);
        NtClose(h);
        return 1;
    }

    Status = NtOpenThreadToken(NtCurrentThread(), MAXIMUM_ALLOWED, true, &thread_token);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtOpenProcessToken returned %08x\n", (int32_t)Status);
    else {
        printf("thread token:\n");
        get_token_info(thread_token);
        printf("---\n\n");

        NtClose(thread_token);
    }

    printf("object SD:\n");
    test_object_sd();
    printf("---\n\n");

    NtClose(h);

    return 0;
}
