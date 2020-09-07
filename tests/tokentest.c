#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <uchar.h>

#ifdef _WIN32

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

NTSTATUS __stdcall NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                                 PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                                 PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                                 PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                                 PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                                 PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource);

NTSTATUS __stdcall NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      PHANDLE TokenHandle);


NTSTATUS __stdcall NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                           PTOKEN_PRIVILEGES TokenPrivileges,
                                           ULONG PreviousPrivilegesLength,
                                           PTOKEN_PRIVILEGES PreviousPrivileges,
                                           PULONG RequiredLength);

#define STATUS_NOT_ALL_ASSIGNED (NTSTATUS)0x00000106

#else

#define SYSTEM_LUID { 0x3e7, 0x0 }

#endif

typedef struct {
    uint8_t Revision;
    uint8_t SubAuthorityCount;
    uint8_t IdentifierAuthority[6];
    uint32_t SubAuthority[2];
} SID2;

static const SID2 user_sid = { 1, 2, { 0, 0, 0, 0, 0, 22 }, { 1, 1000 } }; // S-1-22-1-1000

static const SID2 group_sid = { 1, 2, { 0, 0, 0, 0, 0, 22 }, { 2, 100 } }; // S-1-22-2-100

int main() {
    NTSTATUS Status;
    HANDLE proc_token, h;
    TOKEN_PRIVILEGES thread_privs, privs;
    LARGE_INTEGER expiry;
    TOKEN_USER user;
    LUID luid = SYSTEM_LUID;
    TOKEN_GROUPS groups;
    TOKEN_OWNER owner;
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_SOURCE source = { "muw test", { 42, 0 } };

    Status = NtOpenProcessToken(NtCurrentProcess(), MAXIMUM_ALLOWED, &proc_token);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtOpenProcessToken returned %08x\n", (int32_t)Status);
        return 10;
    }

    thread_privs.PrivilegeCount = 1;
    thread_privs.Privileges[0].Luid.LowPart = 2; // SeCreateTokenPrivilege
    thread_privs.Privileges[0].Luid.HighPart = 0;
    thread_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Status = NtAdjustPrivilegesToken(proc_token, false, &thread_privs, 0, NULL, NULL);
    if (Status == STATUS_NOT_ALL_ASSIGNED) {
        fprintf(stderr, "NtAdjustPrivilegesToken returned STATUS_NOT_ALL_ASSIGNED\n");
        NtClose(proc_token);
        return 1;
    } else if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtAdjustPrivilegesToken returned %08x\n", (int32_t)Status);
        NtClose(proc_token);
        return 1;
    }

    NtClose(proc_token);

    expiry.QuadPart = 0;

    user.User.Attributes = 0;
    user.User.Sid = (PSID)&user_sid;

    groups.GroupCount = 1;
    groups.Groups[0].Attributes = 0;
    groups.Groups[0].Sid = (PSID)&group_sid;

    privs.PrivilegeCount = 0;
    // FIXME - add privileges

    owner.Owner = (PSID)&user_sid;

    primary_group.PrimaryGroup = (PSID)&group_sid;

    Status = NtCreateToken(&h, MAXIMUM_ALLOWED, NULL, TokenPrimary, &luid, &expiry, &user,
                           &groups, &privs, &owner, &primary_group, NULL/*FIXME - default DACL*/,
                           &source);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateToken returned %08x\n", (int32_t)Status);
        return 1;
    }

    NtClose(h);

    return 0;
}
