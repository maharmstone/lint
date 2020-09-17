#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

static const uint8_t test_sid[] = { 1, 2, 0, 0, 0, 0, 0, 22, 1, 0, 0, 0, 1, 0, 0, 0 }; // S-1-22-1-1

#ifdef _WIN32

#define NtCurrentProcess() (HANDLE)(-1)

NTSTATUS __stdcall NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      PHANDLE TokenHandle);

NTSTATUS __stdcall NtQueryInformationToken(HANDLE TokenHandle,
                                           TOKEN_INFORMATION_CLASS TokenInformationClass,
                                           PVOID TokenInformation, ULONG TokenInformationLength,
                                           PULONG ReturnLength);

NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                         PULONG LengthNeeded);
#else

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

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    BYTE Revision;
    BYTE Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Owner;
    DWORD Group;
    DWORD Sacl;
    DWORD Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;

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

typedef struct {
    BOOLEAN DoDeleteFile;
} FILE_DISPOSITION_INFORMATION;

#define OBJECT_INHERIT_ACE          0x01
#define CONTAINER_INHERIT_ACE       0x02
#define NO_PROPAGATE_INHERIT_ACE    0x04
#define INHERIT_ONLY_ACE            0x08
#define INHERITED_ACE               0x10

#define TOKEN_QUERY                 0x0008

#define ACCESS_ALLOWED_ACE_TYPE     0x0

#define SE_DACL_PRESENT             0x0004
#define SE_SELF_RELATIVE            0x8000

#define FILE_READ_DATA                    0x0001
#define FILE_LIST_DIRECTORY               0x0001
#define FILE_WRITE_DATA                   0x0002
#define FILE_ADD_FILE                     0x0002
#define FILE_APPEND_DATA                  0x0004
#define FILE_ADD_SUBDIRECTORY             0x0004
#define FILE_CREATE_PIPE_INSTANCE         0x0004
#define FILE_READ_EA                      0x0008
#define FILE_WRITE_EA                     0x0010
#define FILE_EXECUTE                      0x0020
#define FILE_TRAVERSE                     0x0020
#define FILE_DELETE_CHILD                 0x0040
#define FILE_READ_ATTRIBUTES              0x0080
#define FILE_WRITE_ATTRIBUTES             0x0100

#define FILE_ALL_ACCESS FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | \
                        FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | \
                        FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | \
                        FILE_WRITE_ATTRIBUTES | DELETE | READ_CONTROL | \
                        WRITE_DAC | WRITE_OWNER

#define DACL_SECURITY_INFORMATION   0x00000004

#define FILE_CREATE                       0x00000002

#endif

SID* self_sid;
size_t self_sid_length;

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
        sprintf(s, "%s-%u", s, (uint32_t)sid->SubAuthority[i]);
    }
#pragma GCC diagnostic pop
}

static void check_acl(HANDLE h, const char* descr, uint8_t expected) {
    NTSTATUS Status;
    char buf[1024];
    ULONG needed;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    ACL* acl;
    ACE_HEADER* ace;

    Status = NtQuerySecurityObject(h, DACL_SECURITY_INFORMATION, buf, sizeof(buf), &needed);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySecurityObject returned %08x\n", (int32_t)Status);
        return;
    }

    sd = (SECURITY_DESCRIPTOR_RELATIVE*)buf;

    if (sd->Dacl == 0) {
        fprintf(stderr, "No DACL returned.");
        return;
    }

    acl = (ACL*)((uint8_t*)sd + sd->Dacl);
    ace = (ACE_HEADER*)&acl[1];

    for (unsigned int i = 0; i < acl->AceCount; i++) {
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            char s[255];
            ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)ace;

            if (!memcmp(&aaa->SidStart, test_sid, sizeof(test_sid))) {
                sid_to_string((SID*)&aaa->SidStart, s);

//                 printf("ACE: allow %x to %s (flags %x)\n", (uint32_t)aaa->Mask, s, aaa->Header.AceFlags);

                if (aaa->Header.AceFlags != expected) {
                    if (expected == 0xff)
                        fprintf(stderr, "%s: expected no ACE, actually found one with flags %x\n", descr, aaa->Header.AceFlags);
                    else
                        fprintf(stderr, "%s: expected flags %x, actually found %x\n", descr, expected, aaa->Header.AceFlags);
                }

                return;
            }
        } else
            fprintf(stderr, "%s: unexpected ACE type %u\n", descr, ace->AceType);

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }

    if (expected != 0xff)
        fprintf(stderr, "%s: expected ACE with flags %x, none found\n", descr, expected);
}

static void sd_test(uint8_t ace_flags, uint8_t expected_subdir_flags, uint8_t expected_file_flags,
                    uint8_t expected_subdir_file_flags, uint8_t expected_subdir_subdir_flags) {
    NTSTATUS Status;
    HANDLE h, subdir, file, subdir_file, subdir_subdir;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    size_t sd_size, acl_size;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    ACL* acl;
    ACCESS_ALLOWED_ACE* aaa;
    FILE_DISPOSITION_INFORMATION dispos;

    static const WCHAR path[] = L"\\??\\C:\\temp\\test";
    static const WCHAR subdir_name[] = L"subdir";
    static const WCHAR file_name[] = L"file";

    acl_size = sizeof(ACL);
    acl_size += offsetof(ACCESS_ALLOWED_ACE, SidStart) + self_sid_length;
    acl_size += offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(test_sid);

    acl = malloc(acl_size);
    acl->AclRevision = 2;
    acl->Sbz1 = 0;
    acl->AclSize = (uint16_t)acl_size;
    acl->AceCount = 2;
    acl->Sbz2 = 0;

    aaa = (ACCESS_ALLOWED_ACE*)&acl[1];
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    aaa->Header.AceSize = (uint16_t)(offsetof(ACCESS_ALLOWED_ACE, SidStart) + self_sid_length);
    aaa->Mask = FILE_ALL_ACCESS;
    memcpy(&aaa->SidStart, self_sid, self_sid_length);

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)aaa + aaa->Header.AceSize);
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = ace_flags;
    aaa->Header.AceSize = (uint16_t)(offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(test_sid));
    aaa->Mask = FILE_READ_DATA;
    memcpy(&aaa->SidStart, test_sid, sizeof(test_sid));

    sd_size = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + acl_size;
    sd = malloc(sd_size);
    memset(sd, 0, sd_size);
    sd->Revision = 1;
    sd->Control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
    sd->Dacl = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    memcpy((uint8_t*)sd + sd->Dacl, acl, acl_size);

    free(acl);

    us.Length = us.MaximumLength = sizeof(path) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)path;

    memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.ObjectName = &us;
    oa.SecurityDescriptor = sd;

    Status = NtCreateFile(&h, FILE_ALL_ACCESS, &oa, &iosb, NULL, 0,
                          0, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);

    free(sd);

    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateFile returned %08x\n", (int32_t)Status);
        return;
    }

    oa.RootDirectory = h;
    oa.SecurityDescriptor = NULL;
    us.Length = us.MaximumLength = sizeof(subdir_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)subdir_name;

    Status = NtCreateFile(&subdir, FILE_ALL_ACCESS, &oa, &iosb, NULL, 0,
                          0, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateFile returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    us.Length = us.MaximumLength = sizeof(file_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)file_name;

    Status = NtCreateFile(&file, FILE_ALL_ACCESS, &oa, &iosb, NULL, 0,
                          0, FILE_CREATE, 0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateFile returned %08x\n", (int32_t)Status);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    oa.RootDirectory = subdir;

    Status = NtCreateFile(&subdir_file, FILE_ALL_ACCESS, &oa, &iosb, NULL, 0,
                          0, FILE_CREATE, 0, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateFile returned %08x\n", (int32_t)Status);
        NtClose(file);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    us.Length = us.MaximumLength = sizeof(subdir_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)subdir_name;

    Status = NtCreateFile(&subdir_subdir, FILE_ALL_ACCESS, &oa, &iosb, NULL, 0,
                          0, FILE_CREATE, FILE_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateFile returned %08x\n", (int32_t)Status);
        NtClose(subdir_file);
        NtClose(file);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    check_acl(h, "dir", ace_flags);
    check_acl(subdir, "subdir", expected_subdir_flags);
    check_acl(file, "file", expected_file_flags);
    check_acl(subdir_file, "subdir\\file", expected_subdir_file_flags);
    check_acl(subdir_subdir, "subdir\\subdir", expected_subdir_subdir_flags);

    dispos.DoDeleteFile = true;

    Status = NtSetInformationFile(subdir_subdir, &iosb, &dispos, sizeof(dispos), FileDispositionInformation);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationFile returned %08x\n", (int32_t)Status);
        NtClose(subdir_subdir);
        NtClose(subdir_file);
        NtClose(file);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    NtClose(subdir_subdir);

    Status = NtSetInformationFile(subdir_file, &iosb, &dispos, sizeof(dispos), FileDispositionInformation);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationFile returned %08x\n", (int32_t)Status);
        NtClose(subdir_file);
        NtClose(file);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    NtClose(subdir_file);

    Status = NtSetInformationFile(file, &iosb, &dispos, sizeof(dispos), FileDispositionInformation);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationFile returned %08x\n", (int32_t)Status);
        NtClose(file);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    NtClose(file);

    Status = NtSetInformationFile(subdir, &iosb, &dispos, sizeof(dispos), FileDispositionInformation);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationFile returned %08x\n", (int32_t)Status);
        NtClose(subdir);
        NtClose(h);
        return;
    }

    NtClose(subdir);

    Status = NtSetInformationFile(h, &iosb, &dispos, sizeof(dispos), FileDispositionInformation);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetInformationFile returned %08x\n", (int32_t)Status);
        NtClose(h);
        return;
    }

    NtClose(h);
}

static bool get_self_sid() {
    NTSTATUS Status;
    HANDLE token;
    char buf[100];
    ULONG retlen;
    TOKEN_USER* tu;

    Status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &token);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtOpenProcessToken returned %08x\n", (int32_t)Status);
        return false;
    }

    Status = NtQueryInformationToken(token, TokenUser, (TOKEN_USER*)buf, sizeof(buf), &retlen);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQueryInformationToken returned %08x\n", (int32_t)Status);
        NtClose(token);
        return false;
    }

    NtClose(token);

    tu = (TOKEN_USER*)buf;

    {
        char s[255];

        sid_to_string(tu->User.Sid, s);

        printf("Current SID is %s.\n", s);
    }

    self_sid_length = offsetof(SID, SubAuthority) + (((SID*)tu->User.Sid)->SubAuthorityCount * sizeof(DWORD));

    self_sid = malloc(self_sid_length);
    memcpy(self_sid, tu->User.Sid, self_sid_length);

    return true;
}

int main() {
    get_self_sid();

    // FIXME - get current directory?

    printf("No flags:\n");
    sd_test(0,
            0xff,
            0xff,
            0xff,
            0xff);

    printf("OI:\n");
    sd_test(OBJECT_INHERIT_ACE,
            INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
            0,
            0,
            INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE);

    printf("OI | NP:\n");
    sd_test(OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            0xff,
            0,
            0xff,
            0xff);

    printf("CI:\n");
    sd_test(CONTAINER_INHERIT_ACE,
            CONTAINER_INHERIT_ACE,
            0xff,
            0xff,
            CONTAINER_INHERIT_ACE);

    printf("CI | NP:\n");
    sd_test(CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            0,
            0xff,
            0xff,
            0xff);

    printf("CI | OI:\n");
    sd_test(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            0,
            0,
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);

    printf("CI | OI | NP:\n");
    sd_test(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE,
            0,
            0,
            0xff,
            0xff);

    return 0;
}
