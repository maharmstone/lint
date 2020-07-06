#include <stdio.h>
#include <stdint.h>
#include <uchar.h>
#include <wchar.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../kernel/ioctls.h"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <sys/ioctl.h>
#endif

#ifdef _WIN32
NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
#else
typedef int32_t NTSTATUS;
typedef void* HANDLE, *PHANDLE;
typedef uint32_t ULONG, *PULONG;
typedef void* PVOID;
typedef uint16_t USHORT;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;

typedef wchar_t WCHAR;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    ULONG pad1;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    ULONG pad2;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define KEY_ENUMERATE_SUB_KEYS (0x0008)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#endif

#ifndef _WIN32

#define STATUS_NOT_IMPLEMENTED              (NTSTATUS)0xc0000002

int muwine_fd = 0;

#define init_muwine() if (muwine_fd == 0) { \
    int fd = open("/dev/muwine", 0); \
    if (fd < 0) return STATUS_NOT_IMPLEMENTED; \
    muwine_fd = fd; \
}

NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    uintptr_t args[] = {
        3,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENKEY, args);
}

NTSTATUS NtClose(HANDLE Handle) {
    uintptr_t args[] = {
        1,
        (uintptr_t)Handle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCLOSE, args);
}

#endif

static const char16_t regpath[] = u"\\Registry\\Machine";

int main() {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;

    us.Length = us.MaximumLength = sizeof(regpath) - sizeof(char16_t);
    us.Buffer = (char16_t*)regpath;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtOpenKey(&h, KEY_ENUMERATE_SUB_KEYS, &oa);
    printf("NtOpenKey returned %08x\n", (int32_t)Status);

    if (!NT_SUCCESS(Status))
        return 1;

    Status = NtClose(h);
    printf("NtClose returned %08x\n", (int32_t)Status);

    return 0;
}
