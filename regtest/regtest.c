#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <uchar.h>
#include <wchar.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include "../kernel/ioctls.h"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <sys/ioctl.h>
#endif

#ifndef _WIN32
typedef int32_t NTSTATUS;
typedef void* HANDLE, *PHANDLE;
typedef uint32_t ULONG, *PULONG;
typedef void* PVOID;
typedef uint16_t USHORT;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;
typedef wchar_t WCHAR;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef uint8_t UCHAR;

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

typedef struct _LARGE_INTEGER {
    int64_t QuadPart;
} LARGE_INTEGER;

#define KEY_QUERY_VALUE        (0x0001)
#define KEY_SET_VALUE          (0x0002)
#define KEY_ENUMERATE_SUB_KEYS (0x0008)

#define REG_SZ                 1
#define REG_DWORD              4

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#endif

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION;

#ifdef _WIN32
NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS __stdcall NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                                  PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                       PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                   PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                                 ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS __stdcall NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
#endif

#ifndef _WIN32

#define STATUS_NOT_IMPLEMENTED              (NTSTATUS)0xc0000002

int muwine_fd = 0;

#define init_muwine() if (muwine_fd == 0) { \
    int fd = open("/dev/muwine", O_RDWR); \
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

NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                        PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    uintptr_t args[] = {
        6,
        (uintptr_t)KeyHandle,
        (uintptr_t)Index,
        (uintptr_t)KeyInformationClass,
        (uintptr_t)KeyInformation,
        (uintptr_t)Length,
        (uintptr_t)ResultLength
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTENUMERATEKEY, args);
}

NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                             PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    uintptr_t args[] = {
        6,
        (uintptr_t)KeyHandle,
        (uintptr_t)Index,
        (uintptr_t)KeyValueInformationClass,
        (uintptr_t)KeyValueInformation,
        (uintptr_t)Length,
        (uintptr_t)ResultLength
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTENUMERATEVALUEKEY, args);
}

NTSTATUS NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                         PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    uintptr_t args[] = {
        6,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName,
        (uintptr_t)KeyValueInformationClass,
        (uintptr_t)KeyValueInformation,
        (uintptr_t)Length,
        (uintptr_t)ResultLength
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYVALUEKEY, args);
}

NTSTATUS NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                       ULONG Type, PVOID Data, ULONG DataSize) {
    uintptr_t args[] = {
        6,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName,
        (uintptr_t)TitleIndex,
        (uintptr_t)Type,
        (uintptr_t)Data,
        (uintptr_t)DataSize
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETVALUEKEY, args);
}

NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDELETEVALUEKEY, args);
}

#endif

#ifdef _WIN32
static const char16_t regpath[] = u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\btrfs";
#else
static const char16_t regpath[] = u"\\Registry\\Machine\\ControlSet001\\Services\\btrfs"; // FIXME
#endif

static const char16_t key_name[] = u"Start";
static const char16_t key_name2[] = u"NewName";
static const char16_t key_value[] = u"hello, world";

int main() {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    ULONG index, len;
    char buf[255];
    DWORD val, type;

    us.Length = us.MaximumLength = sizeof(regpath) - sizeof(char16_t);
    us.Buffer = (char16_t*)regpath;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtOpenKey(&h, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE, &oa);

    if (!NT_SUCCESS(Status)) {
        printf("NtOpenKey returned %08x\n", (int32_t)Status);
        return 1;
    }

    index = 0;

    do {
        Status = NtEnumerateKey(h, index, KeyBasicInformation, buf, sizeof(buf), &len);

        if (!NT_SUCCESS(Status))
            printf("NtEnumerateKey returned %08x\n", (int32_t)Status);

        if (NT_SUCCESS(Status)) {
            char name[255], *s;

            KEY_BASIC_INFORMATION* kbi = (KEY_BASIC_INFORMATION*)buf;

            s = name;
            for (unsigned int i = 0; i < kbi->NameLength / sizeof(WCHAR); i++) {
                *s = (char)kbi->Name[i];
                s++;
            }
            *s = 0;

            printf("kbi: LastWriteTime = %" PRIx64 ", TitleIndex = %x, NameLength = %x, Name = %s\n",
                (int64_t)kbi->LastWriteTime.QuadPart, (uint32_t)kbi->TitleIndex, (uint32_t)kbi->NameLength, name);
        }

        index++;
    } while (NT_SUCCESS(Status));

    index = 0;

    do {
        Status = NtEnumerateValueKey(h, index, KeyValueFullInformation, buf, sizeof(buf), &len);

        if (!NT_SUCCESS(Status))
            printf("NtEnumerateValueKey returned %08x\n", (int32_t)Status);

        if (NT_SUCCESS(Status)) {
            char name[255], *s;
            KEY_VALUE_FULL_INFORMATION* kvfi = (KEY_VALUE_FULL_INFORMATION*)buf;

            s = name;
            for (unsigned int i = 0; i < kvfi->NameLength / sizeof(WCHAR); i++) {
                *s = (char)kvfi->Name[i];
                s++;
            }
            *s = 0;

            printf("kvfi: TitleIndex = %x, Type = %x, NameLength = %x, Name = %s, DataLength = %x, Data:",
                   (uint32_t)kvfi->TitleIndex, (uint32_t)kvfi->Type, (uint32_t)kvfi->NameLength,
                   name, (uint32_t)kvfi->DataLength);

            uint8_t* data = (uint8_t*)kvfi + kvfi->DataOffset;
            for (unsigned int i = 0; i < kvfi->DataLength; i++) {
                printf(" %02x", data[i]);
            }
            printf("\n");
        }

        index++;
    } while (NT_SUCCESS(Status));

    us.Length = us.MaximumLength = sizeof(key_name) - sizeof(char16_t);
    us.Buffer = (WCHAR*)key_name;

    Status = NtQueryValueKey(h, &us, KeyValueFullInformation, buf, sizeof(buf), &len);

    if (!NT_SUCCESS(Status))
        printf("NtQueryValueKey returned %08x\n", (int32_t)Status);
    else {
        char name[255], *s;
        KEY_VALUE_FULL_INFORMATION* kvfi = (KEY_VALUE_FULL_INFORMATION*)buf;

        s = name;
        for (unsigned int i = 0; i < kvfi->NameLength / sizeof(WCHAR); i++) {
            *s = (char)kvfi->Name[i];
            s++;
        }
        *s = 0;

        printf("kvfi: TitleIndex = %x, Type = %x, NameLength = %x, Name = %s, DataLength = %x, Data:",
               (uint32_t)kvfi->TitleIndex, (uint32_t)kvfi->Type, (uint32_t)kvfi->NameLength,
               name, (uint32_t)kvfi->DataLength);

        uint8_t* data = (uint8_t*)kvfi + kvfi->DataOffset;
        for (unsigned int i = 0; i < kvfi->DataLength; i++) {
            printf(" %02x", data[i]);
        }
        printf("\n");

        type = kvfi->Type;
    }

    us.Length = us.MaximumLength = sizeof(key_name2) - sizeof(char16_t);
    us.Buffer = (WCHAR*)key_name2;

    if (type == REG_DWORD) {
        Status = NtSetValueKey(h, &us, 0, REG_SZ, (PVOID)key_value, sizeof(key_value));
        if (!NT_SUCCESS(Status))
            printf("NtSetValueKey returned %08x\n", (int32_t)Status);
    } else {
        val = (uint32_t)time(NULL);

        Status = NtSetValueKey(h, &us, 0, REG_DWORD, &val, sizeof(val));
        if (!NT_SUCCESS(Status))
            printf("NtSetValueKey returned %08x\n", (int32_t)Status);
    }

    us.Length = us.MaximumLength = sizeof(key_name) - sizeof(char16_t);
    us.Buffer = (WCHAR*)key_name;

    Status = NtDeleteValueKey(h, &us);
    if (!NT_SUCCESS(Status))
        printf("NtDeleteValueKey returned %08x\n", (int32_t)Status);

    Status = NtClose(h);
    if (!NT_SUCCESS(Status))
        printf("NtClose returned %08x\n", (int32_t)Status);

    return 0;
}
