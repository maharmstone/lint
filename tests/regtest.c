#include <stdio.h>
#include <uchar.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <muw.h>
#endif

#ifdef _WIN32
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
NTSTATUS __stdcall NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                               ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS __stdcall NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                              ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtDeleteKey(HANDLE KeyHandle);
NTSTATUS __stdcall NtFlushKey(HANDLE KeyHandle);

#endif

static const char16_t regpath[] = u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\btrfs";
static const char16_t regpath2[] = u"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\btrfs\\volatile";

static const char16_t regpath3[] = u"\\Registry\\Machine\\System\\CurrentControlSet\\test\\0000";

static const char16_t key_name[] = u"Start";
static const char16_t key_name2[] = u"NewName";
static const char16_t key_value[] = u"hello, world";

int main() {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    ULONG index, len, dispos;
    char buf[255];
    DWORD val, type;

#if 0
    us.Length = us.MaximumLength = sizeof(regpath3) - sizeof(char16_t);
    us.Buffer = malloc(us.Length);

    memcpy(us.Buffer, regpath3, us.Length);

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    for (unsigned int i = 0; i < 1000; i++) {
        us.Buffer[(us.Length / sizeof(char16_t)) - 3] = '0' + (i / 100);
        us.Buffer[(us.Length / sizeof(char16_t)) - 2] = '0' + ((i / 10) % 10);
        us.Buffer[(us.Length / sizeof(char16_t)) - 1] = '0' + (i % 10);

        Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
        if (!NT_SUCCESS(Status)) {
            printf("NtCreateKey returned %08x\n", (int32_t)Status);
            return 0;
        }

        Status = NtDeleteKey(h);
        if (!NT_SUCCESS(Status)) {
            printf("NtDeleteKey returned %08x\n", (int32_t)Status);
            NtClose(h);
            return 0;
        }

        NtClose(h);
    }
#endif

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

    Status = NtQueryKey(h, KeyBasicInformation, buf, sizeof(buf), &len);

    if (!NT_SUCCESS(Status))
        printf("NtQueryKey returned %08x\n", (int32_t)Status);

    if (NT_SUCCESS(Status)) {
        char name[255], *s;

        KEY_BASIC_INFORMATION* kbi = (KEY_BASIC_INFORMATION*)buf;

        s = name;
        for (unsigned int i = 0; i < kbi->NameLength / sizeof(WCHAR); i++) {
            *s = (char)kbi->Name[i];
            s++;
        }
        *s = 0;

        printf("NtQueryKey kbi: LastWriteTime = %" PRIx64 ", TitleIndex = %x, NameLength = %x, Name = %s\n",
               (int64_t)kbi->LastWriteTime.QuadPart, (uint32_t)kbi->TitleIndex, (uint32_t)kbi->NameLength, name);
    }

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

    us.Length = us.MaximumLength = sizeof(regpath2) - sizeof(char16_t);
    us.Buffer = (char16_t*)regpath2;

    oa.ObjectName = &us;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
    printf("NtCreateKey returned %08x (dispos = %x)\n", (int32_t)Status, (int32_t)dispos);

    Status = NtFlushKey(h);
    if (!NT_SUCCESS(Status))
        printf("NtFlushKey returned %08x\n", (int32_t)Status);

    us.Length = us.MaximumLength = sizeof(key_name2) - sizeof(char16_t);
    us.Buffer = (WCHAR*)key_name2;

    val = 229;

    Status = NtSetValueKey(h, &us, 0, REG_DWORD, &val, sizeof(val));
    if (!NT_SUCCESS(Status))
        printf("NtSetValueKey returned %08x\n", (int32_t)Status);

    Status = NtDeleteKey(h);
    if (!NT_SUCCESS(Status))
        printf("NtDeleteKey returned %08x\n", (int32_t)Status);

    Status = NtClose(h);
    if (!NT_SUCCESS(Status))
        printf("NtClose returned %08x\n", (int32_t)Status);

    return 0;
}
