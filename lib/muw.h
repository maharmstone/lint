#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MUW_FIRST_HANDLE 0x1000000

#ifndef MUW_FUNCS_ONLY

#include <wchar.h>
#include <assert.h>

#ifndef MUW_NO_WCHAR_ASSERT
static_assert(sizeof(wchar_t) == 2, "wchar_t is not 2 bytes. Make sure you pass -fshort-wchar to gcc.");
#endif

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
typedef uint8_t BOOLEAN;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct {
    ULONG Length;
    ULONG pad1;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    ULONG pad2;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _LARGE_INTEGER {
    int64_t QuadPart;
} LARGE_INTEGER;

#define KEY_QUERY_VALUE        0x0001
#define KEY_SET_VALUE          0x0002
#define KEY_CREATE_SUB_KEY     0x0004
#define KEY_ENUMERATE_SUB_KEYS 0x0008
#define KEY_NOTIFY             0x0010
#define KEY_CREATE_LINK        0x0020

#define DELETE                 0x00010000
#define READ_CONTROL           0x00020000
#define WRITE_DAC              0x00040000
#define WRITE_OWNER            0x00080000
#define SYNCHRONIZE            0x00100000

#define REG_OPTION_NON_VOLATILE     0x00000000
#define REG_OPTION_VOLATILE         0x00000001
#define REG_OPTION_CREATE_LINK      0x00000002
#define REG_OPTION_BACKUP_RESTORE   0x00000004
#define REG_OPTION_OPEN_LINK        0x00000008

#define REG_NONE                        0
#define REG_SZ                          1
#define REG_EXPAND_SZ                   2
#define REG_BINARY                      3
#define REG_DWORD                       4
#define REG_DWORD_LITTLE_ENDIAN         4
#define REG_DWORD_BIG_ENDIAN            5
#define REG_LINK                        6
#define REG_MULTI_SZ                    7
#define REG_RESOURCE_LIST               8
#define REG_FULL_RESOURCE_DESCRIPTOR    9
#define REG_RESOURCE_REQUIREMENTS_LIST 10
#define REG_QWORD                      11
#define REG_QWORD_LITTLE_ENDIAN        11

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef enum {
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

typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION;

typedef enum {
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

typedef struct {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    uintptr_t Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef void* PIO_APC_ROUTINE;

#endif

#define __stdcall __attribute__((ms_abi)) __attribute__((__force_align_arg_pointer__))

void close_muwine();

NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS __stdcall NtClose(HANDLE Handle);
NTSTATUS __stdcall NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                                  PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                       PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                   void* KeyValueInformation, DWORD Length, DWORD* ResultLength);
NTSTATUS __stdcall NtSetValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName, ULONG TitleIndex,
                                 ULONG Type, const void* Data, ULONG DataSize);
NTSTATUS __stdcall NtDeleteValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName);
NTSTATUS __stdcall NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes, ULONG TitleIndex,
                               const UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS __stdcall NtDeleteKey(HANDLE KeyHandle);
NTSTATUS __stdcall NtLoadKey(const OBJECT_ATTRIBUTES* DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName);
NTSTATUS __stdcall NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName);
NTSTATUS __stdcall NtFlushKey(HANDLE KeyHandle);
NTSTATUS __stdcall NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG OpenOptions);
NTSTATUS __stdcall NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                              ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle);
NTSTATUS __stdcall NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchSubtree,
                                     PVOID ChangeBuffer, ULONG Length, BOOLEAN Asynchronous);
NTSTATUS __stdcall NtNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects,
                                              HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                              PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter,
                                              BOOLEAN WatchSubtree, PVOID ChangeBuffer, ULONG Length,
                                              BOOLEAN Asynchronous);

#ifdef __cplusplus
}
#endif
