#pragma once

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#ifdef CONFIG_X86_64
#define _WIN64
#endif

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_SUCCESS                      0x00000000
#define STATUS_NO_MORE_ENTRIES              0x8000001a
#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_HANDLE               0xc0000008
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_BUFFER_TOO_SMALL             0xc0000023
#define STATUS_OBJECT_NAME_INVALID          0xc0000033
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_OBJECT_PATH_INVALID          0xc0000039
#define STATUS_OBJECT_PATH_NOT_FOUND        0xc000003a
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_REGISTRY_CORRUPT             0xc000014c

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef int32_t NTSTATUS;
typedef uint16_t WCHAR, *PWSTR;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef uint32_t ULONG, *PULONG;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;
typedef void* PVOID;
typedef uint16_t USHORT;
typedef uint8_t UCHAR;

typedef struct {
    int64_t QuadPart;
} LARGE_INTEGER;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
#ifdef _WIN64
    ULONG pad1;
#endif
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
#ifdef _WIN64
    ULONG pad2;
#endif
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

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

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;

#define REG_CREATED_NEW_KEY         0x00000001
#define REG_OPENED_EXISTING_KEY     0x00000002

#define REG_OPTION_NON_VOLATILE     0x00000000
#define REG_OPTION_VOLATILE         0x00000001
#define REG_OPTION_CREATE_LINK      0x00000002
#define REG_OPTION_BACKUP_RESTORE   0x00000004
#define REG_OPTION_OPEN_LINK        0x00000008

typedef NTSTATUS (*muwine_func1arg)(uintptr_t arg1);
typedef NTSTATUS (*muwine_func2arg)(uintptr_t arg1, uintptr_t arg2);
typedef NTSTATUS (*muwine_func3arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
typedef NTSTATUS (*muwine_func4arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4);
typedef NTSTATUS (*muwine_func5arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4, uintptr_t arg5);
typedef NTSTATUS (*muwine_func6arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);
typedef NTSTATUS (*muwine_func7arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                    uintptr_t arg7);

struct _object_header;

typedef void (*muwine_close_object)(struct _object_header* obj);

typedef enum {
    muwine_object_key
} object_type;

typedef struct _object_header {
    int refcount;
    struct list_head list;
    object_type type;
    muwine_close_object close;
} object_header;

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);
bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us);
bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us);
int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count);
NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h);
object_header* get_object_from_handle(HANDLE h);

// reg.c
NTSTATUS muwine_init_reg_root(void);
void muwine_free_reg(void);
NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtClose(HANDLE Handle);
NTSTATUS user_NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                             PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS user_NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                  PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS user_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                              PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS user_NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                            ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS user_NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
NTSTATUS user_NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                          PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
NTSTATUS NtDeleteKey(HANDLE KeyHandle);
NTSTATUS user_NtLoadKey(POBJECT_ATTRIBUTES DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName);
NTSTATUS NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName);
NTSTATUS NtFlushKey(HANDLE KeyHandle);
