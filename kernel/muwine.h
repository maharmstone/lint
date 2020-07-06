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
#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_OBJECT_PATH_INVALID          0xc0000039
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_REGISTRY_CORRUPT             0xc000014c

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef uintptr_t NTSTATUS;
typedef uint16_t WCHAR, *PWSTR;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef uint32_t ULONG;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;
typedef void* PVOID;
typedef uint16_t USHORT;

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

typedef NTSTATUS (*muwine_func1arg)(uintptr_t arg1);
typedef NTSTATUS (*muwine_func2arg)(uintptr_t arg1, uintptr_t arg2);
typedef NTSTATUS (*muwine_func3arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);
bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us);
bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us);
int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count);
NTSTATUS muwine_add_handle(void* object, PHANDLE h);

// reg.c
NTSTATUS muwine_init_registry(const char* system_hive);
void muwine_free_reg(void);
NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtClose(HANDLE Handle);
