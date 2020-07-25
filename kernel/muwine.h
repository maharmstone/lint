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

#define MUW_FIRST_HANDLE 0x1000000

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_SUCCESS                      0x00000000
#define STATUS_BUFFER_OVERFLOW              0x80000005
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
#define STATUS_CANNOT_DELETE                0xc0000121
#define STATUS_REGISTRY_CORRUPT             0xc000014c
#define STATUS_CHILD_MUST_BE_VOLATILE       0xc0000181

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
typedef uint8_t BOOLEAN;

typedef struct {
    int64_t QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

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

typedef struct {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    uintptr_t Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef void* PIO_APC_ROUTINE;

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

#define DELETE                  0x00010000
#define READ_CONTROL            0x00020000
#define WRITE_DAC               0x00040000
#define WRITE_OWNER             0x00080000

#define KEY_QUERY_VALUE         0x00000001
#define KEY_SET_VALUE           0x00000002
#define KEY_CREATE_SUB_KEY      0x00000004
#define KEY_ENUMERATE_SUB_KEYS  0x00000008
#define KEY_NOTIFY              0x00000010
#define KEY_CREATE_LINK         0x00000020

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
typedef NTSTATUS (*muwine_func8arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                    uintptr_t arg7, uintptr_t arg8);
typedef NTSTATUS (*muwine_func9arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                    uintptr_t arg7, uintptr_t arg8, uintptr_t arg9);
typedef NTSTATUS (*muwine_func10arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                     uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                     uintptr_t arg7, uintptr_t arg8, uintptr_t arg9,
                                     uintptr_t arg10);
typedef NTSTATUS (*muwine_func11arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                     uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                     uintptr_t arg7, uintptr_t arg8, uintptr_t arg9,
                                     uintptr_t arg10, uintptr_t arg11);
typedef NTSTATUS (*muwine_func12arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                     uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                     uintptr_t arg7, uintptr_t arg8, uintptr_t arg9,
                                     uintptr_t arg10, uintptr_t arg11, uintptr_t arg12);

struct _object_header;

typedef void (*muwine_close_object)(struct _object_header* obj);

typedef enum {
    muwine_object_key
} object_type;

typedef struct _object_header {
    int refcount;
    struct list_head list;
    object_type type;
    UNICODE_STRING path;
    muwine_close_object close;
} object_header;

typedef struct _token token;

typedef struct {
    struct list_head list;
    pid_t pid;
    int refcount;
    struct list_head handle_list;
    spinlock_t handle_list_lock;
    uintptr_t next_handle_no;
    token* token;
} process;

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);
bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us);
bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us);
int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count);
process* muwine_current_process(void);

// reg.c
NTSTATUS muwine_init_registry(void);
void muwine_free_reg(void);
NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
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
NTSTATUS user_NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName);
NTSTATUS NtFlushKey(HANDLE KeyHandle);
NTSTATUS user_NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                          ULONG OpenOptions);
NTSTATUS user_NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                         ULONG Length, PULONG ResultLength);
NTSTATUS NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle);
NTSTATUS NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                           PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchSubtree,
                           PVOID ChangeBuffer, ULONG Length, BOOLEAN Asynchronous);
NTSTATUS NtNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects,
                                    HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                    PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter,
                                    BOOLEAN WatchSubtree, PVOID ChangeBuffer, ULONG Length,
                                    BOOLEAN Asynchronous);

// sec.c
typedef struct _SECURITY_DESCRIPTOR SECURITY_DESCRIPTOR;
typedef struct _SID SID;

typedef struct _token {
    SID* owner;
    SID* group;
} token;

NTSTATUS muwine_create_inherited_sd(const SECURITY_DESCRIPTOR* parent_sd, unsigned int parent_sd_len, bool container,
                                    token* tok, SECURITY_DESCRIPTOR** out, unsigned int* outlen);
void muwine_make_process_token(token** t);
void muwine_free_token(token* token);
void muwine_duplicate_token(token* old, token** new);
void muwine_registry_root_sd(SECURITY_DESCRIPTOR** out, unsigned int* sdlen);

// file.c
#define FILE_SUPERSEDE                    0x00000000
#define FILE_OPEN                         0x00000001
#define FILE_CREATE                       0x00000002
#define FILE_OPEN_IF                      0x00000003
#define FILE_OVERWRITE                    0x00000004
#define FILE_OVERWRITE_IF                 0x00000005

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                      ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                      PVOID EaBuffer, ULONG EaLength);
NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key);

// handle.c
typedef struct {
    struct list_head list;
    object_header* object;
    uintptr_t number;
} handle;

NTSTATUS NtClose(HANDLE Handle);
NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h);
object_header* get_object_from_handle(HANDLE h);
