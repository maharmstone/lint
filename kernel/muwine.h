#pragma once

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/kprobes.h>

#ifdef CONFIG_X86_64
#define _WIN64
#endif

#define MUW_FIRST_HANDLE 0x1000000

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_SUCCESS                      0x00000000
#define STATUS_WAIT_0                       0x00000000
#define STATUS_TIMEOUT                      0x00000102
#define STATUS_SOME_NOT_MAPPED              0x00000107
#define STATUS_OBJECT_NAME_EXISTS           0x40000000
#define STATUS_BUFFER_OVERFLOW              0x80000005
#define STATUS_NO_MORE_FILES                0x80000006
#define STATUS_NO_MORE_ENTRIES              0x8000001a
#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_INFO_CLASS           0xc0000003
#define STATUS_ACCESS_VIOLATION             0xc0000005
#define STATUS_INVALID_HANDLE               0xc0000008
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_NO_SUCH_FILE                 0xc000000f
#define STATUS_CONFLICTING_ADDRESSES        0xc0000018
#define STATUS_ACCESS_DENIED                0xc0000022
#define STATUS_BUFFER_TOO_SMALL             0xc0000023
#define STATUS_OBJECT_NAME_INVALID          0xc0000033
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_OBJECT_NAME_COLLISION        0xc0000035
#define STATUS_OBJECT_PATH_INVALID          0xc0000039
#define STATUS_OBJECT_PATH_NOT_FOUND        0xc000003a
#define STATUS_DELETE_PENDING               0xc0000056
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_MEDIA_WRITE_PROTECTED        0xc00000a2
#define STATUS_FILE_IS_A_DIRECTORY          0xc00000ba
#define STATUS_NOT_SAME_DEVICE              0xc00000d4
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_NOT_A_DIRECTORY              0xc0000103
#define STATUS_CANNOT_DELETE                0xc0000121
#define STATUS_REGISTRY_CORRUPT             0xc000014c
#define STATUS_CHILD_MUST_BE_VOLATILE       0xc0000181

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef int32_t NTSTATUS;
typedef uint16_t WCHAR, *PWSTR;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef uint32_t ULONG, *PULONG;
typedef int32_t LONG, *PLONG;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;
typedef void* PVOID;
typedef uint16_t USHORT;
typedef uint8_t UCHAR;
typedef uint8_t BOOLEAN, *PBOOLEAN;
typedef uintptr_t ULONG_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef char CCHAR;
typedef ULONG DEVICE_TYPE;
typedef uint64_t DWORD64;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uint16_t WORD;
typedef uint8_t BYTE;

#ifdef __amd64 // FIXME - also aarch64
#define KERNEL_HANDLE_MASK 0x8000000000000000
typedef int64_t intptr_t;
#else
#define KERNEL_HANDLE_MASK 0x80000000
typedef int32_t intptr_t;
#endif

typedef intptr_t LONG_PTR;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

typedef struct {
    union {
        struct {
            DWORD LowPart;
            LONG HighPart;
        };
        int64_t QuadPart;
    };
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#define OBJ_INHERIT             0x00000002
#define OBJ_PERMANENT           0x00000010
#define OBJ_EXCLUSIVE           0x00000020
#define OBJ_CASE_INSENSITIVE    0x00000040
#define OBJ_OPENIF              0x00000080
#define OBJ_OPENLINK            0x00000100
#define OBJ_KERNEL_HANDLE       0x00000200
#define OBJ_FORCE_ACCESS_CHECK  0x00000400

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
#define SYNCHRONIZE             0x00100000
#define STANDARD_RIGHTS_REQUIRED    WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE
#define MAXIMUM_ALLOWED         0x02000000
#define GENERIC_READ            0x80000000
#define GENERIC_WRITE           0x40000000
#define GENERIC_EXECUTE         0x20000000
#define GENERIC_ALL             0x10000000

#define STANDARD_RIGHTS_READ    READ_CONTROL
#define STANDARD_RIGHTS_WRITE   READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE READ_CONTROL

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

typedef struct _type_object type_object;

typedef struct _object_header {
    int refcount;
    int handle_count;
    type_object* type;
    UNICODE_STRING path;
    spinlock_t path_lock;
    bool permanent;
} object_header;

typedef struct {
    object_header h;
    bool signalled;
    spinlock_t sync_lock;
    struct list_head waiters;
} sync_object;

typedef struct _token_object token_object;

typedef struct {
    sync_object header;
    struct list_head list;
    struct list_head dead_list;
    pid_t pid;
    struct list_head handle_list;
    spinlock_t handle_list_lock;
    uintptr_t next_handle_no;
    token_object* token;
    struct rw_semaphore mapping_list_sem;
    struct list_head mapping_list;
} process_object;

typedef struct _device device;

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);
bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us);
bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us);
int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count);
int strnicmp(const char* string1, const char* string2, size_t count);
NTSTATUS utf8_to_utf16(WCHAR* dest, ULONG dest_max, ULONG* dest_len, const char* src, ULONG src_len);
NTSTATUS utf16_to_utf8(char* dest, ULONG dest_max, ULONG* dest_len, const WCHAR* src, ULONG src_len);
NTSTATUS get_func_ptr(const char* name, void** func);

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

typedef struct _token_object {
    object_header header;
    SID* owner;
    SID* group;
} token_object;

NTSTATUS muwine_create_inherited_sd(const SECURITY_DESCRIPTOR* parent_sd, unsigned int parent_sd_len, bool container,
                                    token_object* tok, SECURITY_DESCRIPTOR** out, unsigned int* outlen);
void muwine_make_process_token(token_object** t);
void muwine_registry_root_sd(SECURITY_DESCRIPTOR** out, unsigned int* sdlen);
ACCESS_MASK sanitize_access_mask(ACCESS_MASK access, type_object* type);
NTSTATUS muwine_init_tokens(void);

// file.c
#define FILE_SUPERSEDE                    0x00000000
#define FILE_OPEN                         0x00000001
#define FILE_CREATE                       0x00000002
#define FILE_OPEN_IF                      0x00000003
#define FILE_OVERWRITE                    0x00000004
#define FILE_OVERWRITE_IF                 0x00000005

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

// FIXME - these should all have SYNCHRONIZE as well
#define FILE_GENERIC_READ FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | \
                          READ_CONTROL
#define FILE_GENERIC_WRITE FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | \
                           FILE_WRITE_ATTRIBUTES | READ_CONTROL
#define FILE_GENERIC_EXECUTE FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL
#define FILE_ALL_ACCESS FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | \
                        FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | \
                        FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | \
                        FILE_WRITE_ATTRIBUTES | DELETE | READ_CONTROL | \
                        WRITE_DAC | WRITE_OWNER

#define FILE_DIRECTORY_FILE               0x00000001
#define FILE_WRITE_THROUGH                0x00000002
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT         0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_CREATE_TREE_CONNECTION       0x00000080
#define FILE_COMPLETE_IF_OPLOCKED         0x00000100
#define FILE_NO_EA_KNOWLEDGE              0x00000200
#define FILE_OPEN_REMOTE_INSTANCE         0x00000400
#define FILE_RANDOM_ACCESS                0x00000800
#define FILE_DELETE_ON_CLOSE              0x00001000
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000
#define FILE_NO_COMPRESSION               0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK        0x00010000
#define FILE_DISALLOW_EXCLUSIVE           0x00020000
#define FILE_RESERVE_OPFILTER             0x00100000
#define FILE_OPEN_REPARSE_POINT           0x00200000
#define FILE_OPEN_NO_RECALL               0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY    0x00800000

#define FILE_USE_FILE_POINTER_POSITION    0xfffffffe

#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_DEVICE               0x00000040
#define FILE_ATTRIBUTE_NORMAL               0x00000080
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800
#define FILE_ATTRIBUTE_OFFLINE              0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000

#define FILE_SUPERSEDED         0x00000000
#define FILE_OPENED             0x00000001
#define FILE_CREATED            0x00000002
#define FILE_OVERWRITTEN        0x00000003
#define FILE_EXISTS             0x00000004
#define FILE_DOES_NOT_EXIST     0x00000005

#define FILE_BYTE_ALIGNMENT             0x00000000

#define FILE_SHARE_READ         0x00000001
#define FILE_SHARE_WRITE        0x00000002
#define FILE_SHARE_DELETE       0x00000004

typedef enum {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileAttributeCacheInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS;

typedef struct {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION;

typedef struct {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION;

typedef struct {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION;

typedef struct {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION;

typedef struct {
    ULONG EaSize;
} FILE_EA_INFORMATION;

typedef struct {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

typedef struct {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION;

typedef struct {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION;

typedef struct {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION;

typedef struct {
    ULONG Mode;
} FILE_MODE_INFORMATION;

typedef struct {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION;

typedef struct {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION;

typedef struct {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION;

typedef struct {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef struct {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION;

typedef enum {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS;

typedef struct {
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION;

typedef struct {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION;

#define FILE_DEVICE_DISK_FILE_SYSTEM 0x00000008

#define FILE_DEVICE_IS_MOUNTED 0x00000020

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                      ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                      PVOID EaBuffer, ULONG EaLength);
NTSTATUS user_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                           PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                           ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                           PVOID EaBuffer, ULONG EaLength);
NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS user_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                         PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key);
NTSTATUS user_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                         PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                         PULONG Key);
NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS user_NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                     ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                     PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                     PULONG Key);
NTSTATUS user_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                          PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                          PULONG Key);
NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                              ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS user_NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                   ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                              FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                              PUNICODE_STRING FileMask, BOOLEAN RestartScan);
NTSTATUS user_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                   PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                   FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                   PUNICODE_STRING FileMask, BOOLEAN RestartScan);
NTSTATUS user_NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                           ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                               PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                               PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                               ULONG OutputBufferLength);
NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                         PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                         ULONG OutputBufferLength);
NTSTATUS NtSetVolumeInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                    FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                    PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                    BOOLEAN ExclusiveLock);
NTSTATUS NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                     ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList,
                                     ULONG SidListLength, SID* StartSid, BOOLEAN RestartScan);
NTSTATUS NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                   ULONG Length);
NTSTATUS NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                      PLARGE_INTEGER Length, ULONG Key);
NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);
NTSTATUS user_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                    FILE_BASIC_INFORMATION* FileInformation);
NTSTATUS NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                       ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength,
                       PULONG EaIndex, BOOLEAN RestartScan);
NTSTATUS user_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                        FILE_NETWORK_OPEN_INFORMATION* FileInformation);
NTSTATUS NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                     ULONG Length);

// handle.c
typedef struct {
    struct list_head list;
    object_header* object;
    uintptr_t number;
    ACCESS_MASK access;
} handle;

typedef enum {
    WaitAllObject,
    WaitAnyObject
} OBJECT_WAIT_TYPE;

NTSTATUS NtClose(HANDLE Handle);
NTSTATUS user_NtClose(HANDLE Handle);
NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h, bool kernel, ACCESS_MASK access);
object_header* get_object_from_handle(HANDLE h, ACCESS_MASK* access);
void muwine_free_kernel_handles(void);
NTSTATUS user_NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);
NTSTATUS NtWaitForMultipleObjects(ULONG ObjectCount, PHANDLE ObjectsArray,
                                  OBJECT_WAIT_TYPE WaitType, BOOLEAN Alertable,
                                  PLARGE_INTEGER TimeOut);
void signal_object(sync_object* obj, bool auto_reset);

// unixfs.c
typedef struct {
    object_header header;
    ULONG options;
    uint64_t offset;
    device* dev;
    loff_t query_dir_offset;
    UNICODE_STRING query_string;
    unsigned int mapping_count;
} file_object;

NTSTATUS muwine_init_unixroot(void);

// obj.c
typedef NTSTATUS (*muwine_create)(device* dev, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, const UNICODE_STRING* us,
                                  PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                  ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                  PVOID EaBuffer, ULONG EaLength, ULONG oa_attributes);
typedef NTSTATUS (*muwine_query_information)(file_object* obj, ACCESS_MASK access,
                                             PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                             FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*muwine_read)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                PULONG Key);
typedef NTSTATUS (*muwine_write)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                 PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                 PULONG Key);
typedef NTSTATUS (*muwine_set_information)(file_object* obj, ACCESS_MASK access, PIO_STATUS_BLOCK IoStatusBlock,
                                           PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*muwine_query_directory)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                           PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                           FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                           PUNICODE_STRING FileMask, BOOLEAN RestartScan);
typedef NTSTATUS (*muwine_query_volume_information)(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                                      ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
typedef struct file* (*muwine_get_filp)(file_object* obj);

extern type_object* dir_type;

typedef struct _device {
    object_header header;
    muwine_create create;
    muwine_read read;
    muwine_write write;
    muwine_query_information query_information;
    muwine_set_information set_information;
    muwine_query_directory query_directory;
    muwine_query_volume_information query_volume_information;
    muwine_get_filp get_filp;
} device;

typedef void (*muwine_close_object)(struct _object_header* obj);
typedef void (*muwine_cleanup_object)(struct _object_header* obj);

typedef struct _type_object {
    object_header header;
    UNICODE_STRING name;
    muwine_close_object close;
    muwine_cleanup_object cleanup;
    uint32_t generic_read;
    uint32_t generic_write;
    uint32_t generic_execute;
    uint32_t generic_all;
    uint32_t valid;
} type_object;

static void __inline inc_obj_refcount(object_header* obj) {
    __sync_add_and_fetch(&obj->refcount, 1);
}

static void __inline dec_obj_refcount(object_header* obj) {
    if (__sync_sub_and_fetch(&obj->refcount, 1) == 0)
        obj->type->close(obj);
}

void free_object(object_header* obj);
type_object* muwine_add_object_type(const UNICODE_STRING* name, muwine_close_object close,
                                    muwine_cleanup_object cleanup, uint32_t generic_read,
                                    uint32_t generic_write, uint32_t generic_execute,
                                    uint32_t generic_all, uint32_t valid);
void muwine_free_objs(void);
NTSTATUS muwine_open_object(const UNICODE_STRING* us, object_header** obj, UNICODE_STRING* after,
                            bool* after_alloc, bool open_parent);
NTSTATUS muwine_init_objdir(void);
NTSTATUS NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS user_NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                    PUNICODE_STRING DestinationName);
NTSTATUS user_NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                         PUNICODE_STRING DestinationName);
NTSTATUS muwine_add_entry_in_hierarchy(const UNICODE_STRING* us, object_header* obj, bool resolve_symlinks,
                                       bool permanent);
NTSTATUS muwine_resolve_obj_symlinks(UNICODE_STRING* us, bool* done_alloc);
void object_cleanup(object_header* obj);

// sect.c
typedef enum {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef enum {
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation,
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct {
    struct list_head list;
    uintptr_t address;
    uintptr_t length;
    object_header* sect;
    unsigned long file_offset;
    bool committed;
} section_map;

NTSTATUS user_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                              HANDLE FileHandle);
NTSTATUS user_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                 ULONG AllocationType, ULONG Win32Protect);
NTSTATUS user_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS NtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize);
NTSTATUS user_NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer,
                        ULONG InformationBufferSize, PULONG ResultLength);
NTSTATUS user_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                     ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS user_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                             ULONG FreeType);
NTSTATUS user_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                                  ULONG FreeType);
NTSTATUS muwine_init_sections(void);

// thread.c
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct {
    PVOID PreviousStackBase;
    PVOID PreviousStackLimit;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID AllocatedStackBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct __attribute__((aligned(16))) {
    ULONGLONG Low;
    LONGLONG High;
} M128A;

typedef struct {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
} XMM_SAVE_AREA32;

// FIXME - architecture-dependent
typedef struct __attribute__((aligned(16))) {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union {
        XMM_SAVE_AREA32 FltSave;
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

NTSTATUS muwine_init_threads(void);
NTSTATUS user_NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                             PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                             BOOLEAN CreateSuspended);
NTSTATUS user_NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
int muwine_thread_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs);

// proc.c
typedef struct _thread_object thread_object;

NTSTATUS muwine_init_processes(void);
void muwine_add_current_process(void);
process_object* muwine_current_process_object(void);
int muwine_group_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs);
int muwine_fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs);
thread_object* muwine_current_thread_object(void) ;

// timer.c
typedef void (*PTIMER_APC_ROUTINE)(PVOID TimerContext, ULONG TimerLowValue,
                                   LONG TimerHighValue);
typedef enum {
    TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef enum {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

NTSTATUS muwine_init_timers(void);
NTSTATUS user_NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);
NTSTATUS user_NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass,
                      PVOID TimerInformation, ULONG TimerInformationLength,
                      PULONG ReturnLength);
NTSTATUS user_NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime,
                         PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                         BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState);
NTSTATUS user_NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState);
void muwine_free_proc(void);

// event.c
typedef enum {
    EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

NTSTATUS user_NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                            BOOLEAN InitialState);
NTSTATUS user_NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS user_NtSetEvent(HANDLE EventHandle, PLONG PreviousState);
NTSTATUS user_NtResetEvent(HANDLE EventHandle, PLONG PreviousState);
NTSTATUS user_NtClearEvent(HANDLE EventHandle);
NTSTATUS user_NtPulseEvent(HANDLE EventHandle, PLONG PreviousState);
NTSTATUS NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass,
                      PVOID EventInformation, ULONG EventInformationLength,
                      PULONG ReturnLength);
NTSTATUS muwine_init_events(void);

// mutant.c
typedef enum {
    MutantBasicInformation
} MUTANT_INFORMATION_CLASS;

NTSTATUS user_NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);
NTSTATUS NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass,
                       PVOID MutantInformation, ULONG MutantInformationLength,
                       PULONG ResultLength);
NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount);
NTSTATUS muwine_init_mutants(void);
