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
#define STATUS_NOT_ALL_ASSIGNED             0x00000106
#define STATUS_SOME_NOT_MAPPED              0x00000107
#define STATUS_OBJECT_NAME_EXISTS           0x40000000
#define STATUS_BUFFER_OVERFLOW              0x80000005
#define STATUS_NO_MORE_FILES                0x80000006
#define STATUS_NO_MORE_ENTRIES              0x8000001a
#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_INFO_CLASS           0xc0000003
#define STATUS_INFO_LENGTH_MISMATCH         0xc0000004
#define STATUS_ACCESS_VIOLATION             0xc0000005
#define STATUS_INVALID_HANDLE               0xc0000008
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_NO_SUCH_FILE                 0xc000000f
#define STATUS_CONFLICTING_ADDRESSES        0xc0000018
#define STATUS_ACCESS_DENIED                0xc0000022
#define STATUS_BUFFER_TOO_SMALL             0xc0000023
#define STATUS_OBJECT_TYPE_MISMATCH         0xc0000024
#define STATUS_OBJECT_NAME_INVALID          0xc0000033
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_OBJECT_NAME_COLLISION        0xc0000035
#define STATUS_OBJECT_PATH_INVALID          0xc0000039
#define STATUS_OBJECT_PATH_NOT_FOUND        0xc000003a
#define STATUS_MUTANT_NOT_OWNED             0xc0000046
#define STATUS_SEMAPHORE_LIMIT_EXCEEDED     0xc0000047
#define STATUS_SECTION_NOT_IMAGE            0xc0000049
#define STATUS_DELETE_PENDING               0xc0000056
#define STATUS_UNKNOWN_REVISION             0xc0000058
#define STATUS_PRIVILEGE_NOT_HELD           0xc0000061
#define STATUS_INVALID_ACL                  0xc0000077
#define STATUS_INVALID_SID                  0xc0000078
#define STATUS_INVALID_SECURITY_DESCR       0xc0000079
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_MEDIA_WRITE_PROTECTED        0xc00000a2
#define STATUS_BAD_IMPERSONATION_LEVEL      0xc00000a5
#define STATUS_FILE_IS_A_DIRECTORY          0xc00000ba
#define STATUS_NOT_SAME_DEVICE              0xc00000d4
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_NOT_A_DIRECTORY              0xc0000103
#define STATUS_CANNOT_DELETE                0xc0000121
#define STATUS_REGISTRY_CORRUPT             0xc000014c
#define STATUS_CHILD_MUST_BE_VOLATILE       0xc0000181

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef int32_t NTSTATUS, *PNTSTATUS;
typedef char CHAR;
typedef uint16_t WCHAR, *PWSTR;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef uint32_t ULONG, *PULONG;
typedef int32_t LONG, *PLONG;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK, *PACCESS_MASK;
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
typedef DWORD EXECUTION_STATE;
typedef uint64_t ULONG64;

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
    };

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

#define DELETE                  0x00010000
#define READ_CONTROL            0x00020000
#define WRITE_DAC               0x00040000
#define WRITE_OWNER             0x00080000
#define SYNCHRONIZE             0x00100000
#define STANDARD_RIGHTS_REQUIRED    WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE
#define ACCESS_SYSTEM_SECURITY  0x01000000
#define MAXIMUM_ALLOWED         0x02000000
#define GENERIC_READ            0x80000000
#define GENERIC_WRITE           0x40000000
#define GENERIC_EXECUTE         0x20000000
#define GENERIC_ALL             0x10000000

#define STANDARD_RIGHTS_READ    READ_CONTROL
#define STANDARD_RIGHTS_WRITE   READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE READ_CONTROL

typedef NTSTATUS (*muwine_func0arg)(void);
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
typedef NTSTATUS (*muwine_func13arg)(uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                                     uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                                     uintptr_t arg7, uintptr_t arg8, uintptr_t arg9,
                                     uintptr_t arg10, uintptr_t arg11, uintptr_t arg12,
                                     uintptr_t arg13);

typedef struct _type_object type_object;
typedef struct _SECURITY_DESCRIPTOR_RELATIVE SECURITY_DESCRIPTOR_RELATIVE;

typedef struct _object_header {
    int refcount;
    int handle_count;
    type_object* type;
    UNICODE_STRING path;
    spinlock_t header_lock;
    bool permanent;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
} object_header;

typedef struct {
    object_header h;
    bool signalled;
    spinlock_t sync_lock;
    struct list_head waiters;
} sync_object;

typedef struct _token_object token_object;
typedef struct _process_object process_object;

typedef struct _device device;

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);
bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us);
bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us);
void free_object_attributes(OBJECT_ATTRIBUTES* oa);
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
typedef enum {
    TokenPrimary = 1,
    TokenImpersonation
} TOKEN_TYPE;

typedef enum {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    TokenProcessTrustLevel,
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS;

typedef struct _SID SID;
typedef struct _token_object token_object;
typedef struct _LUID LUID, *PLUID;
typedef struct _TOKEN_USER TOKEN_USER, *PTOKEN_USER;
typedef struct _TOKEN_GROUPS TOKEN_GROUPS, *PTOKEN_GROUPS;
typedef struct _TOKEN_PRIVILEGES TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;
typedef struct _TOKEN_OWNER TOKEN_OWNER, *PTOKEN_OWNER;
typedef struct _TOKEN_PRIMARY_GROUP TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;
typedef struct _TOKEN_DEFAULT_DACL TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;
typedef struct _TOKEN_SOURCE TOKEN_SOURCE, *PTOKEN_SOURCE;
typedef ULONG SECURITY_INFORMATION;

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

typedef void* PSECURITY_DESCRIPTOR;
typedef struct _GENERIC_MAPPING GENERIC_MAPPING, *PGENERIC_MAPPING;
typedef struct _PRIVILEGE_SET PRIVILEGE_SET, *PPRIVILEGE_SET;

NTSTATUS muwine_make_process_token(token_object** t);
void muwine_registry_root_sd(SECURITY_DESCRIPTOR_RELATIVE** out, unsigned int* sdlen);
NTSTATUS muwine_init_tokens(void);
NTSTATUS user_NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                            PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                            PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                            PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                            PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                            PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource);
NTSTATUS user_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                 PHANDLE TokenHandle);
NTSTATUS NtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                              ULONG HandleAttributes, PHANDLE TokenHandle);
NTSTATUS user_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                      PTOKEN_PRIVILEGES TokenPrivileges,
                                      ULONG PreviousPrivilegesLength,
                                      PTOKEN_PRIVILEGES PreviousPrivileges,
                                      PULONG RequiredLength);
NTSTATUS user_NtQueryInformationToken(HANDLE TokenHandle,
                                      TOKEN_INFORMATION_CLASS TokenInformationClass,
                                      PVOID TokenInformation, ULONG TokenInformationLength,
                                      PULONG ReturnLength);
NTSTATUS user_NtAllocateLocallyUniqueId(PLUID Luid);
NTSTATUS user_NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                    PULONG LengthNeeded);
NTSTATUS NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                           BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
NTSTATUS NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                             ULONG HandleAttributes, PHANDLE TokenHandle);
NTSTATUS muwine_create_sd(object_header* parent, SECURITY_DESCRIPTOR_RELATIVE* creator,
                          token_object* token, GENERIC_MAPPING* generic_mapping,
                          unsigned int flags, bool is_container,
                          SECURITY_DESCRIPTOR_RELATIVE** ret, size_t* retlen);
NTSTATUS muwine_create_sd2(SECURITY_DESCRIPTOR_RELATIVE* parent_sd,
                           SECURITY_DESCRIPTOR_RELATIVE* creator,
                           token_object* token, GENERIC_MAPPING* generic_mapping,
                           unsigned int flags, bool is_container,
                           SECURITY_DESCRIPTOR_RELATIVE** ret, size_t* retlen);
token_object* muwine_get_current_token(void);
token_object* duplicate_token(token_object* tok);
NTSTATUS copy_sd(SECURITY_DESCRIPTOR_RELATIVE* in, SECURITY_DESCRIPTOR_RELATIVE** out);
NTSTATUS check_sd(SECURITY_DESCRIPTOR_RELATIVE* sd, unsigned int len);
NTSTATUS user_NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken,
                            ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping,
                            PPRIVILEGE_SET RequiredPrivilegesBuffer, PULONG BufferLength,
                            PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus);
NTSTATUS NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                             PSECURITY_DESCRIPTOR SecurityDescriptor);
NTSTATUS NtPrivilegeCheck(HANDLE TokenHandle, PPRIVILEGE_SET RequiredPrivileges,
                          PBOOLEAN Result);
NTSTATUS NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
                          TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
NTSTATUS NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                               PVOID TokenInformation, ULONG TokenInformationLength);
NTSTATUS access_check_type(type_object* type, ACCESS_MASK desired, ACCESS_MASK* granted);
NTSTATUS access_check_object(object_header* obj, ACCESS_MASK desired, ACCESS_MASK* granted);
void dump_sd(SECURITY_DESCRIPTOR_RELATIVE* sd);

// file.c
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

typedef struct _FILE_BASIC_INFORMATION FILE_BASIC_INFORMATION;
typedef struct _FILE_NETWORK_OPEN_INFORMATION FILE_NETWORK_OPEN_INFORMATION;

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
NTSTATUS user_NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
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
void signal_object(sync_object* obj, bool single_thread, bool no_lock);

// unixfs.c
typedef struct _file_object file_object;

NTSTATUS muwine_init_unixroot(void);

// obj.c
extern type_object* dir_type;

typedef void (*muwine_close_object)(struct _object_header* obj);
typedef void (*muwine_cleanup_object)(struct _object_header* obj);

typedef struct _GENERIC_MAPPING {
    ACCESS_MASK GenericRead;
    ACCESS_MASK GenericWrite;
    ACCESS_MASK GenericExecute;
    ACCESS_MASK GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;

typedef struct _type_object {
    object_header header;
    UNICODE_STRING name;
    muwine_close_object close;
    muwine_cleanup_object cleanup;
    GENERIC_MAPPING generic_mapping;
    uint32_t valid;
} type_object;

typedef struct _DIRECTORY_BASIC_INFORMATION *PDIRECTORY_BASIC_INFORMATION;

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
NTSTATUS user_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                    PUNICODE_STRING DestinationName);
NTSTATUS user_NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                         PUNICODE_STRING DestinationName);
NTSTATUS muwine_add_entry_in_hierarchy(const UNICODE_STRING* us, object_header* obj, bool resolve_symlinks,
                                       bool permanent, object_header** old);
NTSTATUS muwine_add_entry_in_hierarchy2(object_header** obj, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS muwine_resolve_obj_symlinks(UNICODE_STRING* us, bool* done_alloc);
void object_cleanup(object_header* obj);
void object_close(object_header* obj);
object_header* muwine_alloc_object(size_t size, type_object* type, SECURITY_DESCRIPTOR_RELATIVE* sd);
size_t sd_length(SECURITY_DESCRIPTOR_RELATIVE* sd);
SECURITY_DESCRIPTOR_RELATIVE* create_dir_root_sd(void);
NTSTATUS muwine_open_object2(const POBJECT_ATTRIBUTES ObjectAttributes, object_header** obj,
                             UNICODE_STRING* ret_after, bool* ret_after_alloc, bool open_parent);
NTSTATUS NtMakeTemporaryObject(HANDLE Handle);
NTSTATUS NtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle,
                                PDIRECTORY_BASIC_INFORMATION Buffer, ULONG Length,
                                BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan,
                                PULONG Context, PULONG ReturnLength);
NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget,
                                   PULONG ReturnedLength);

static void __inline inc_obj_refcount(object_header* obj) {
    __sync_add_and_fetch(&obj->refcount, 1);
}

static void __inline dec_obj_refcount(object_header* obj) {
    if (__sync_sub_and_fetch(&obj->refcount, 1) == 0)
        object_close(obj);
}

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
NTSTATUS user_NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass,
                             PVOID InformationBuffer, SIZE_T InformationBufferSize,
                             PSIZE_T ResultLength);
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

typedef enum {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
} THREADINFOCLASS;

#define EXCEPTION_MAXIMUM_PARAMETERS 15

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD* ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _thread_object thread_object;
typedef void (*PNTAPCFUNC)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef void (*PRTL_THREAD_START_ROUTINE)(void*);

NTSTATUS muwine_init_threads(void);
NTSTATUS user_NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                             PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                             BOOLEAN CreateSuspended);
NTSTATUS user_NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                PVOID ThreadInformation, ULONG ThreadInformationLength);
int muwine_thread_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs);
NTSTATUS user_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                               PRTL_THREAD_START_ROUTINE StartRoutine, PVOID Argument,
                               ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize,
                               SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
ULONG NtGetCurrentProcessorNumber(void);
NTSTATUS NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                  PVOID ThreadInformation, ULONG ThreadInformationLength,
                                  PULONG ReturnLength);
NTSTATUS NtQueueApcThread(HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1,
                          ULONG_PTR arg2, ULONG_PTR arg3);
NTSTATUS NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext,
                          BOOLEAN HandleException);
NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NtSetThreadExecutionState(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags);
NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS NtYieldExecution(void);
NTSTATUS NtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NtAlertThread(HANDLE ThreadHandle);
NTSTATUS NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
thread_object* muwine_current_thread_object(void);

// proc.c
typedef enum {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
} PROCESS_INFORMATION_CLASS;

typedef struct _PS_CREATE_INFO *PPS_CREATE_INFO;
typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;

NTSTATUS muwine_init_processes(void);
NTSTATUS muwine_add_current_process(void);
process_object* muwine_current_process_object(void);
int muwine_group_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs);
int muwine_fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs);
NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask,
                       POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle,
                                   PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                   PVOID ProcessInformation, ULONG ProcessInformationLength,
                                   PULONG ReturnLength);
NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle,
                                 PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                 PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS NtSuspendProcess(HANDLE ProcessHandle);
NTSTATUS NtResumeProcess(HANDLE ProcessHandle);
NTSTATUS NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
                             ACCESS_MASK ProcessDesiredAccess,
                             ACCESS_MASK ThreadDesiredAccess,
                             POBJECT_ATTRIBUTES ProcessObjectAttributes,
                             POBJECT_ATTRIBUTES ThreadObjectAttributes,
                             ULONG ProcessFlags, ULONG ThreadFlags,
                             PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                             PPS_CREATE_INFO CreateInfo,
                             PPS_ATTRIBUTE_LIST AttributeList);

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
NTSTATUS user_NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass,
                       PVOID MutantInformation, ULONG MutantInformationLength,
                       PULONG ResultLength);
NTSTATUS user_NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount);
NTSTATUS muwine_init_mutants(void);
void release_abandoned_mutants(thread_object* t);

// semaphore.c
typedef enum {
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

NTSTATUS user_NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount,
                                LONG MaximumCount);
NTSTATUS user_NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS NtQuerySemaphore(HANDLE SemaphoreHandle,
                          SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
                          PVOID SemaphoreInformation, ULONG SemaphoreInformationLength,
                          PULONG ReturnLength);
NTSTATUS user_NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount);
NTSTATUS muwine_init_semaphores(void);
