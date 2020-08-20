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
typedef int32_t LONG;
typedef void* PVOID;
typedef uint16_t USHORT;
typedef ULONG DWORD;
typedef DWORD ACCESS_MASK;
typedef wchar_t WCHAR;
typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef uint8_t UCHAR;
typedef uint8_t BOOLEAN;
typedef uintptr_t ULONG_PTR;
typedef ULONG_PTR SIZE_T, *PSIZE_T;
typedef intptr_t LONG_PTR;
typedef char CCHAR;
typedef uint64_t DWORD64;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uint16_t WORD;
typedef uint8_t BYTE;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

#define OBJ_INHERIT             0x00000002
#define OBJ_PERMANENT           0x00000010
#define OBJ_EXCLUSIVE           0x00000020
#define OBJ_CASE_INSENSITIVE    0x00000040
#define OBJ_OPENIF              0x00000080
#define OBJ_OPENLINK            0x00000100
#define OBJ_KERNEL_HANDLE       0x00000200
#define OBJ_FORCE_ACCESS_CHECK  0x00000400

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

typedef struct {
    union {
        struct {
            DWORD LowPart;
            LONG HighPart;
        };
        int64_t QuadPart;
    };
} LARGE_INTEGER, *PLARGE_INTEGER;

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
#define STANDARD_RIGHTS_REQUIRED    (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
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

#define SECTION_QUERY 0x0001
#define SECTION_MAP_WRITE 0x0002
#define SECTION_MAP_READ 0x0004
#define SECTION_MAP_EXECUTE 0x0008
#define SECTION_EXTEND_SIZE 0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |SECTION_QUERY| SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE)

#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_MAPPED 0x40000
#define MEM_RESET 0x80000
#define MEM_TOP_DOWN 0x100000
#define MEM_WRITE_WATCH 0x200000
#define MEM_PHYSICAL 0x400000
#define MEM_ROTATE 0x800000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_4MB_PAGES 0x80000000

#define SEC_FILE 0x800000
#define SEC_IMAGE 0x1000000
#define SEC_PROTECTED_IMAGE 0x2000000
#define SEC_RESERVE 0x4000000
#define SEC_COMMIT 0x8000000
#define SEC_NOCACHE 0x10000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

typedef enum {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

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

typedef struct {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION;

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

typedef void* PSID;

#define THREAD_TERMINATE 0x0001
#define THREAD_SUSPEND_RESUME 0x0002
#define THREAD_GET_CONTEXT 0x0008
#define THREAD_SET_CONTEXT 0x0010
#define THREAD_SET_INFORMATION 0x0020
#define THREAD_QUERY_INFORMATION 0x0040
#define THREAD_SET_THREAD_TOKEN 0x0080
#define THREAD_IMPERSONATE 0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_ALL_ACCESS STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                          THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION | \
                          THREAD_DIRECT_IMPERSONATION | THREAD_IMPERSONATE | \
                          THREAD_SET_THREAD_TOKEN | THREAD_QUERY_INFORMATION | \
                          THREAD_SET_INFORMATION | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | \
                          THREAD_SUSPEND_RESUME | THREAD_TERMINATE
// FIXME - is THREAD_ALL_ACCESS right? It doesn't match mingw

#ifdef _X86_

#define CONTEXT_i386 0x00010000
#define CONTEXT_CONTROL CONTEXT_i386 | 0x00000001
#define CONTEXT_INTEGER CONTEXT_i386 | 0x00000002
#define CONTEXT_SEGMENTS CONTEXT_i386 | 0x00000004
#define CONTEXT_FLOATING_POINT CONTEXT_i386 | 0x00000008
#define CONTEXT_DEBUG_REGISTERS CONTEXT_i386 | 0x00000010
#define CONTEXT_EXTENDED_REGISTERS CONTEXT_i386 | 0x00000020

#elif defined(__x86_64__)

#define CONTEXT_AMD64 0x00100000
#define CONTEXT_CONTROL CONTEXT_AMD64 | 0x00000001
#define CONTEXT_INTEGER CONTEXT_AMD64 | 0x00000002
#define CONTEXT_SEGMENTS CONTEXT_AMD64 | 0x00000004
#define CONTEXT_FLOATING_POINT CONTEXT_AMD64 | 0x00000008
#define CONTEXT_DEBUG_REGISTERS CONTEXT_AMD64 | 0x00000010

#endif

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

#endif

#define __stdcall __attribute__((ms_abi)) __attribute__((__force_align_arg_pointer__))

void close_muwine();

NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS __stdcall NtClose(HANDLE Handle);
NTSTATUS __stdcall NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                                  PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                       PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName,
                                   KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, void* KeyValueInformation,
                                   DWORD Length, DWORD* ResultLength);
NTSTATUS __stdcall NtSetValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName, ULONG TitleIndex,
                                 ULONG Type, const void* Data, ULONG DataSize);
NTSTATUS __stdcall NtDeleteValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName);
NTSTATUS __stdcall NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG TitleIndex, const UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition);
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
NTSTATUS __stdcall NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                PVOID EaBuffer, ULONG EaLength);
NTSTATUS __stdcall NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                PULONG Key);
NTSTATUS __stdcall NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS __stdcall NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS __stdcall NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, const void* Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                PULONG Key);
NTSTATUS __stdcall NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                              ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                        PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                        PUNICODE_STRING FileMask, BOOLEAN RestartScan);
NTSTATUS __stdcall NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS __stdcall NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                              PUNICODE_STRING DestinationName);
NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                                   const LARGE_INTEGER* MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle);
NTSTATUS __stdcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      SIZE_T CommitSize, const LARGE_INTEGER* SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                      ULONG AllocationType, ULONG Win32Protect);
NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                          ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                           PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS __stdcall NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes);
NTSTATUS __stdcall NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                                ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
NTSTATUS __stdcall NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                         PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                         ULONG OutputBufferLength);
NTSTATUS __stdcall NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                   PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                   ULONG OutputBufferLength);
NTSTATUS __stdcall NtSetVolumeInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                              FS_INFORMATION_CLASS FileSystemInformationClass);
NTSTATUS __stdcall NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                              PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                              BOOLEAN ExclusiveLock);
NTSTATUS __stdcall NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                               ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList,
                                               ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan);
NTSTATUS __stdcall NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                             ULONG Length);
NTSTATUS __stdcall NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                                PLARGE_INTEGER Length, ULONG Key);
NTSTATUS __stdcall NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
NTSTATUS __stdcall NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);
NTSTATUS __stdcall NtQueryAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                         FILE_BASIC_INFORMATION* FileInformation);
NTSTATUS __stdcall NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                 ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength,
                                 PULONG EaIndex, BOOLEAN RestartScan);
NTSTATUS __stdcall NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                             FILE_NETWORK_OPEN_INFORMATION* FileInformation);
NTSTATUS __stdcall NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                               ULONG Length);
NTSTATUS __stdcall NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                  PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                                  BOOLEAN CreateSuspended);
NTSTATUS __stdcall NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

#ifdef __cplusplus
}
#endif
