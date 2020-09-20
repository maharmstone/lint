#include "muw.h"
#include "../kernel/ioctls.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#define STATUS_NOT_IMPLEMENTED              (NTSTATUS)0xc0000002

int muwine_fd = 0;

#define init_muwine() if (muwine_fd == 0) { \
    int fd = (int)syscall(SYS_open, "/dev/muwine", O_RDWR, 0); \
    if (fd < 0) return STATUS_NOT_IMPLEMENTED; \
    muwine_fd = fd; \
}

#define do_ioctl(num, args, ret) do { \
    __asm __volatile( \
        "mov rax, %1\n\t" \
        "mov rdi, %2\n\t" \
        "mov rsi, %3\n\t" \
        "mov rdx, %4\n\t" \
        "syscall\n\t" \
        "mov %0, rax\n\t" \
        : "=m" ((uint64_t)ret) \
        : "r" ((uint64_t)SYS_ioctl), "r" ((uint64_t)muwine_fd), "r" ((uint64_t)num), "r" (args) \
        : "rax", "rdi", "rsi", "rdx" \
    ); \
} while (0)

NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtClose(HANDLE Handle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)Handle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCLOSE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                                  PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    long ret;

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

    do_ioctl(MUWINE_IOCTL_NTENUMERATEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                       PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    long ret;

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

    do_ioctl(MUWINE_IOCTL_NTENUMERATEVALUEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName,
                                   KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                   PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    long ret;

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

    do_ioctl(MUWINE_IOCTL_NTQUERYVALUEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName, ULONG TitleIndex,
                                 ULONG Type, const void* Data, ULONG DataSize) {
    long ret;

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

    do_ioctl(MUWINE_IOCTL_NTSETVALUEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDeleteValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDELETEVALUEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG TitleIndex, const UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition) {
    long ret;

    uintptr_t args[] = {
        7,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)TitleIndex,
        (uintptr_t)Class,
        (uintptr_t)CreateOptions,
        (uintptr_t)Disposition
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDeleteKey(HANDLE KeyHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)KeyHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDELETEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtLoadKey(const OBJECT_ATTRIBUTES* DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)DestinationKeyName,
        (uintptr_t)HiveFileName
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTLOADKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)DestinationKeyName
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTUNLOADKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtFlushKey(HANDLE KeyHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)KeyHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTFLUSHKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG OpenOptions) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)OpenOptions
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENKEYEX, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                              ULONG Length, PULONG ResultLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)KeyHandle,
        (uintptr_t)KeyInformationClass,
        (uintptr_t)KeyInformation,
        (uintptr_t)Length,
        (uintptr_t)ResultLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)FileHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSAVEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchSubtree,
                                     PVOID ChangeBuffer, ULONG Length, BOOLEAN Asynchronous) {
    long ret;

    uintptr_t args[] = {
        10,
        (uintptr_t)KeyHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)CompletionFilter,
        (uintptr_t)WatchSubtree,
        (uintptr_t)ChangeBuffer,
        (uintptr_t)Length,
        (uintptr_t)Asynchronous
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTNOTIFYCHANGEKEY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects,
                                              HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                              PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter,
                                              BOOLEAN WatchSubtree, PVOID ChangeBuffer, ULONG Length,
                                              BOOLEAN Asynchronous) {
    long ret;

    uintptr_t args[] = {
        12,
        (uintptr_t)KeyHandle,
        (uintptr_t)Count,
        (uintptr_t)SubordinateObjects,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)CompletionFilter,
        (uintptr_t)WatchSubtree,
        (uintptr_t)ChangeBuffer,
        (uintptr_t)Length,
        (uintptr_t)Asynchronous
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTNOTIFYCHANGEMULTIPLEKEYS, args, ret);

    return (NTSTATUS)ret;
}

void close_muwine() {
    if (muwine_fd != 0) {
        close(muwine_fd);
        muwine_fd = 0;
    }
}

NTSTATUS __stdcall NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                PVOID EaBuffer, ULONG EaLength) {
    long ret;

    uintptr_t args[] = {
        11,
        (uintptr_t)FileHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)AllocationSize,
        (uintptr_t)FileAttributes,
        (uintptr_t)ShareAccess,
        (uintptr_t)CreateDisposition,
        (uintptr_t)CreateOptions,
        (uintptr_t)EaBuffer,
        (uintptr_t)EaLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                              PULONG Key) {
    long ret;

    uintptr_t args[] = {
        9,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length,
        (uintptr_t)ByteOffset,
        (uintptr_t)Key
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTREADFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    long ret;

    uintptr_t args[] = {
        6,
        (uintptr_t)FileHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)ShareAccess,
        (uintptr_t)OpenOptions
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                          ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FileInformation,
        (uintptr_t)Length,
        (uintptr_t)FileInformationClass
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                               PIO_STATUS_BLOCK IoStatusBlock, const void* Buffer, ULONG Length,
                               PLARGE_INTEGER ByteOffset, PULONG Key) {
    long ret;

    uintptr_t args[] = {
        9,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length,
        (uintptr_t)ByteOffset,
        (uintptr_t)Key
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTWRITEFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                        ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FileInformation,
        (uintptr_t)Length,
        (uintptr_t)FileInformationClass
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                        PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                        PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
    long ret;

    uintptr_t args[] = {
        11,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FileInformation,
        (uintptr_t)Length,
        (uintptr_t)FileInformationClass,
        (uintptr_t)ReturnSingleEntry,
        (uintptr_t)FileMask,
        (uintptr_t)RestartScan
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYDIRECTORYFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)DirectoryHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEDIRECTORYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                              PUNICODE_STRING DestinationName) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)pHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)DestinationName
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATESYMBOLICLINKOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                                   const LARGE_INTEGER* MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle) {
    long ret;

    uintptr_t args[] = {
        7,
        (uintptr_t)SectionHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)MaximumSize,
        (uintptr_t)SectionPageProtection,
        (uintptr_t)AllocationAttributes,
        (uintptr_t)FileHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATESECTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      SIZE_T CommitSize, const LARGE_INTEGER* SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                      ULONG AllocationType, ULONG Win32Protect) {
    long ret;

    uintptr_t args[] = {
        10,
        (uintptr_t)SectionHandle,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)ZeroBits,
        (uintptr_t)CommitSize,
        (uintptr_t)SectionOffset,
        (uintptr_t)ViewSize,
        (uintptr_t)InheritDisposition,
        (uintptr_t)AllocationType,
        (uintptr_t)Win32Protect
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTMAPVIEWOFSECTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTUNMAPVIEWOFSECTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                          ULONG NewAccessProtection, PULONG OldAccessProtection) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)NumberOfBytesToProtect,
        (uintptr_t)NewAccessProtection,
        (uintptr_t)OldAccessProtection
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTPROTECTVIRTUALMEMORY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                           PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    long ret;

    uintptr_t args[] = {
        6,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)ZeroBits,
        (uintptr_t)RegionSize,
        (uintptr_t)AllocationType,
        (uintptr_t)Protect
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTALLOCATEVIRTUALMEMORY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)SectionHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENSECTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                                ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FsInformation,
        (uintptr_t)Length,
        (uintptr_t)FsInformationClass
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYVOLUMEINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)RegionSize,
        (uintptr_t)FreeType
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTFREEVIRTUALMEMORY, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                         PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                         ULONG OutputBufferLength) {
    long ret;

    uintptr_t args[] = {
        10,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)IoControlCode,
        (uintptr_t)InputBuffer,
        (uintptr_t)InputBufferLength,
        (uintptr_t)OutputBuffer,
        (uintptr_t)OutputBufferLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDEVICEIOCONTROLFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                   PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                   ULONG OutputBufferLength) {
    long ret;

    uintptr_t args[] = {
        10,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)IoControlCode,
        (uintptr_t)InputBuffer,
        (uintptr_t)InputBufferLength,
        (uintptr_t)OutputBuffer,
        (uintptr_t)OutputBufferLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTFSCONTROLFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetVolumeInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                              FS_INFORMATION_CLASS FileSystemInformationClass) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)hFile,
        (uintptr_t)io,
        (uintptr_t)ptr,
        (uintptr_t)len,
        (uintptr_t)FileSystemInformationClass
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETVOLUMEINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                              PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                              BOOLEAN ExclusiveLock) {
    long ret;

    uintptr_t args[] = {
        10,
        (uintptr_t)FileHandle,
        (uintptr_t)Event,
        (uintptr_t)ApcRoutine,
        (uintptr_t)ApcContext,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)ByteOffset,
        (uintptr_t)Length,
        (uintptr_t)Key,
        (uintptr_t)FailImmediately,
        (uintptr_t)ExclusiveLock
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTLOCKFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                               ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList,
                                               ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan) {
    long ret;

    uintptr_t args[] = {
        9,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length,
        (uintptr_t)ReturnSingleEntry,
        (uintptr_t)SidList,
        (uintptr_t)SidListLength,
        (uintptr_t)StartSid,
        (uintptr_t)RestartScan
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYQUOTAINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                             ULONG Length) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETQUOTAINFORMATIONFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                                PLARGE_INTEGER Length, ULONG Key) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)ByteOffset,
        (uintptr_t)Length,
        (uintptr_t)Key
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTUNLOCKFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDELETEFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTFLUSHBUFFERSFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                         FILE_BASIC_INFORMATION* FileInformation) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)FileInformation
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYATTRIBUTESFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                 ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength,
                                 PULONG EaIndex, BOOLEAN RestartScan) {
    long ret;

    uintptr_t args[] = {
        9,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length,
        (uintptr_t)ReturnSingleEntry,
        (uintptr_t)EaList,
        (uintptr_t)EaListLength,
        (uintptr_t)EaIndex,
        (uintptr_t)RestartScan
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYEAFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                             FILE_NETWORK_OPEN_INFORMATION* FileInformation) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)FileInformation
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYFULLATTRIBUTESFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                               ULONG Length) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETEAFILE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                  PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                                  BOOLEAN CreateSuspended) {
    long ret;

    uintptr_t args[] = {
        8,
        (uintptr_t)ThreadHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)ProcessHandle,
        (uintptr_t)ClientId,
        (uintptr_t)ThreadContext,
        (uintptr_t)InitialTeb,
        (uintptr_t)CreateSuspended
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATETHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadHandle,
        (uintptr_t)ExitStatus
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTTERMINATETHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable,
                                         const LARGE_INTEGER* TimeOut) {
    long ret;
    LARGE_INTEGER to;

    if (TimeOut)
        to.QuadPart = TimeOut->QuadPart;

    uintptr_t args[] = {
        3,
        (uintptr_t)ObjectHandle,
        (uintptr_t)Alertable,
        (uintptr_t)(TimeOut ? &to : NULL)
    };

    init_muwine();

    do {
        do_ioctl(MUWINE_IOCTL_NTWAITFORSINGLEOBJECT, args, ret);
    } while (ret == -EINTR);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtWaitForMultipleObjects(ULONG ObjectCount, const HANDLE* ObjectsArray,
                                            OBJECT_WAIT_TYPE WaitType, BOOLEAN Alertable,
                                            const LARGE_INTEGER* TimeOut) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)ObjectCount,
        (uintptr_t)ObjectsArray,
        (uintptr_t)WaitType,
        (uintptr_t)Alertable,
        (uintptr_t)TimeOut
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTWAITFORMULTIPLEOBJECTS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes, TIMER_TYPE TimerType) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)TimerHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)TimerType
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATETIMER, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                               const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)TimerHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENTIMER, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass,
                                PVOID TimerInformation, ULONG TimerInformationLength,
                                PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)TimerHandle,
        (uintptr_t)TimerInformationClass,
        (uintptr_t)TimerInformation,
        (uintptr_t)TimerInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYTIMER, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetTimer(HANDLE TimerHandle, const LARGE_INTEGER* DueTime,
                              PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                              BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    long ret;

    uintptr_t args[] = {
        7,
        (uintptr_t)TimerHandle,
        (uintptr_t)DueTime,
        (uintptr_t)TimerApcRoutine,
        (uintptr_t)TimerContext,
        (uintptr_t)ResumeTimer,
        (uintptr_t)Period,
        (uintptr_t)PreviousState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETTIMER, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)TimerHandle,
        (uintptr_t)CurrentState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCANCELTIMER, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes, EVENT_TYPE EventType,
                                 BOOLEAN InitialState) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)EventHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)EventType,
        (uintptr_t)InitialState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                               const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)EventHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)EventHandle,
        (uintptr_t)PreviousState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtResetEvent(HANDLE EventHandle, PLONG PreviousState) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)EventHandle,
        (uintptr_t)PreviousState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRESETEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtClearEvent(HANDLE EventHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)EventHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCLEAREVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PLONG PreviousState) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)EventHandle,
        (uintptr_t)PreviousState
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTPULSEEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass,
                                PVOID EventInformation, ULONG EventInformationLength,
                                PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)EventHandle,
        (uintptr_t)EventInformationClass,
        (uintptr_t)EventInformation,
        (uintptr_t)EventInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYEVENT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                                  const OBJECT_ATTRIBUTES* ObjectAttributes, BOOLEAN InitialOwner) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)MutantHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)InitialOwner
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEMUTANT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                                const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)MutantHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENMUTANT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass,
                                 PVOID MutantInformation, ULONG MutantInformationLength,
                                 PULONG ResultLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)MutantHandle,
        (uintptr_t)MutantInformationClass,
        (uintptr_t)MutantInformation,
        (uintptr_t)MutantInformationLength,
        (uintptr_t)ResultLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYMUTANT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)MutantHandle,
        (uintptr_t)PreviousCount
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRELEASEMUTANT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                     const OBJECT_ATTRIBUTES* ObjectAttributes, LONG InitialCount,
                                     LONG MaximumCount) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)SemaphoreHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)InitialCount,
        (uintptr_t)MaximumCount
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATESEMAPHORE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                   const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)SemaphoreHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENSEMAPHORE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQuerySemaphore(HANDLE SemaphoreHandle,
                                    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
                                    PVOID SemaphoreInformation, ULONG SemaphoreInformationLength,
                                    PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)SemaphoreHandle,
        (uintptr_t)SemaphoreInformationClass,
        (uintptr_t)SemaphoreInformation,
        (uintptr_t)SemaphoreInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYSEMAPHORE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)SemaphoreHandle,
        (uintptr_t)ReleaseCount,
        (uintptr_t)PreviousCount
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRELEASESEMAPHORE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                                 PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                                 PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                                 PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                                 PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                                 PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource) {
    long ret;

    uintptr_t args[] = {
        13,
        (uintptr_t)TokenHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)TokenType,
        (uintptr_t)AuthenticationId,
        (uintptr_t)ExpirationTime,
        (uintptr_t)TokenUser,
        (uintptr_t)TokenGroups,
        (uintptr_t)TokenPrivileges,
        (uintptr_t)TokenOwner,
        (uintptr_t)TokenPrimaryGroup,
        (uintptr_t)TokenDefaultDacl,
        (uintptr_t)TokenSource
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATETOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                      PHANDLE TokenHandle) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)ProcessHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)TokenHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENPROCESSTOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                           PTOKEN_PRIVILEGES TokenPrivileges,
                                           ULONG PreviousPrivilegesLength,
                                           PTOKEN_PRIVILEGES PreviousPrivileges,
                                           PULONG RequiredLength) {
    long ret;

    uintptr_t args[] = {
        6,
        (uintptr_t)TokenHandle,
        (uintptr_t)DisableAllPrivileges,
        (uintptr_t)TokenPrivileges,
        (uintptr_t)PreviousPrivilegesLength,
        (uintptr_t)PreviousPrivileges,
        (uintptr_t)RequiredLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTADJUSTPRIVILEGESTOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryInformationToken(HANDLE TokenHandle,
                                           TOKEN_INFORMATION_CLASS TokenInformationClass,
                                           PVOID TokenInformation, ULONG TokenInformationLength,
                                           PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)TokenHandle,
        (uintptr_t)TokenInformationClass,
        (uintptr_t)TokenInformation,
        (uintptr_t)TokenInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYINFORMATIONTOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAllocateLocallyUniqueId(PLUID Luid) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)Luid
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTALLOCATELOCALLYUNIQUEID, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                         PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                         PULONG LengthNeeded) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)Handle,
        (uintptr_t)SecurityInformation,
        (uintptr_t)SecurityDescriptor,
        (uintptr_t)Length,
        (uintptr_t)LengthNeeded,
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYSECURITYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                     BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ThreadHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)OpenAsSelf,
        (uintptr_t)TokenHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENTHREADTOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetInformationThread(HANDLE ThreadHandle,
                                          THREADINFOCLASS ThreadInformationClass,
                                          const void* ThreadInformation,
                                          ULONG ThreadInformationLength) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ThreadHandle,
        (uintptr_t)ThreadInformationClass,
        (uintptr_t)ThreadInformation,
        (uintptr_t)ThreadInformationLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETINFORMATIONTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                         const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)DirectoryHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENDIRECTORYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken,
                                 ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping,
                                 PPRIVILEGE_SET RequiredPrivilegesBuffer, PULONG BufferLength,
                                 PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {
    long ret;

    uintptr_t args[] = {
        8,
        (uintptr_t)SecurityDescriptor,
        (uintptr_t)ClientToken,
        (uintptr_t)DesiredAccess,
        (uintptr_t)GenericMapping,
        (uintptr_t)RequiredPrivilegesBuffer,
        (uintptr_t)BufferLength,
        (uintptr_t)GrantedAccess,
        (uintptr_t)AccessStatus
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTACCESSCHECK, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                       PSECURITY_DESCRIPTOR SecurityDescriptor) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)Handle,
        (uintptr_t)SecurityInformation,
        (uintptr_t)SecurityDescriptor
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETSECURITYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtPrivilegeCheck(HANDLE TokenHandle, PPRIVILEGE_SET RequiredPrivileges,
                                    PBOOLEAN Result) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)TokenHandle,
        (uintptr_t)RequiredPrivileges,
        (uintptr_t)Result
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTPRIVILEGECHECK, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
                                    TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
    long ret;

    uintptr_t args[] = {
        6,
        (uintptr_t)ExistingTokenHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)EffectiveOnly,
        (uintptr_t)TokenType,
        (uintptr_t)NewTokenHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDUPLICATETOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetInformationToken(HANDLE TokenHandle,
                                         TOKEN_INFORMATION_CLASS TokenInformationClass,
                                         PVOID TokenInformation, ULONG TokenInformationLength) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)TokenHandle,
        (uintptr_t)TokenInformationClass,
        (uintptr_t)TokenInformation,
        (uintptr_t)TokenInformationLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETINFORMATIONTOKEN, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                       BOOLEAN OpenAsSelf, ULONG HandleAttributes,
                                       PHANDLE TokenHandle) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)ThreadHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)OpenAsSelf,
        (uintptr_t)HandleAttributes,
        (uintptr_t)TokenHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENTHREADTOKENEX, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                        ULONG HandleAttributes, PHANDLE TokenHandle) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ProcessHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)HandleAttributes,
        (uintptr_t)TokenHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENPROCESSTOKENEX, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                    PRTL_THREAD_START_ROUTINE StartRoutine, PVOID Argument,
                                    ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize,
                                    SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    long ret;

    uintptr_t args[] = {
        11,
        (uintptr_t)ThreadHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)ProcessHandle,
        (uintptr_t)StartRoutine,
        (uintptr_t)Argument,
        (uintptr_t)CreateFlags,
        (uintptr_t)ZeroBits,
        (uintptr_t)StackSize,
        (uintptr_t)MaximumStackSize,
        (uintptr_t)AttributeList
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATETHREADEX, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtDelayExecution(BOOLEAN Alertable, const LARGE_INTEGER* DelayInterval) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)Alertable,
        (uintptr_t)DelayInterval,
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTDELAYEXECUTION, args, ret);

    return (NTSTATUS)ret;
}

ULONG __stdcall NtGetCurrentProcessorNumber(void) {
    long ret;

    uintptr_t args[] = {
        0
    };

    do_ioctl(MUWINE_IOCTL_NTGETCURRENTPROCESSORNUMBER, args, ret);

    return (ULONG)ret;
}

NTSTATUS __stdcall NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                const OBJECT_ATTRIBUTES* ObjectAttributes,
                                const CLIENT_ID* ClientId) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ThreadHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)ClientId
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryInformationThread(HANDLE ThreadHandle,
                                            THREADINFOCLASS ThreadInformationClass,
                                            PVOID ThreadInformation, ULONG ThreadInformationLength,
                                            PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)ThreadHandle,
        (uintptr_t)ThreadInformationClass,
        (uintptr_t)ThreadInformation,
        (uintptr_t)ThreadInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYINFORMATIONTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueueApcThread(HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1,
                                    ULONG_PTR arg2, ULONG_PTR arg3) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)handle,
        (uintptr_t)func,
        (uintptr_t)arg1,
        (uintptr_t)arg2,
        (uintptr_t)arg3
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUEUEAPCTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext,
                                    BOOLEAN HandleException) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)ExceptionRecord,
        (uintptr_t)ThreadContext,
        (uintptr_t)HandleException
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRAISEEXCEPTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadHandle,
        (uintptr_t)SuspendCount,
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRESUMETHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetContextThread(HANDLE ThreadHandle, const CONTEXT* Context) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadHandle,
        (uintptr_t)Context
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETCONTEXTTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetThreadExecutionState(EXECUTION_STATE NewFlags,
                                             EXECUTION_STATE* PreviousFlags) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)NewFlags,
        (uintptr_t)PreviousFlags
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETTHREADEXECUTIONSTATE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadHandle,
        (uintptr_t)PreviousSuspendCount
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSUSPENDTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtYieldExecution() {
    long ret;

    uintptr_t args[] = {
        0
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTYIELDEXECUTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadHandle,
        (uintptr_t)SuspendCount
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTALERTRESUMETHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtAlertThread(HANDLE ThreadHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)ThreadHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTALERTTHREAD, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ThreadContext,
        (uintptr_t)RaiseAlert
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCONTINUE, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes,
                                 const CLIENT_ID* ClientId) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ProcessHandle,
        (uintptr_t)AccessMask,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)ClientId
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryInformationProcess(HANDLE ProcessHandle,
                                             PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                             PVOID ProcessInformation,
                                             ULONG ProcessInformationLength,
                                             PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)ProcessHandle,
        (uintptr_t)ProcessInformationClass,
        (uintptr_t)ProcessInformation,
        (uintptr_t)ProcessInformationLength,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYINFORMATIONPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSetInformationProcess(HANDLE ProcessHandle,
                                           PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                           PVOID ProcessInformation,
                                           ULONG ProcessInformationLength) {
    long ret;

    uintptr_t args[] = {
        4,
        (uintptr_t)ProcessHandle,
        (uintptr_t)ProcessInformationClass,
        (uintptr_t)ProcessInformation,
        (uintptr_t)ProcessInformationLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSETINFORMATIONPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    long ret;

    uintptr_t args[] = {
        2,
        (uintptr_t)ProcessHandle,
        (uintptr_t)ExitStatus
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTTERMINATEPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtSuspendProcess(HANDLE ProcessHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)ProcessHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTSUSPENDPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtResumeProcess(HANDLE ProcessHandle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)ProcessHandle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTRESUMEPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass,
                                  PVOID InformationBuffer, SIZE_T InformationBufferSize,
                                  PSIZE_T ResultLength) {
    long ret;

    uintptr_t args[] = {
        5,
        (uintptr_t)SectionHandle,
        (uintptr_t)InformationClass,
        (uintptr_t)InformationBuffer,
        (uintptr_t)InformationBufferSize,
        (uintptr_t)ResultLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYSECTION, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
                                       ACCESS_MASK ProcessDesiredAccess,
                                       ACCESS_MASK ThreadDesiredAccess,
                                       POBJECT_ATTRIBUTES ProcessObjectAttributes,
                                       POBJECT_ATTRIBUTES ThreadObjectAttributes,
                                       ULONG ProcessFlags, ULONG ThreadFlags,
                                       PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                                       PPS_CREATE_INFO CreateInfo,
                                       PPS_ATTRIBUTE_LIST AttributeList) {
    long ret;

    uintptr_t args[] = {
        11,
        (uintptr_t)ProcessHandle,
        (uintptr_t)ThreadHandle,
        (uintptr_t)ProcessDesiredAccess,
        (uintptr_t)ThreadDesiredAccess,
        (uintptr_t)ProcessObjectAttributes,
        (uintptr_t)ThreadObjectAttributes,
        (uintptr_t)ProcessFlags,
        (uintptr_t)ThreadFlags,
        (uintptr_t)ProcessParameters,
        (uintptr_t)CreateInfo,
        (uintptr_t)AttributeList
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTCREATEUSERPROCESS, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtMakeTemporaryObject(HANDLE Handle) {
    long ret;

    uintptr_t args[] = {
        1,
        (uintptr_t)Handle
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTMAKETEMPORARYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess,
                                            const OBJECT_ATTRIBUTES* ObjectAttributes) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)LinkHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTOPENSYMBOLICLINKOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length,
                                          BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan,
                                          PULONG Context, PULONG ReturnLength) {
    long ret;

    uintptr_t args[] = {
        7,
        (uintptr_t)DirectoryHandle,
        (uintptr_t)Buffer,
        (uintptr_t)Length,
        (uintptr_t)ReturnSingleEntry,
        (uintptr_t)RestartScan,
        (uintptr_t)Context,
        (uintptr_t)ReturnLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYDIRECTORYOBJECT, args, ret);

    return (NTSTATUS)ret;
}

NTSTATUS __stdcall NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget,
                                             PULONG ReturnedLength) {
    long ret;

    uintptr_t args[] = {
        3,
        (uintptr_t)LinkHandle,
        (uintptr_t)LinkTarget,
        (uintptr_t)ReturnedLength
    };

    init_muwine();

    do_ioctl(MUWINE_IOCTL_NTQUERYSYMBOLICLINKOBJECT, args, ret);

    return (NTSTATUS)ret;
}
