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
        "mov rax, %0\n\t" \
        "mov rdi, %1\n\t" \
        "mov rsi, %2\n\t" \
        "mov rdx, %3\n\t" \
        "syscall\n\t" \
        "mov %4, rax\n\t" \
        : \
        : "r" ((uint64_t)SYS_ioctl), "r" ((uint64_t)muwine_fd), "r" ((uint64_t)num), "r" (args), "m" ((uint64_t)ret) \
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
