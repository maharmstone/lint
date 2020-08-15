#include "muw.h"
#include "../kernel/ioctls.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define STATUS_NOT_IMPLEMENTED              (NTSTATUS)0xc0000002

int muwine_fd = 0;

#define init_muwine() if (muwine_fd == 0) { \
    int fd = open("/dev/muwine", O_RDWR); \
    if (fd < 0) return STATUS_NOT_IMPLEMENTED; \
    muwine_fd = fd; \
}

NTSTATUS __stdcall NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes) {
    uintptr_t args[] = {
        3,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENKEY, args);
}

NTSTATUS __stdcall NtClose(HANDLE Handle) {
    uintptr_t args[] = {
        1,
        (uintptr_t)Handle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCLOSE, args);
}

NTSTATUS __stdcall NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                                  PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTENUMERATEKEY, args);
}

NTSTATUS __stdcall NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                       PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTENUMERATEVALUEKEY, args);
}

NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName,
                                   KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                   PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYVALUEKEY, args);
}

NTSTATUS __stdcall NtSetValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName, ULONG TitleIndex,
                                 ULONG Type, const void* Data, ULONG DataSize) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETVALUEKEY, args);
}

NTSTATUS __stdcall NtDeleteValueKey(HANDLE KeyHandle, const UNICODE_STRING* ValueName) {
    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDELETEVALUEKEY, args);
}

NTSTATUS __stdcall NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG TitleIndex, const UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCREATEKEY, args);
}

NTSTATUS __stdcall NtDeleteKey(HANDLE KeyHandle) {
    uintptr_t args[] = {
        1,
        (uintptr_t)KeyHandle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDELETEKEY, args);
}

NTSTATUS __stdcall NtLoadKey(const OBJECT_ATTRIBUTES* DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName) {
    uintptr_t args[] = {
        2,
        (uintptr_t)DestinationKeyName,
        (uintptr_t)HiveFileName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTLOADKEY, args);
}

NTSTATUS __stdcall NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    uintptr_t args[] = {
        1,
        (uintptr_t)DestinationKeyName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTUNLOADKEY, args);
}

NTSTATUS __stdcall NtFlushKey(HANDLE KeyHandle) {
    uintptr_t args[] = {
        1,
        (uintptr_t)KeyHandle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTFLUSHKEY, args);
}

NTSTATUS __stdcall NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                               ULONG OpenOptions) {
    uintptr_t args[] = {
        4,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)OpenOptions
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENKEYEX, args);
}

NTSTATUS __stdcall NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                              ULONG Length, PULONG ResultLength) {
    uintptr_t args[] = {
        5,
        (uintptr_t)KeyHandle,
        (uintptr_t)KeyInformationClass,
        (uintptr_t)KeyInformation,
        (uintptr_t)Length,
        (uintptr_t)ResultLength
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYKEY, args);
}

NTSTATUS __stdcall NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)FileHandle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSAVEKEY, args);
}

NTSTATUS __stdcall NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchSubtree,
                                     PVOID ChangeBuffer, ULONG Length, BOOLEAN Asynchronous) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTNOTIFYCHANGEKEY, args);
}

NTSTATUS __stdcall NtNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects,
                                              HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                              PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter,
                                              BOOLEAN WatchSubtree, PVOID ChangeBuffer, ULONG Length,
                                              BOOLEAN Asynchronous) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTNOTIFYCHANGEMULTIPLEKEYS, args);
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCREATEFILE, args);
}

NTSTATUS __stdcall NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                              PULONG Key) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTREADFILE, args);
}

NTSTATUS __stdcall NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENFILE, args);
}

NTSTATUS __stdcall NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                          ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FileInformation,
        (uintptr_t)Length,
        (uintptr_t)FileInformationClass
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                               PIO_STATUS_BLOCK IoStatusBlock, const void* Buffer, ULONG Length,
                               PLARGE_INTEGER ByteOffset, PULONG Key) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTWRITEFILE, args);
}

NTSTATUS __stdcall NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                        ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FileInformation,
        (uintptr_t)Length,
        (uintptr_t)FileInformationClass
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                        PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                        FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                        PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYDIRECTORYFILE, args);
}

NTSTATUS __stdcall NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    uintptr_t args[] = {
        3,
        (uintptr_t)DirectoryHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCREATEDIRECTORYOBJECT, args);
}

NTSTATUS __stdcall NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                              PUNICODE_STRING DestinationName) {
    uintptr_t args[] = {
        4,
        (uintptr_t)pHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)DestinationName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCREATESYMBOLICLINKOBJECT, args);
}

NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                                   const LARGE_INTEGER* MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCREATESECTION, args);
}

NTSTATUS __stdcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      SIZE_T CommitSize, const LARGE_INTEGER* SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                      ULONG AllocationType, ULONG Win32Protect) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTMAPVIEWOFSECTION, args);
}

NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    uintptr_t args[] = {
        2,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTUNMAPVIEWOFSECTION, args);
}

NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                          ULONG NewAccessProtection, PULONG OldAccessProtection) {
    uintptr_t args[] = {
        5,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)NumberOfBytesToProtect,
        (uintptr_t)NewAccessProtection,
        (uintptr_t)OldAccessProtection
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTPROTECTVIRTUALMEMORY, args);
}

NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                           PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTALLOCATEVIRTUALMEMORY, args);
}

NTSTATUS __stdcall NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                 const OBJECT_ATTRIBUTES* ObjectAttributes) {
    uintptr_t args[] = {
        3,
        (uintptr_t)SectionHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENSECTION, args);
}

NTSTATUS __stdcall NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                                ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)FsInformation,
        (uintptr_t)Length,
        (uintptr_t)FsInformationClass
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYVOLUMEINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    uintptr_t args[] = {
        4,
        (uintptr_t)ProcessHandle,
        (uintptr_t)BaseAddress,
        (uintptr_t)RegionSize,
        (uintptr_t)FreeType
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTFREEVIRTUALMEMORY, args);
}

NTSTATUS __stdcall NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                         PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                         ULONG OutputBufferLength) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDEVICEIOCONTROLFILE, args);
}

NTSTATUS __stdcall NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                   PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                   PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                   ULONG OutputBufferLength) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTFSCONTROLFILE, args);
}

NTSTATUS __stdcall NtSetVolumeInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                              FS_INFORMATION_CLASS FileSystemInformationClass) {
    uintptr_t args[] = {
        5,
        (uintptr_t)hFile,
        (uintptr_t)io,
        (uintptr_t)ptr,
        (uintptr_t)len,
        (uintptr_t)FileSystemInformationClass
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETVOLUMEINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                              PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                              PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                              BOOLEAN ExclusiveLock) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTLOCKFILE, args);
}

NTSTATUS __stdcall NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                               ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList,
                                               ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYQUOTAINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                             ULONG Length) {
    uintptr_t args[] = {
        4,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETQUOTAINFORMATIONFILE, args);
}

NTSTATUS __stdcall NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                                PLARGE_INTEGER Length, ULONG Key) {
    uintptr_t args[] = {
        5,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)ByteOffset,
        (uintptr_t)Length,
        (uintptr_t)Key
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTUNLOCKFILE, args);
}

NTSTATUS __stdcall NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    uintptr_t args[] = {
        1,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDELETEFILE, args);
}

NTSTATUS __stdcall NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    uintptr_t args[] = {
        2,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTFLUSHBUFFERSFILE, args);
}

NTSTATUS __stdcall NtQueryAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                         FILE_BASIC_INFORMATION* FileInformation) {
    uintptr_t args[] = {
        2,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)FileInformation
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYATTRIBUTESFILE, args);
}

NTSTATUS __stdcall NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                 ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength,
                                 PULONG EaIndex, BOOLEAN RestartScan) {
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

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYEAFILE, args);
}

NTSTATUS __stdcall NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES* ObjectAttributes,
                                             FILE_NETWORK_OPEN_INFORMATION* FileInformation) {
    uintptr_t args[] = {
        2,
        (uintptr_t)ObjectAttributes,
        (uintptr_t)FileInformation
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTQUERYFULLATTRIBUTESFILE, args);
}

NTSTATUS __stdcall NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                               ULONG Length) {
    uintptr_t args[] = {
        4,
        (uintptr_t)FileHandle,
        (uintptr_t)IoStatusBlock,
        (uintptr_t)Buffer,
        (uintptr_t)Length
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTSETEAFILE, args);
}
