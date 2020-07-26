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
