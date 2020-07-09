#include "muw.h"
#include "../kernel/ioctls.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define STATUS_NOT_IMPLEMENTED              (NTSTATUS)0xc0000002

int muwine_fd = 0;

#define init_muwine() if (muwine_fd == 0) { \
    int fd = open("/dev/muwine", O_RDWR); \
    if (fd < 0) return STATUS_NOT_IMPLEMENTED; \
    muwine_fd = fd; \
}

NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    uintptr_t args[] = {
        3,
        (uintptr_t)KeyHandle,
        (uintptr_t)DesiredAccess,
        (uintptr_t)ObjectAttributes
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTOPENKEY, args);
}

NTSTATUS NtClose(HANDLE Handle) {
    uintptr_t args[] = {
        1,
        (uintptr_t)Handle
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTCLOSE, args);
}

NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
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

NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
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

NTSTATUS NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
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

NTSTATUS NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                       ULONG Type, PVOID Data, ULONG DataSize) {
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

NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    uintptr_t args[] = {
        2,
        (uintptr_t)KeyHandle,
        (uintptr_t)ValueName
    };

    init_muwine();

    return ioctl(muwine_fd, MUWINE_IOCTL_NTDELETEVALUEKEY, args);
}

NTSTATUS NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                     PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
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
