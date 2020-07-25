#include "muwine.h"

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                      ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                      PVOID EaBuffer, ULONG EaLength) {
    printk(KERN_INFO "NtCreateFile(%lx, %x, %px, %px, %px, %x, %x, %x, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
           FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer,
           EaLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, NULL, 0);
}

NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key) {
    printk(KERN_INFO "NtReadFile(%lx, %lx, %px, %px, %px, %px, %x, %px, %px): stub\n",
           (uintptr_t)FileHandle, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           Buffer, Length, ByteOffset, Key);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    printk(KERN_INFO "NtQueryInformationFile(%lx, %px, %px, %x, %x): stub\n", (uintptr_t)FileHandle,
           IoStatusBlock, FileInformation, Length, FileInformationClass);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
