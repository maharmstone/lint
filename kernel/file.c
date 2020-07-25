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
