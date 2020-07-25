#include "muwine.h"

NTSTATUS unixfs_create_file(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, UNICODE_STRING* us,
                            PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                            PVOID EaBuffer, ULONG EaLength) {
    printk(KERN_INFO "unixfs_create_file(%lx, %x, %px, %px, %px, %x, %x, %x, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, DesiredAccess, us, IoStatusBlock, AllocationSize,
           FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer,
           EaLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
