#include "muwine.h"

NTSTATUS unixfs_create_file(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, UNICODE_STRING* us,
                            PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                            PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS Status;
    ULONG as_len;
    char* name;
    unsigned int i;

    printk(KERN_INFO "unixfs_create_file(%lx, %x, %px, %px, %px, %x, %x, %x, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, DesiredAccess, us, IoStatusBlock, AllocationSize,
           FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer,
           EaLength);

    // FIXME - ADS

    // FIXME - handle creating files
    // FIXME - how do ECPs get passed?

    if (CreateDisposition != FILE_OPEN && CreateDisposition != FILE_OPEN_IF)
        return STATUS_NOT_IMPLEMENTED;

    // FIXME - handle opening \\Device\\UnixRoot directly
    if (us->Length < sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    if (us->Buffer[0] != '\\')
        return STATUS_INVALID_PARAMETER;

    // FIXME - convert us to UTF-8, and replace backslashes with slashes
    Status = utf16_to_utf8(NULL, 0, &as_len, us->Buffer, us->Length);
    if (!NT_SUCCESS(Status))
        return Status;
    else if (Status == STATUS_SOME_NOT_MAPPED)
        return STATUS_INVALID_PARAMETER;

    name = kmalloc(as_len + 1, GFP_KERNEL);
    if (!name)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = utf16_to_utf8(name, as_len, &as_len, us->Buffer, us->Length);
    if (!NT_SUCCESS(Status)) {
        kfree(name);
        return Status;
    }

    for (i = 0; i < as_len; i++) {
        if (name[i] == '\\')
            name[i] = '/';
    }

    name[as_len] = 0;

    printk(KERN_INFO "name = \"%s\"\n", name);

    // FIXME - loop through list of FCBs, and increase refcount if found; otherwise, do filp_open
    // FIXME - check xattr for SD, and check process has permissions for requested access
    // FIXME - check share access

    // FIXME - FILE_DIRECTORY_FILE and FILE_NON_DIRECTORY_FILE
    // FIXME - oplocks
    // FIXME - EAs
    // FIXME - other options

    // FIXME - create file object (with path)
    // FIXME - return handle

    kfree(name);

    return STATUS_NOT_IMPLEMENTED;
}
