#include "muwine.h"

#define SECTOR_SIZE 0x1000

typedef struct _fcb {
    struct list_head list;
    unsigned int refcount;
    struct file* f;
    char path[1];
} fcb;

LIST_HEAD(fcb_list);
DECLARE_RWSEM(fcb_list_sem);

static int stricmp(char* s1, char* s2) {
    // FIXME - do this properly (including Greek, Cyrillic, etc.)

    while (true) {
        char c1 = *s1;
        char c2 = *s2;

        if (c1 >= 'A' && c1 <= 'Z')
            c1 = c1 - 'A' + 'a';

        if (c2 >= 'A' && c2 <= 'Z')
            c2 = c2 - 'A' + 'a';

        if (c1 < c2)
            return -1;
        else if (c2 < c1)
            return 1;

        if (c1 == 0 || c2 == 0)
            break;

        s1++;
        s2++;
    }

    return 0;
}

static void file_object_close(object_header* obj) {
    file_object* f = (file_object*)obj;

    down_write(&fcb_list_sem);

    f->f->refcount--;

    if (f->f->refcount == 0) {
        filp_close(f->f->f, NULL);
        list_del(&f->f->list);
        kfree(f->f);
    }

    up_write(&fcb_list_sem);

    if (f->header.path.Buffer)
        kfree(f->header.path.Buffer);

    kfree(f);
}

NTSTATUS unixfs_create_file(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, UNICODE_STRING* us,
                            PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                            PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS Status;
    ULONG as_len;
    char* path;
    unsigned int i;
    struct list_head* le;
    fcb* f = NULL;
    file_object* obj;

    static const WCHAR prefix[] = L"\\Device\\UnixRoot";

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

    // convert us to UTF-8, and replace backslashes with slashes

    Status = utf16_to_utf8(NULL, 0, &as_len, us->Buffer, us->Length);
    if (!NT_SUCCESS(Status))
        return Status;
    else if (Status == STATUS_SOME_NOT_MAPPED)
        return STATUS_INVALID_PARAMETER;

    path = kmalloc(as_len + 1, GFP_KERNEL);
    if (!path)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = utf16_to_utf8(path, as_len, &as_len, us->Buffer, us->Length);
    if (!NT_SUCCESS(Status)) {
        kfree(path);
        return Status;
    }

    for (i = 0; i < as_len; i++) {
        if (path[i] == '\\')
            path[i] = '/';
    }

    path[as_len] = 0;

    // loop through list of FCBs, and increase refcount if found; otherwise, do filp_open

    down_write(&fcb_list_sem);

    le = fcb_list.next;
    while (le != &fcb_list) {
        fcb* f2 = list_entry(le, fcb, list);

        // FIXME - should be by mount point and inode no.
        if (!stricmp(f2->path, path)) {
            f2->refcount++;
            f = f2;
            break;
        }

        le = le->next;
    }

    if (!f) {
        f = kmalloc(offsetof(fcb, path) + as_len + 1, GFP_KERNEL);
        if (!f) {
            up_write(&fcb_list_sem);
            kfree(path);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        f->refcount = 1;

        // FIXME - case-insensitivity
        f->f = filp_open(path, O_RDONLY, 0);
        if (IS_ERR(f)) {
            int err = (int)(uintptr_t)f->f;

            up_write(&fcb_list_sem);

            kfree(f);
            kfree(path);

            return muwine_error_to_ntstatus(err);
        }

        memcpy(f->path, path, as_len + 1);

        list_add_tail(&f->list, &fcb_list);
    }

    up_write(&fcb_list_sem);

    kfree(path);

    // FIXME - check xattr for SD, and check process has permissions for requested access
    // FIXME - check share access

    // FIXME - FILE_DIRECTORY_FILE and FILE_NON_DIRECTORY_FILE
    // FIXME - oplocks
    // FIXME - EAs
    // FIXME - other options

    // create file object (with path)

    obj = kmalloc(sizeof(file_object), GFP_KERNEL);
    if (!obj) {
        down_write(&fcb_list_sem);

        f->refcount--;

        if (f->refcount == 0) {
            filp_close(f->f, NULL);
            list_del(&f->list);
            kfree(f);
        }

        up_write(&fcb_list_sem);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->header.refcount = 1;
    obj->header.type = muwine_object_file;

    obj->header.path.Length = obj->header.path.MaximumLength = us->Length + sizeof(prefix) - sizeof(WCHAR);
    obj->header.path.Buffer = kmalloc(obj->header.path.Length, GFP_KERNEL);

    if (!obj->header.path.Buffer) {
        down_write(&fcb_list_sem);

        f->refcount--;

        if (f->refcount == 0) {
            filp_close(f->f, NULL);
            list_del(&f->list);
            kfree(f);
        }

        up_write(&fcb_list_sem);

        kfree(obj);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(obj->header.path.Buffer, prefix, sizeof(prefix) - sizeof(WCHAR));
    memcpy(&obj->header.path.Buffer[(sizeof(prefix) / sizeof(WCHAR)) - 1], us->Buffer, us->Length);

    obj->header.close = file_object_close;
    obj->f = f;
    obj->flags = 0;
    obj->offset = 0;

    if (CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        obj->flags |= FO_SYNCHRONOUS_IO;

    // return handle

    Status = muwine_add_handle(&obj->header, FileHandle);

    if (!NT_SUCCESS(Status)) {
        down_write(&fcb_list_sem);

        f->refcount--;

        if (f->refcount == 0) {
            filp_close(f->f, NULL);
            list_del(&f->list);
            kfree(f);
        }

        up_write(&fcb_list_sem);

        kfree(obj->header.path.Buffer);
        kfree(obj);

        return Status;
    }

    return Status;
}

NTSTATUS unixfs_query_information(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                  ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    switch (FileInformationClass) {
        case FileStandardInformation: {
            FILE_STANDARD_INFORMATION* fsi = (FILE_STANDARD_INFORMATION*)FileInformation;

            if (Length < sizeof(FILE_STANDARD_INFORMATION))
                return STATUS_BUFFER_TOO_SMALL;

            if (!obj->f->f->f_inode)
                return STATUS_INTERNAL_ERROR;

            fsi->EndOfFile.QuadPart = obj->f->f->f_inode->i_size;
            fsi->AllocationSize.QuadPart = (fsi->EndOfFile.QuadPart + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
            fsi->NumberOfLinks = obj->f->f->f_inode->i_nlink;
            fsi->DeletePending = false; // FIXME
            fsi->Directory = false; // FIXME

            IoStatusBlock->Information = sizeof(FILE_STANDARD_INFORMATION);

            return STATUS_SUCCESS;
        }

        // FIXME - FileBasicInformation
        // FIXME - FileInternalInformation
        // FIXME - FileEndOfFileInformation
        // FIXME - FileAllInformation
        // FIXME - others not supported by Wine

        default: {
            printk(KERN_INFO "unixfs_query_information: unhandled class %x\n",
                   FileInformationClass);

            return STATUS_INVALID_INFO_CLASS;
        }
    }
}

NTSTATUS unixfs_read(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                     PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                     PULONG Key) {
    ssize_t read;
    loff_t pos;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (ByteOffset && ByteOffset->HighPart == -1 && ByteOffset->LowPart == FILE_USE_FILE_POINTER_POSITION)
        ByteOffset = NULL;

    if (ByteOffset)
        pos = ByteOffset->QuadPart;
    else if (obj->flags & FO_SYNCHRONOUS_IO)
        pos = obj->offset;
    else
        return STATUS_INVALID_PARAMETER;

    read = kernel_read(obj->f->f, Buffer, Length, &pos);

    if (read < 0) {
        if (obj->flags & FO_SYNCHRONOUS_IO && ByteOffset)
            obj->offset = ByteOffset->QuadPart;

        return muwine_error_to_ntstatus(read);
    }

    if (obj->flags & FO_SYNCHRONOUS_IO)
        obj->offset = pos;

    IoStatusBlock->Information = read;

    return STATUS_SUCCESS;
}

NTSTATUS unixfs_write(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                      PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                      PULONG Key) {
    printk(KERN_INFO "unixfs_write(%px, %lx, %px, %px, %px, %px, %x, %px, %px): stub\n",
           obj, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           Buffer, Length, ByteOffset, Key);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS unixfs_set_information(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    printk(KERN_INFO "unixfs_set_information(%px, %px, %px, %x, %x): stub\n",
           obj, IoStatusBlock, FileInformation, Length, FileInformationClass);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
