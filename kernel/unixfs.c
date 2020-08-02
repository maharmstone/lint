#include "muwine.h"
#include <linux/namei.h>

#define SECTOR_SIZE 0x1000

typedef struct _fcb {
    struct list_head list;
    unsigned int refcount;
    struct file* f;
    char path[1];
} fcb;

static LIST_HEAD(fcb_list);
static DECLARE_RWSEM(fcb_list_sem);

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

    if (__sync_sub_and_fetch(&f->dev->header.refcount, 1) == 0)
        f->dev->header.close(&f->dev->header);

    if (f->header.path.Buffer)
        kfree(f->header.path.Buffer);

    kfree(f);
}

static NTSTATUS unixfs_create_file(device* dev, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, const UNICODE_STRING* us,
                                   PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                   ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                   PVOID EaBuffer, ULONG EaLength, ULONG oa_attributes) {
    NTSTATUS Status;
    ULONG as_len;
    char* path;
    unsigned int i;
    struct list_head* le;
    fcb* f = NULL;
    file_object* obj;

    // FIXME - ADS

    // FIXME - handle creating files
    // FIXME - how do ECPs get passed?

    // FIXME - handle opening \\Device\\UnixRoot directly
    if (us->Length < sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    if (CreateDisposition != FILE_SUPERSEDE && CreateDisposition != FILE_CREATE &&
        CreateDisposition != FILE_OPEN && CreateDisposition != FILE_OPEN_IF &&
        CreateDisposition != FILE_OVERWRITE && CreateDisposition != FILE_OVERWRITE_IF) {
        return STATUS_INVALID_PARAMETER;
    }

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
            if (CreateDisposition == FILE_SUPERSEDE) {
                up_write(&fcb_list_sem);
                kfree(path);
                return STATUS_CANNOT_DELETE;
            } else if (CreateDisposition == FILE_CREATE) {
                up_write(&fcb_list_sem);
                kfree(path);
                return STATUS_OBJECT_NAME_EXISTS;
            }

            f2->refcount++;
            f = f2;
            break;
        }

        le = le->next;
    }

    if (!f) {
        unsigned int flags;

        f = kmalloc(offsetof(fcb, path) + as_len + 1, GFP_KERNEL);
        if (!f) {
            up_write(&fcb_list_sem);
            kfree(path);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        f->refcount = 1;

        if (CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF)
            flags = O_CREAT;
        else if (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_OVERWRITE)
            flags = O_CREAT | O_EXCL;
        else
            flags = 0;

        if (CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF ||
            CreateDisposition == FILE_SUPERSEDE) {
            flags |= O_TRUNC;
        }

        // FIXME - case-insensitivity
        f->f = filp_open(path, flags | O_RDWR, 0644);
        if (IS_ERR(f->f)) {
            int err = (int)(uintptr_t)f->f;

            up_write(&fcb_list_sem);

            kfree(f);
            kfree(path);

            return muwine_error_to_ntstatus(err);
        }

        // FIXME - if new file, change uid and gid

        memcpy(f->path, path, as_len + 1);

        list_add_tail(&f->list, &fcb_list);
    }

    up_write(&fcb_list_sem);

    kfree(path);

    // FIXME - truncate if re-opened currently open file, and FILE_OVERWRITE, FILE_OVERWRITE_IF, or FILE_SUPERSEDE

    // FIXME - if supersede, should get rid of xattrs etc.(?)

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

    spin_lock_init(&obj->header.path_lock);
    obj->header.path.Length = obj->header.path.MaximumLength = us->Length + dev->header.path.Length;
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

    memcpy(obj->header.path.Buffer, dev->header.path.Buffer, dev->header.path.Length);
    memcpy(&obj->header.path.Buffer[dev->header.path.Length / sizeof(WCHAR)], us->Buffer, us->Length);

    obj->header.close = file_object_close;
    obj->f = f;
    obj->flags = 0;
    obj->offset = 0;
    obj->dev = dev;

    __sync_add_and_fetch(&dev->header.refcount, 1);

    if (CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        obj->flags |= FO_SYNCHRONOUS_IO;

    // return handle

    Status = muwine_add_handle(&obj->header, FileHandle, oa_attributes & OBJ_KERNEL_HANDLE);

    if (!NT_SUCCESS(Status)) {
        down_write(&fcb_list_sem);

        f->refcount--;

        if (f->refcount == 0) {
            filp_close(f->f, NULL);
            list_del(&f->list);
            kfree(f);
        }

        up_write(&fcb_list_sem);

        if (__sync_sub_and_fetch(&obj->dev->header.refcount, 1) == 0)
            obj->dev->header.close(&obj->dev->header);

        kfree(obj->header.path.Buffer);
        kfree(obj);

        return Status;
    }

    if (f->f->f_mode & FMODE_CREATED)
        IoStatusBlock->Information = FILE_CREATED;
    else {
        switch (CreateDisposition) {
            case FILE_SUPERSEDE:
                IoStatusBlock->Information = FILE_SUPERSEDED;
            break;

            case FILE_OPEN:
            case FILE_OPEN_IF:
                IoStatusBlock->Information = FILE_OPENED;
            break;

            case FILE_OVERWRITE:
            case FILE_OVERWRITE_IF:
                IoStatusBlock->Information = FILE_OVERWRITTEN;
            break;
        }
    }

    return Status;
}

static NTSTATUS unixfs_query_information(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
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

        case FileBasicInformation: {
            printk(KERN_INFO "unixfs_query_information: unhandled class FileBasicInformation\n");

            // FIXME

            return STATUS_INVALID_INFO_CLASS;
        }

        case FileInternalInformation: {
            printk(KERN_INFO "unixfs_query_information: unhandled class FileInternalInformation\n");

            // FIXME

            return STATUS_INVALID_INFO_CLASS;
        }

        case FileEndOfFileInformation: {
            FILE_END_OF_FILE_INFORMATION* feofi = (FILE_END_OF_FILE_INFORMATION*)FileInformation;

            if (Length < sizeof(FILE_END_OF_FILE_INFORMATION))
                return STATUS_BUFFER_TOO_SMALL;

            if (!obj->f->f->f_inode)
                return STATUS_INTERNAL_ERROR;

            feofi->EndOfFile.QuadPart = obj->f->f->f_inode->i_size;

            IoStatusBlock->Information = sizeof(FILE_END_OF_FILE_INFORMATION);

            return STATUS_SUCCESS;
        }

        case FileAllInformation: {
            printk(KERN_INFO "unixfs_query_information: unhandled class FileAllInformation\n");

            // FIXME

            return STATUS_INVALID_INFO_CLASS;
        }

        // FIXME - others not supported by Wine?

        default: {
            printk(KERN_INFO "unixfs_query_information: unhandled class %x\n",
                   FileInformationClass);

            return STATUS_INVALID_INFO_CLASS;
        }
    }
}

static NTSTATUS unixfs_read(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
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

static NTSTATUS unixfs_write(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                             PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                             PULONG Key) {
    ssize_t written;
    loff_t pos;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    // FIXME - FILE_APPEND_DATA

    if (ByteOffset && ByteOffset->HighPart == -1 && ByteOffset->LowPart == FILE_USE_FILE_POINTER_POSITION)
        ByteOffset = NULL;

    if (ByteOffset)
        pos = ByteOffset->QuadPart;
    else if (obj->flags & FO_SYNCHRONOUS_IO)
        pos = obj->offset;
    else
        return STATUS_INVALID_PARAMETER;

    written = kernel_write(obj->f->f, Buffer, Length, &pos);

    if (written < 0) {
        if (obj->flags & FO_SYNCHRONOUS_IO && ByteOffset)
            obj->offset = ByteOffset->QuadPart;

        return muwine_error_to_ntstatus(written);
    }

    if (obj->flags & FO_SYNCHRONOUS_IO)
        obj->offset = pos;

    IoStatusBlock->Information = written;

    return STATUS_SUCCESS;
}

typedef struct {
    struct dir_context dc;
    const char* fn;
    bool found;
} rename_iterate;

static int dir_iterate(struct dir_context* dc, const char* name, int name_len, loff_t pos,
                       u64 ino, unsigned int type) {
    rename_iterate* ri = (rename_iterate*)dc;

    if (strnicmp(name, ri->fn, name_len) || ri->fn[name_len] != 0)
        return 0;

    ri->found = true;

    return -1; // stop iterating
}

static NTSTATUS unixfs_rename(file_object* obj, FILE_RENAME_INFORMATION* fri) {
    NTSTATUS Status;
    ULONG dest_len;
    char* dest;
    char* fn;
    unsigned int i, last_slash;
    struct file* dest_dir;
    int ret;
    struct dentry* new_dentry;
    rename_iterate ri;
    UNICODE_STRING new_path;

    // FIXME - handle POSIX-style deletes
    // FIXME - don't allow if directory with open children

    if (fri->FileNameLength < 2 * sizeof(WCHAR) || fri->FileName[0] != '\\')
        return STATUS_INVALID_PARAMETER;

    Status = utf16_to_utf8(NULL, 0, &dest_len, fri->FileName, fri->FileNameLength);
    if (!NT_SUCCESS(Status))
        return Status;

    dest = kmalloc(dest_len + 1, GFP_KERNEL);
    if (!dest)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = utf16_to_utf8(dest, dest_len, &dest_len, fri->FileName, fri->FileNameLength);
    if (!NT_SUCCESS(Status))
        return Status;

    dest[dest_len] = 0;

    for (i = 0; i < dest_len; i++) {
        if (dest[i] == '\\') {
            dest[i] = '/';
            last_slash = i;
        }
    }

    dest[last_slash] = 0;
    fn = dest + last_slash + 1;

    // FIXME - open case-insensitively
    dest_dir = filp_open(dest, 0, 0);
    if (IS_ERR(dest_dir)) {
        int err = (int)(uintptr_t)dest_dir;

        kfree(dest);

        if (err == -ENOENT)
            return STATUS_OBJECT_PATH_NOT_FOUND;
        else
            return muwine_error_to_ntstatus(err);
    }

    if (obj->f->f->f_inode->i_sb != dest_dir->f_inode->i_sb) { // FIXME
        printk(KERN_ALERT "unixfs_rename: FIXME - handle moving files across filesystems\n");
        filp_close(dest_dir, NULL);
        kfree(dest);
        return STATUS_INTERNAL_ERROR;
    }

    new_dentry = d_alloc_name(file_dentry(dest_dir), fn);
    if (!new_dentry) {
        filp_close(dest_dir, NULL);
        kfree(dest);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    lock_rename(file_dentry(obj->f->f)->d_parent, file_dentry(dest_dir));

    ri.dc.actor = dir_iterate;
    ri.dc.pos = 0;
    ri.fn = fn;
    ri.found = false;

    if (dest_dir->f_op->iterate_shared)
        dest_dir->f_op->iterate_shared(dest_dir, &ri.dc);
    else
        dest_dir->f_op->iterate(dest_dir, &ri.dc);

    if (ri.found) {
        if (!fri->ReplaceIfExists) {
            unlock_rename(file_dentry(obj->f->f)->d_parent, file_dentry(dest_dir));

            d_invalidate(new_dentry);

            filp_close(dest_dir, NULL);

            kfree(dest);


            return STATUS_OBJECT_NAME_COLLISION;
        }

        // FIXME - search FCB list for this inode, and fail if present
        // FIXME - delete (in case file exists but differs by case)
    }

    ret = vfs_rename(file_dentry(obj->f->f)->d_parent->d_inode, file_dentry(obj->f->f), dest_dir->f_inode,
                     new_dentry, NULL, 0);

    unlock_rename(file_dentry(obj->f->f)->d_parent, file_dentry(dest_dir));

    d_invalidate(new_dentry);

    filp_close(dest_dir, NULL);

    kfree(dest);

    if (ret < 0)
        return muwine_error_to_ntstatus(ret);

    spin_lock(&obj->header.path_lock);

    new_path.Length = obj->dev->header.path.Length + fri->FileNameLength;
    new_path.Buffer = kmalloc(new_path.Length, GFP_KERNEL);

    if (!new_path.Buffer) {
        spin_unlock(&obj->header.path_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    kfree(obj->header.path.Buffer);
    obj->header.path = new_path;

    memcpy(obj->header.path.Buffer, obj->dev->header.path.Buffer, obj->dev->header.path.Length);
    memcpy(obj->header.path.Buffer + (obj->dev->header.path.Length / sizeof(WCHAR)),
        fri->FileName, fri->FileNameLength);

    spin_unlock(&obj->header.path_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_set_information(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                       ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    switch (FileInformationClass) {
        case FileRenameInformation: {
            FILE_RENAME_INFORMATION* fri = FileInformation;

            if (Length < offsetof(FILE_RENAME_INFORMATION, FileName))
                return STATUS_INVALID_PARAMETER;

            if (Length < offsetof(FILE_RENAME_INFORMATION, FileName) + fri->FileNameLength)
                return STATUS_INVALID_PARAMETER;

            return unixfs_rename(obj, fri);
        }

        default:
            printk(KERN_INFO "unixfs_set_information: unhandled class %x\n",
                   FileInformationClass);

            return STATUS_INVALID_INFO_CLASS;
    }
}

static NTSTATUS unixfs_query_directory(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                       FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                       PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
    printk(KERN_INFO "unixfs_query_directory(%px, %lx, %px, %px, %px, %px, %x, %x, %x, %px, %x): stub\n",
           obj, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask,
           RestartScan);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static struct file* unixfs_get_filp(file_object* obj) {
    return obj->f->f;
}

static void device_object_close(object_header* obj) {
    device* dev = (device*)obj;

    if (dev->header.path.Buffer)
        kfree(dev->header.path.Buffer);

    kfree(dev);
}

NTSTATUS muwine_init_unixroot(void) {
    NTSTATUS Status;
    device* dev;

    static const WCHAR name[] = L"\\Device\\UnixRoot";

    dev = kzalloc(sizeof(device), GFP_KERNEL);
    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    dev->header.refcount = 1;
    dev->header.type = muwine_object_device;

    spin_lock_init(&dev->header.path_lock);
    dev->header.close = device_object_close;

    dev->header.path.Length = sizeof(name) - sizeof(WCHAR);
    dev->header.path.Buffer = kmalloc(dev->header.path.Length, GFP_KERNEL);
    if (!dev->header.path.Buffer) {
        dev->header.close(&dev->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(dev->header.path.Buffer, name, dev->header.path.Length);

    dev->create = unixfs_create_file;
    dev->read = unixfs_read;
    dev->write = unixfs_write;
    dev->query_information = unixfs_query_information;
    dev->set_information = unixfs_set_information;
    dev->query_directory = unixfs_query_directory;
    dev->get_filp = unixfs_get_filp;

    Status = muwine_add_entry_in_hierarchy(&dev->header.path, &dev->header, true);
    if (!NT_SUCCESS(Status)) {
        dev->header.close(&dev->header);
        return Status;
    }

    return STATUS_SUCCESS;
}
