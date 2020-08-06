#include "muwine.h"
#include <linux/namei.h>
#include <linux/fs_struct.h>

#define SECTOR_SIZE 0x1000

typedef struct _fcb {
    struct list_head list;
    unsigned int refcount;
    struct file* f;
    char path[1];
} fcb;

static LIST_HEAD(fcb_list);
static DECLARE_RWSEM(fcb_list_sem);

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

    if (f->query_string.Buffer)
        kfree(f->query_string.Buffer);

    if (__sync_sub_and_fetch(&f->dev->header.refcount, 1) == 0)
        f->dev->header.close(&f->dev->header);

    if (f->header.path.Buffer)
        kfree(f->header.path.Buffer);

    kfree(f);
}

typedef struct {
    struct dir_context dc;
    const char* part;
    unsigned int part_len;
    bool found;
    char* found_part;
} open_file_iterate;

static int open_file_dir_iterate(struct dir_context* dc, const char* name, int name_len, loff_t pos,
                                 u64 ino, unsigned int type) {
    open_file_iterate* ofi = (open_file_iterate*)dc;

    if (name_len == 1 && name[0] == '.')
        return 0;

    if (name_len == 2 && name[0] == '.' && name[1] == '.')
        return 0;

    if (name_len != ofi->part_len)
        return 0;

    if (strnicmp(name, ofi->part, name_len))
        return 0;

    ofi->found = true;

    ofi->found_part = kmalloc(name_len + 1, GFP_KERNEL);
    if (!ofi->found_part)
        return -1;

    memcpy(ofi->found_part, name, name_len);
    ofi->found_part[name_len] = 0;

    return -1; // stop iterating
}

static NTSTATUS open_file(const char* fn, struct file** ret, bool is_dir) {
    struct path root;
    struct file* parent;
    open_file_iterate ofi;

    if (fn[0] == '/')
        fn++;

    task_lock(&init_task);
    get_fs_root(init_task.fs, &root);
    task_unlock(&init_task);

    parent = file_open_root(root.dentry, root.mnt, "", O_DIRECTORY, 0);
    if (IS_ERR(parent))
        return muwine_error_to_ntstatus((int)(uintptr_t)parent);

    ofi.dc.actor = open_file_dir_iterate;

    do {
        struct file* new_parent;
        unsigned int flags;

        ofi.dc.pos = 0;
        ofi.part = fn;
        ofi.part_len = 0;
        ofi.found_part = NULL;
        ofi.found = false;

        while (fn[ofi.part_len] != 0 && fn[ofi.part_len] != '/') {
            ofi.part_len++;
        }

        if (parent->f_op->iterate_shared)
            parent->f_op->iterate_shared(parent, &ofi.dc);
        else
            parent->f_op->iterate(parent, &ofi.dc);

        if (!ofi.found) {
            if (fn[ofi.part_len] != 0) {
                filp_close(parent, NULL);
                return STATUS_OBJECT_PATH_NOT_FOUND;
            } else {
                *ret = parent;
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }

        if (!ofi.found_part) {
            filp_close(parent, NULL);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (fn[ofi.part_len] != 0 || is_dir) // directory
            flags = O_DIRECTORY;
        else
            flags = O_RDWR;

        new_parent = file_open_root(parent->f_path.dentry, parent->f_path.mnt,
                                    ofi.found_part, flags, 0);

        kfree(ofi.found_part);
        filp_close(parent, NULL);

        if (IS_ERR(new_parent))
            return muwine_error_to_ntstatus((int)(uintptr_t)new_parent);

        parent = new_parent;
        fn += ofi.part_len;

        if (fn[0] == 0)
            break;

        fn++;
    } while (true);

    *ret = parent;

    return STATUS_SUCCESS;
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
    struct file* file;
    bool name_exists;

    // FIXME - ADS

    // FIXME - handle symlinks

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

    if (CreateOptions & FILE_DIRECTORY_FILE && CreateDisposition == FILE_SUPERSEDE)
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

    while (as_len > 0 && path[as_len - 1] == '/') {
        as_len--;
    }

    path[as_len] = 0;

    Status = open_file(path, &file, CreateOptions & FILE_DIRECTORY_FILE);

    if (NT_SUCCESS(Status) && CreateDisposition == FILE_CREATE) {
        kfree(path);
        filp_close(file, NULL);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        kfree(path);
        return Status;
    }

    name_exists = Status != STATUS_OBJECT_NAME_NOT_FOUND;

    if (!name_exists && (CreateDisposition == FILE_OPEN || CreateDisposition == FILE_OVERWRITE)) {
        kfree(path);
        filp_close(file, NULL);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (name_exists && CreateOptions & FILE_DIRECTORY_FILE && !S_ISDIR(file->f_inode->i_mode)) {
        kfree(path);
        filp_close(file, NULL);
        return STATUS_NOT_A_DIRECTORY;
    } else if (name_exists && CreateOptions & FILE_NON_DIRECTORY_FILE && S_ISDIR(file->f_inode->i_mode)) {
        kfree(path);
        filp_close(file, NULL);
        return STATUS_FILE_IS_A_DIRECTORY;
    }

    // loop through list of FCBs, and increase refcount if found; otherwise, do filp_open

    // FIXME - if need to create new file, this should be done outside of lock

    down_write(&fcb_list_sem);

    if (name_exists) {
        le = fcb_list.next;
        while (le != &fcb_list) {
            fcb* f2 = list_entry(le, fcb, list);

            if (f2->f->f_inode == file->f_inode) {
                if (CreateDisposition == FILE_SUPERSEDE) {
                    up_write(&fcb_list_sem);
                    kfree(path);
                    filp_close(file, NULL);
                    return STATUS_CANNOT_DELETE;
                }

                f2->refcount++;
                f = f2;
                filp_close(file, NULL);
                break;
            }

            le = le->next;
        }
    }

    if (!name_exists) {
        struct file* new_file;
        umode_t mode = 0644;
        unsigned int pos = as_len - 1;
        const char* fn = path;
        unsigned int flags;

        if (CreateOptions & FILE_DIRECTORY_FILE)
            mode |= S_IFDIR;

        while (pos > 0) {
            if (path[pos] == '/') {
                fn = &path[pos+1];
                break;
            }

            pos--;
        }

        flags = O_CREAT | O_EXCL;

        if (!(CreateOptions & FILE_DIRECTORY_FILE))
            flags |= O_RDWR;

        new_file = file_open_root(file->f_path.dentry, file->f_path.mnt,
                                  fn, flags, mode);

        filp_close(file, NULL);

        if (IS_ERR(new_file)) {
            up_write(&fcb_list_sem);
            kfree(path);
            return muwine_error_to_ntstatus((int)(uintptr_t)new_file);
        }

        file = new_file;

        // FIXME - change uid and gid
    }

    if (!f) {
        f = kmalloc(offsetof(fcb, path) + as_len + 1, GFP_KERNEL);
        if (!f) {
            up_write(&fcb_list_sem);
            kfree(path);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        f->refcount = 1;

        f->f = file;

        memcpy(f->path, path, as_len + 1);

        list_add_tail(&f->list, &fcb_list);
    }

    up_write(&fcb_list_sem);

    kfree(path);

    if (name_exists &&
        (CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE_IF ||
            CreateDisposition == FILE_OVERWRITE)) {
        int ret = vfs_truncate(&file->f_path, 0);

        if (ret < 0) {
            down_write(&fcb_list_sem);

            f->refcount--;

            if (f->refcount == 0) {
                filp_close(f->f, NULL);
                list_del(&f->list);
                kfree(f);
            }

            up_write(&fcb_list_sem);

            return muwine_error_to_ntstatus(ret);
        }
    }

    // FIXME - if supersede, should get rid of xattrs etc.(?)

    // FIXME - check xattr for SD, and check process has permissions for requested access
    // FIXME - check share access

    // FIXME - oplocks
    // FIXME - EAs
    // FIXME - other options

    // create file object (with path)

    obj = kzalloc(sizeof(file_object), GFP_KERNEL);
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

    if (!name_exists)
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

    Status = open_file(dest, &dest_dir, true);

    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        filp_close(dest_dir, NULL);
        kfree(dest);
        return Status;
    } else if (!NT_SUCCESS(Status)) {
        kfree(dest);
        return Status;
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

typedef struct {
    struct dir_context dc;
    void* buf;
    unsigned int length;
    bool single_entry;
    FILE_INFORMATION_CLASS type;
    NTSTATUS Status;
    bool first;
} query_directory_iterate;

static int query_directory_iterate_func(struct dir_context* dc, const char* name, int name_len, loff_t pos,
                                        u64 ino, unsigned int type) {
    query_directory_iterate* qdi = (query_directory_iterate*)dc;
    NTSTATUS Status;
    UNICODE_STRING utf16name;
    ULONG dest_len;

    printk("query_directory_iterate_func(%px, %s, %u, %llu, %llx, %u)\n", dc, name, name_len, pos, ino, type);

    if (qdi->single_entry && !qdi->first)
        return -1;

    Status = utf8_to_utf16(NULL, 0, &dest_len, name, name_len);
    if (!NT_SUCCESS(Status)) {
        qdi->Status = Status;
        return -1;
    }

    utf16name.Length = dest_len;
    utf16name.Buffer = kmalloc(dest_len, GFP_KERNEL);

    if (!utf16name.Buffer) {
        qdi->Status = STATUS_INSUFFICIENT_RESOURCES;
        return -1;
    }

    Status = utf8_to_utf16(utf16name.Buffer, utf16name.Length, &dest_len, name, name_len);
    if (!NT_SUCCESS(Status)) {
        kfree(utf16name.Buffer);
        qdi->Status = Status;
        return -1;
    }

    // FIXME - skip if doesn't match pattern

    switch (qdi->type) {
        case FileBothDirectoryInformation: {
            FILE_BOTH_DIR_INFORMATION* fbdi = qdi->buf;

            if (qdi->length < offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length) {
                if (qdi->first)
                    qdi->Status = STATUS_BUFFER_TOO_SMALL;

                kfree(utf16name.Buffer);

                return -1;
            }

            memset(fbdi, 0, offsetof(FILE_BOTH_DIR_INFORMATION, FileName));

            // FIXME - if not first, align buf to 8-byte boundary

            // FIXME - NextEntryOffset
//             LARGE_INTEGER CreationTime; // FIXME
//             LARGE_INTEGER LastAccessTime; // FIXME
//             LARGE_INTEGER LastWriteTime; // FIXME
//             LARGE_INTEGER ChangeTime; // FIXME
//             LARGE_INTEGER EndOfFile; // FIXME
//             LARGE_INTEGER AllocationSize; // FIXME
//             ULONG FileAttributes; // FIXME
            fbdi->FileNameLength = utf16name.Length;
//             ULONG EaSize; // FIXME
            memcpy(fbdi->FileName, utf16name.Buffer, utf16name.Length);

            qdi->buf = (uint8_t*)qdi->buf + offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length;
            qdi->length -= offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length;

            break;
        }

        default:
            printk(KERN_INFO "query_directory_iterate_func: unhandled class %u\n", qdi->type);
            qdi->Status = STATUS_NOT_IMPLEMENTED;
            return -1;
    }

    qdi->first = false;

    kfree(utf16name.Buffer);

    return 0;
}

static NTSTATUS unixfs_query_directory(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                       PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                       FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                       PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
    query_directory_iterate qdi;
    bool initial;

    printk(KERN_INFO "unixfs_query_directory(%px, %lx, %px, %px, %px, %px, %x, %x, %x, %px, %x): stub\n",
           obj, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask,
           RestartScan);

    if (RestartScan) {
        obj->query_dir_offset = 0;

        if (obj->query_string.Buffer) {
            kfree(obj->query_string.Buffer);
            obj->query_string.Buffer = NULL;
        }
    }

    initial = obj->query_dir_offset == 0;

    qdi.dc.pos = obj->query_dir_offset;
    qdi.dc.actor = query_directory_iterate_func;
    qdi.buf = FileInformation;
    qdi.length = Length;
    qdi.single_entry = true; //ReturnSingleEntry;
    qdi.type = FileInformationClass;
    qdi.Status = STATUS_SUCCESS;
    qdi.first = true;

    if (obj->f->f->f_op->iterate_shared) {
        down_read(&obj->f->f->f_inode->i_rwsem);
        obj->f->f->f_op->iterate_shared(obj->f->f, &qdi.dc);
        up_read(&obj->f->f->f_inode->i_rwsem);
    } else {
        down_write(&obj->f->f->f_inode->i_rwsem);
        obj->f->f->f_op->iterate(obj->f->f, &qdi.dc);
        up_write(&obj->f->f->f_inode->i_rwsem);
    }

    if (!NT_SUCCESS(qdi.Status))
        return qdi.Status;

    if (qdi.first)
        return initial ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;

    obj->query_dir_offset = qdi.dc.pos;

    IoStatusBlock->Information = (uint8_t*)qdi.buf - (uint8_t*)FileInformation;

    printk(KERN_INFO "IoStatusBlock->Information = %lx\n", IoStatusBlock->Information);

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_query_volume_info(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                         ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    printk(KERN_INFO "unixfs_query_volume_info(%px, %px, %px, %x, %x): stub\n", obj,
           IoStatusBlock, FsInformation, Length, FsInformationClass);

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
    dev->query_volume_information = unixfs_query_volume_info;
    dev->get_filp = unixfs_get_filp;

    Status = muwine_add_entry_in_hierarchy(&dev->header.path, &dev->header, true);
    if (!NT_SUCCESS(Status)) {
        dev->header.close(&dev->header);
        return Status;
    }

    return STATUS_SUCCESS;
}
