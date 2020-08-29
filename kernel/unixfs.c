#include "muwine.h"
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/statfs.h>

#define SECTOR_SIZE 0x1000

typedef struct {
    struct list_head list;
    struct inode* inode;
    unsigned int refcount;
} unixfs_inode;

typedef struct {
    file_object fileobj;
    struct list_head list;
    struct file* f;
    unixfs_inode* inode;
    bool delete_pending;
} unixfs_file_object;

static LIST_HEAD(file_list);
static LIST_HEAD(inode_list);
static DECLARE_RWSEM(file_list_sem);

type_object* device_type = NULL;
type_object* file_type = NULL;

static void free_unixfs_inode(unixfs_inode* ui) {
    if (__sync_sub_and_fetch(&ui->refcount, 1) != 0)
        return;

    list_del(&ui->list);
    kfree(ui);
}

static void file_object_close(object_header* obj) {
    unixfs_file_object* f = (unixfs_file_object*)obj;

    down_write(&file_list_sem);
    list_del(&f->list);
    free_unixfs_inode(f->inode);
    up_write(&file_list_sem);

    filp_close(f->f, NULL);

    if (f->fileobj.query_string.Buffer)
        kfree(f->fileobj.query_string.Buffer);

    dec_obj_refcount(&f->fileobj.dev->header);

    free_object(&f->fileobj.header);
}

static void file_object_cleanup(object_header* obj) {
    unixfs_file_object* ufo = (unixfs_file_object*)obj;

    if (ufo->fileobj.options & FILE_DELETE_ON_CLOSE)
        ufo->delete_pending = true;

    if (ufo->delete_pending) {
        struct inode* parent = file_dentry(ufo->f)->d_parent->d_inode;
        int ret;

        // FIXME - check file not open via another file object

        down_write(&parent->i_rwsem);

        ret = vfs_unlink(parent, file_dentry(ufo->f), NULL);

        up_write(&parent->i_rwsem);

        if (ret < 0)
            printk(KERN_INFO "file_object_cleanup: vfs_unlink returned %d\n", ret);
    }
}

typedef struct {
    struct dir_context dc;
    const char* part;
    unsigned int part_len;
    bool found;
    char* found_part;
    unsigned int found_type;
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
    ofi->found_type = type;

    ofi->found_part = kmalloc(name_len + 1, GFP_KERNEL);
    if (!ofi->found_part)
        return -1;

    memcpy(ofi->found_part, name, name_len);
    ofi->found_part[name_len] = 0;


    return -1; // stop iterating
}

static NTSTATUS open_file(const char* fn, struct file** ret, bool is_rw) {
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

    if (fn[0] == 0) { // root
        *ret = parent;

        return STATUS_SUCCESS;
    }

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

        if (parent->f_op->iterate_shared) {
            int ret = down_read_killable(&parent->f_inode->i_rwsem);

            if (ret < 0) {
                filp_close(parent, NULL);
                return muwine_error_to_ntstatus(ret);
            }

            parent->f_op->iterate_shared(parent, &ofi.dc);
            up_read(&parent->f_inode->i_rwsem);
        } else {
            int ret = down_write_killable(&parent->f_inode->i_rwsem);

            if (ret < 0) {
                filp_close(parent, NULL);
                return muwine_error_to_ntstatus(ret);
            }

            parent->f_op->iterate(parent, &ofi.dc);
            up_write(&parent->f_inode->i_rwsem);
        }

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

        if (ofi.found_type == DT_DIR)
            flags = O_DIRECTORY;
        else if (ofi.found_type == DT_REG)
            flags = is_rw ? O_RDWR : O_RDONLY;

        if (ofi.found_type == DT_REG && is_rw && parent->f_path.mnt->mnt_sb->s_flags & SB_RDONLY) {
            filp_close(parent, NULL);
            return STATUS_MEDIA_WRITE_PROTECTED;
        }

        new_parent = file_open_root(parent->f_path.dentry, parent->f_path.mnt,
                                    ofi.found_part, flags, 0);

        kfree(ofi.found_part);
        filp_close(parent, NULL);

        if (IS_ERR(new_parent)) {
            if (PTR_ERR(new_parent) == -ENOENT) {
                if (fn[ofi.part_len] != 0) {
                    filp_close(parent, NULL);
                    return STATUS_OBJECT_PATH_NOT_FOUND;
                } else {
                    *ret = parent;
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
            }

            return muwine_error_to_ntstatus((int)(uintptr_t)new_parent);
        }

        parent = new_parent;
        fn += ofi.part_len;

        if (fn[0] == 0)
            break;

        fn++;
    } while (true);

    *ret = parent;

    return STATUS_SUCCESS;
}

static NTSTATUS access_check(ACCESS_MASK desired, ACCESS_MASK* granted) {
    // FIXME - compare process token with SD, and return STATUS_ACCESS_DENIED if necessary
    // FIXME - handle MAXIMUM_ALLOWED

    *granted = desired;

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
    unixfs_file_object* obj;
    struct file* file;
    bool name_exists;
    bool is_rw;
    ACCESS_MASK access;
    unixfs_inode* ui = NULL;

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

    access = DesiredAccess;

    if (DesiredAccess & MAXIMUM_ALLOWED)
        access |= file_type->valid;

    is_rw = access & (WRITE_OWNER | WRITE_DAC | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | DELETE |
                      FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD);

    Status = open_file(path, &file, is_rw);

    // FIXME - if MAXIMUM_ALLOWED and FS is readonly, strip out write flags and try again

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

    if (name_exists) {
        Status = access_check(access, &access);

        if (!NT_SUCCESS(Status)) {
            kfree(path);
            filp_close(file, NULL);
            return Status;
        }
    } else
        access = DesiredAccess;

    if (CreateOptions & FILE_DELETE_ON_CLOSE && !(access & DELETE)) {
        kfree(path);
        filp_close(file, NULL);
        return STATUS_ACCESS_DENIED;
    }

    // loop through list of FCBs, and increase refcount if found; otherwise, do filp_open

    // FIXME - if need to create new file, this should be done outside of lock

    // FIXME - don't allow if FILE_DELETE_ON_CLOSE and root directory
    // FIXME - don't allow if FILE_DELETE_ON_CLOSE and non-empty directory?

    down_write(&file_list_sem);

    if (name_exists) {
        le = file_list.next;
        while (le != &file_list) {
            unixfs_file_object* ufo = list_entry(le, unixfs_file_object, list);

            if (ufo->inode->inode == file->f_inode && ufo->f->f_path.dentry == file->f_path.dentry) {
                if (!(ShareAccess & FILE_SHARE_DELETE) && ufo->fileobj.options & FILE_DELETE_ON_CLOSE) {
                    up_write(&file_list_sem);
                    kfree(path);
                    filp_close(file, NULL);
                    return STATUS_DELETE_PENDING;
                }

                if (CreateOptions & FILE_DELETE_ON_CLOSE && ufo->fileobj.mapping_count != 0) {
                    up_write(&file_list_sem);
                    kfree(path);
                    filp_close(file, NULL);
                    return STATUS_CANNOT_DELETE;
                }
            }

            le = le->next;
        }

        le = inode_list.next;
        while (le != &inode_list) {
            unixfs_inode* ui2 = list_entry(le, unixfs_inode, list);

            if (ui2->inode == file->f_inode) {
                if (CreateDisposition == FILE_SUPERSEDE) {
                    up_write(&file_list_sem);
                    kfree(path);
                    filp_close(file, NULL);
                    return STATUS_CANNOT_DELETE;
                }

                __sync_add_and_fetch(&ui2->refcount, 1);
                ui = ui2;
            }

            le = le->next;
        }
    } else {
        struct file* new_file;
        umode_t mode;
        unsigned int pos = as_len - 1;
        const char* fn = path;
        unsigned int flags;

        if (CreateOptions & FILE_DIRECTORY_FILE)
            mode = S_IFDIR | 0755;
        else
            mode = 0644;

        while (pos > 0) {
            if (path[pos] == '/') {
                fn = &path[pos+1];
                break;
            }

            pos--;
        }

        if (file->f_path.mnt->mnt_sb->s_flags & SB_RDONLY) {
            up_write(&file_list_sem);
            kfree(path);
            return STATUS_MEDIA_WRITE_PROTECTED;
        }

        if (CreateOptions & FILE_DIRECTORY_FILE) {
            int ret;
            struct dentry* new_dentry;

            new_dentry = d_alloc_name(file_dentry(file), fn);
            if (!new_dentry) {
                up_write(&file_list_sem);
                kfree(path);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            down_write(&file->f_inode->i_rwsem);
            ret = vfs_mkdir(file->f_inode, new_dentry, mode);
            up_write(&file->f_inode->i_rwsem);

            if (ret < 0) {
                up_write(&file_list_sem);
                d_invalidate(new_dentry);
                kfree(path);
                return muwine_error_to_ntstatus(ret);
            }

            d_invalidate(new_dentry);
        }

        if (CreateOptions & FILE_DIRECTORY_FILE)
            flags = O_DIRECTORY;
        else
            flags = O_CREAT | O_EXCL | O_RDWR;

        // FIXME - check against parent's SD that user has permission for this

        new_file = file_open_root(file->f_path.dentry, file->f_path.mnt,
                                  fn, flags, mode);

        filp_close(file, NULL);

        if (IS_ERR(new_file)) {
            up_write(&file_list_sem);
            kfree(path);
            return muwine_error_to_ntstatus((int)(uintptr_t)new_file);
        }

        file = new_file;

        // FIXME - change uid and gid
    }

    if (!ui) {
        ui = kmalloc(sizeof(unixfs_inode), GFP_KERNEL);

        if (!ui) {
            up_write(&file_list_sem);
            kfree(path);
            filp_close(file, NULL);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ui->inode = file->f_inode;
        ui->refcount = 1;
        list_add(&ui->list, &inode_list);
    }

    up_write(&file_list_sem);

    kfree(path);

    if (name_exists &&
        (CreateDisposition == FILE_SUPERSEDE || CreateDisposition == FILE_OVERWRITE_IF ||
            CreateDisposition == FILE_OVERWRITE)) {
        int ret = vfs_truncate(&file->f_path, 0);

        if (ret < 0) {
            down_write(&file_list_sem);
            free_unixfs_inode(ui);
            up_write(&file_list_sem);
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

    obj = kzalloc(sizeof(unixfs_file_object), GFP_KERNEL);
    if (!obj) {
        down_write(&file_list_sem);
        free_unixfs_inode(ui);
        up_write(&file_list_sem);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->fileobj.header.refcount = 1;
    obj->fileobj.header.type = file_type;
    __sync_add_and_fetch(&file_type->header.refcount, 1);

    spin_lock_init(&obj->fileobj.header.path_lock);
    obj->fileobj.header.path.Length = obj->fileobj.header.path.MaximumLength = us->Length + dev->header.path.Length;
    obj->fileobj.header.path.Buffer = kmalloc(obj->fileobj.header.path.Length, GFP_KERNEL);

    if (!obj->fileobj.header.path.Buffer) {
        dec_obj_refcount(&file_type->header);

        kfree(obj);

        down_write(&file_list_sem);
        free_unixfs_inode(ui);
        up_write(&file_list_sem);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(obj->fileobj.header.path.Buffer, dev->header.path.Buffer, dev->header.path.Length);
    memcpy(&obj->fileobj.header.path.Buffer[dev->header.path.Length / sizeof(WCHAR)], us->Buffer, us->Length);

    obj->f = file;
    obj->fileobj.offset = 0;
    obj->fileobj.dev = dev;
    obj->fileobj.options = CreateOptions;
    obj->inode = ui;

    __sync_add_and_fetch(&dev->header.refcount, 1);

    down_write(&file_list_sem);
    list_add_tail(&obj->list, &file_list);
    up_write(&file_list_sem);

    // return handle

    Status = muwine_add_handle(&obj->fileobj.header, FileHandle, oa_attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status)) {
        down_write(&file_list_sem);
        list_del(&obj->list);
        free_unixfs_inode(ui);
        up_write(&file_list_sem);

        dec_obj_refcount(&obj->fileobj.dev->header);
        dec_obj_refcount(&file_type->header);

        kfree(obj->fileobj.header.path.Buffer);
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

static __inline uint64_t unix_time_to_win(struct timespec64* t) {
    return (t->tv_sec * 10000000) + (t->tv_nsec / 100) + 116444736000000000;
}

static ULONG get_file_attributes(struct file* f) {
    ULONG atts;

    // FIXME - get FileAttributes from xattr if set

    if (S_ISDIR(f->f_inode->i_mode))
        atts = FILE_ATTRIBUTE_DIRECTORY;
    else if (S_ISLNK(f->f_inode->i_mode))
        atts = FILE_ATTRIBUTE_REPARSE_POINT;

    atts |= FILE_ATTRIBUTE_ARCHIVE;

    // FIXME - add FILE_ATTRIBUTE_HIDDEN if dot file

    return atts;
}

static NTSTATUS fill_in_file_basic_information(unixfs_file_object* ufo,
                                               FILE_BASIC_INFORMATION* fbi, LONG* left) {
    if (*left < sizeof(FILE_BASIC_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    if (!ufo->f->f_inode)
        return STATUS_INTERNAL_ERROR;

    fbi->CreationTime.QuadPart = 0; // FIXME?
    fbi->LastAccessTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_atime);
    fbi->LastWriteTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_mtime);
    fbi->ChangeTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_ctime);
    fbi->FileAttributes = get_file_attributes(ufo->f);

    *left -= sizeof(FILE_BASIC_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_standard_information(unixfs_file_object* ufo,
                                                  FILE_STANDARD_INFORMATION* fsi, LONG* left) {
    if (*left < sizeof(FILE_STANDARD_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    if (!ufo->f->f_inode)
        return STATUS_INTERNAL_ERROR;

    fsi->EndOfFile.QuadPart = S_ISREG(ufo->f->f_inode->i_mode) ? ufo->f->f_inode->i_size : 0;
    fsi->AllocationSize.QuadPart = (fsi->EndOfFile.QuadPart + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
    fsi->NumberOfLinks = ufo->f->f_inode->i_nlink;
    fsi->DeletePending = false; // FIXME
    fsi->Directory = S_ISDIR(ufo->f->f_inode->i_mode);

    *left -= sizeof(FILE_STANDARD_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_internal_information(unixfs_file_object* ufo,
                                                  FILE_INTERNAL_INFORMATION* fii, LONG* left) {
    if (*left < sizeof(FILE_INTERNAL_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    if (!ufo->f->f_inode)
        return STATUS_INTERNAL_ERROR;

    fii->IndexNumber.QuadPart = ufo->f->f_inode->i_ino;

    *left -= sizeof(FILE_INTERNAL_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_name_information(unixfs_file_object* ufo, FILE_NAME_INFORMATION* fni,
                                              LONG* left) {
    ULONG name_len, dev_name_len;

    if (*left < offsetof(FILE_NAME_INFORMATION, FileName))
        return STATUS_BUFFER_TOO_SMALL;

    name_len = *left - offsetof(FILE_NAME_INFORMATION, FileName);

    // FIXME - handle fake symlinked drives, like C:

    spin_lock(&ufo->fileobj.dev->header.path_lock);
    dev_name_len = ufo->fileobj.dev->header.path.Length;
    spin_unlock(&ufo->fileobj.dev->header.path_lock);

    spin_lock(&ufo->fileobj.header.path_lock);

    fni->FileNameLength = ufo->fileobj.header.path.Length - dev_name_len;

    if (name_len < fni->FileNameLength) {
        memcpy(fni->FileName, ufo->fileobj.header.path.Buffer + (dev_name_len / sizeof(WCHAR)), name_len);
        spin_unlock(&ufo->fileobj.header.path_lock);

        *left -= offsetof(FILE_NAME_INFORMATION, FileName) + name_len;
        return STATUS_BUFFER_OVERFLOW;
    }

    memcpy(fni->FileName, ufo->fileobj.header.path.Buffer + (dev_name_len / sizeof(WCHAR)), fni->FileNameLength);
    spin_unlock(&ufo->fileobj.header.path_lock);

    *left -= offsetof(FILE_NAME_INFORMATION, FileName) + fni->FileNameLength;

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_eof_information(unixfs_file_object* ufo, FILE_END_OF_FILE_INFORMATION* feofi,
                                             LONG* left) {
    if (*left < sizeof(FILE_END_OF_FILE_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    if (!ufo->f->f_inode)
        return STATUS_INTERNAL_ERROR;

    feofi->EndOfFile.QuadPart = S_ISREG(ufo->f->f_inode->i_mode) ? ufo->f->f_inode->i_size : 0;

    *left -= sizeof(FILE_END_OF_FILE_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_ea_information(unixfs_file_object* ufo, FILE_EA_INFORMATION* feai,
                                            LONG* left) {
    if (*left < sizeof(FILE_EA_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    feai->EaSize = 0; // FIXME

    *left -= sizeof(FILE_EA_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_position_information(unixfs_file_object* ufo,
                                                  FILE_POSITION_INFORMATION* fpi,
                                                  LONG* left) {
    if (*left < sizeof(FILE_POSITION_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    fpi->CurrentByteOffset.QuadPart = ufo->fileobj.offset;

    *left -= sizeof(FILE_POSITION_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_access_information(ACCESS_MASK access,
                                                FILE_ACCESS_INFORMATION* fai,
                                                LONG* left) {
    if (*left < sizeof(FILE_ACCESS_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    fai->AccessFlags = access;

    *left -= sizeof(FILE_ACCESS_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_mode_information(unixfs_file_object* ufo,
                                              FILE_MODE_INFORMATION* fmi,
                                              LONG* left) {
    if (*left < sizeof(FILE_MODE_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    fmi->Mode = ufo->fileobj.options & (FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY |
                                        FILE_NO_INTERMEDIATE_BUFFERING |
                                        FILE_SYNCHRONOUS_IO_ALERT |
                                        FILE_SYNCHRONOUS_IO_NONALERT |
                                        FILE_DELETE_ON_CLOSE);

    *left -= sizeof(FILE_MODE_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_alignment_information(FILE_ALIGNMENT_INFORMATION* fai,
                                                   LONG* left) {
    if (*left < sizeof(FILE_ALIGNMENT_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    // FIXME? Wine uses FILE_WORD_ALIGNMENT here
    fai->AlignmentRequirement = FILE_BYTE_ALIGNMENT;

    *left -= sizeof(FILE_ALIGNMENT_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_all_information(unixfs_file_object* ufo, ACCESS_MASK access,
                                             FILE_ALL_INFORMATION* fai, LONG* left) {
    NTSTATUS Status;

    Status = fill_in_file_basic_information(ufo, &fai->BasicInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_standard_information(ufo, &fai->StandardInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_internal_information(ufo, &fai->InternalInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_ea_information(ufo, &fai->EaInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_access_information(access, &fai->AccessInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_position_information(ufo, &fai->PositionInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_mode_information(ufo, &fai->ModeInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_alignment_information(&fai->AlignmentInformation, left);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = fill_in_file_name_information(ufo, &fai->NameInformation, left);

    return Status;
}

static NTSTATUS fill_in_file_network_open_information(unixfs_file_object* ufo,
                                                      FILE_NETWORK_OPEN_INFORMATION* fnoi,
                                                      LONG* left) {
    if (*left < sizeof(FILE_NETWORK_OPEN_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    fnoi->CreationTime.QuadPart = 0; // FIXME?
    fnoi->LastAccessTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_atime);
    fnoi->LastWriteTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_mtime);
    fnoi->ChangeTime.QuadPart = unix_time_to_win(&ufo->f->f_inode->i_ctime);
    fnoi->EndOfFile.QuadPart = S_ISREG(ufo->f->f_inode->i_mode) ? ufo->f->f_inode->i_size : 0;
    fnoi->AllocationSize.QuadPart = (fnoi->EndOfFile.QuadPart + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
    fnoi->FileAttributes = get_file_attributes(ufo->f);

    *left -= sizeof(FILE_NETWORK_OPEN_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_query_information(file_object* obj, ACCESS_MASK access, PIO_STATUS_BLOCK IoStatusBlock,
                                         PVOID FileInformation, ULONG Length,
                                         FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS Status;
    LONG left = Length;
    unixfs_file_object* ufo = (unixfs_file_object*)obj;

    switch (FileInformationClass) {
        case FileBasicInformation:
            Status = fill_in_file_basic_information(ufo, (FILE_BASIC_INFORMATION*)FileInformation,
                                                    &left);
            break;

        case FileStandardInformation:
            Status = fill_in_file_standard_information(ufo,
                                                       (FILE_STANDARD_INFORMATION*)FileInformation,
                                                       &left);
            break;

        case FileInternalInformation:
            Status = fill_in_file_internal_information(ufo,
                                                       (FILE_INTERNAL_INFORMATION*)FileInformation,
                                                       &left);
            break;

        case FileEaInformation:
            Status = fill_in_file_ea_information(ufo, (FILE_EA_INFORMATION*)FileInformation,
                                                 &left);
            break;

        case FileAccessInformation:
            Status = fill_in_file_access_information(access,
                                                     (FILE_ACCESS_INFORMATION*)FileInformation,
                                                     &left);
            break;

        case FileNameInformation:
            Status = fill_in_file_name_information(ufo, (FILE_NAME_INFORMATION*)FileInformation,
                                                   &left);
            break;

        case FilePositionInformation:
            Status = fill_in_file_position_information(ufo,
                                                       (FILE_POSITION_INFORMATION*)FileInformation,
                                                       &left);
            break;

        case FileModeInformation:
            Status = fill_in_file_mode_information(ufo, (FILE_MODE_INFORMATION*)FileInformation,
                                                   &left);
            break;

        case FileAlignmentInformation:
            Status = fill_in_file_alignment_information((FILE_ALIGNMENT_INFORMATION*)FileInformation,
                                                        &left);
            break;

        case FileAllInformation:
            Status = fill_in_file_all_information(ufo, access,
                                                  (FILE_ALL_INFORMATION*)FileInformation,
                                                  &left);
            break;

        case FileEndOfFileInformation:
            Status = fill_in_file_eof_information(ufo,
                                                  (FILE_END_OF_FILE_INFORMATION*)FileInformation,
                                                  &left);
            break;

        case FileNetworkOpenInformation:
            Status = fill_in_file_network_open_information(ufo,
                                                           (FILE_NETWORK_OPEN_INFORMATION*)FileInformation,
                                                           &left);
            break;

        case FileAttributeTagInformation:
            printk(KERN_INFO "unixfs_query_information: FIXME - FileAttributeTagInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        default: {
            printk(KERN_INFO "unixfs_query_information: unhandled class %x\n",
                   FileInformationClass);

            return STATUS_INVALID_INFO_CLASS;
        }
    }

    IoStatusBlock->Information = Length - left;

    return Status;
}

static NTSTATUS unixfs_read(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                            PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                            PULONG Key) {
    unixfs_file_object* ufo = (unixfs_file_object*)obj;
    ssize_t read;
    loff_t pos;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (ByteOffset && ByteOffset->HighPart == -1 && ByteOffset->LowPart == FILE_USE_FILE_POINTER_POSITION)
        ByteOffset = NULL;

    if (ByteOffset)
        pos = ByteOffset->QuadPart;
    else if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        pos = ufo->fileobj.offset;
    else
        return STATUS_INVALID_PARAMETER;

    read = kernel_read(ufo->f, Buffer, Length, &pos);

    if (read < 0) {
        if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) && ByteOffset)
            ufo->fileobj.offset = ByteOffset->QuadPart;

        return muwine_error_to_ntstatus(read);
    }

    if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        ufo->fileobj.offset = pos;

    IoStatusBlock->Information = read;

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_write(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                             PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                             PULONG Key) {
    unixfs_file_object* ufo = (unixfs_file_object*)obj;
    ssize_t written;
    loff_t pos;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    // FIXME - FILE_APPEND_DATA

    if (ByteOffset && ByteOffset->HighPart == -1 && ByteOffset->LowPart == FILE_USE_FILE_POINTER_POSITION)
        ByteOffset = NULL;

    if (ByteOffset)
        pos = ByteOffset->QuadPart;
    else if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        pos = ufo->fileobj.offset;
    else
        return STATUS_INVALID_PARAMETER;

    written = kernel_write(ufo->f, Buffer, Length, &pos);

    if (written < 0) {
        if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) && ByteOffset)
            ufo->fileobj.offset = ByteOffset->QuadPart;

        return muwine_error_to_ntstatus(written);
    }

    if (ufo->fileobj.options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))
        ufo->fileobj.offset = pos;

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
    unixfs_file_object* ufo = (unixfs_file_object*)obj;
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

    if (ufo->f->f_inode->i_sb != dest_dir->f_inode->i_sb) { // FIXME
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

    lock_rename(file_dentry(ufo->f)->d_parent, file_dentry(dest_dir));

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
            unlock_rename(file_dentry(ufo->f)->d_parent, file_dentry(dest_dir));

            d_invalidate(new_dentry);

            filp_close(dest_dir, NULL);

            kfree(dest);

            return STATUS_OBJECT_NAME_COLLISION;
        }

        // FIXME - search FCB list for this inode, and fail if present
        // FIXME - delete (in case file exists but differs by case)
    }

    ret = vfs_rename(file_dentry(ufo->f)->d_parent->d_inode, file_dentry(ufo->f), dest_dir->f_inode,
                     new_dentry, NULL, 0);

    unlock_rename(file_dentry(ufo->f)->d_parent, file_dentry(dest_dir));

    d_invalidate(new_dentry);

    filp_close(dest_dir, NULL);

    kfree(dest);

    if (ret < 0)
        return muwine_error_to_ntstatus(ret);

    spin_lock(&ufo->fileobj.header.path_lock);

    new_path.Length = ufo->fileobj.dev->header.path.Length + fri->FileNameLength;
    new_path.Buffer = kmalloc(new_path.Length, GFP_KERNEL);

    if (!new_path.Buffer) {
        spin_unlock(&ufo->fileobj.header.path_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    kfree(ufo->fileobj.header.path.Buffer);
    ufo->fileobj.header.path = new_path;

    memcpy(ufo->fileobj.header.path.Buffer, ufo->fileobj.dev->header.path.Buffer, ufo->fileobj.dev->header.path.Length);
    memcpy(ufo->fileobj.header.path.Buffer + (ufo->fileobj.dev->header.path.Length / sizeof(WCHAR)),
        fri->FileName, fri->FileNameLength);

    spin_unlock(&ufo->fileobj.header.path_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_set_information(file_object* obj, ACCESS_MASK access,
                                       PIO_STATUS_BLOCK IoStatusBlock,
                                       PVOID FileInformation, ULONG Length,
                                       FILE_INFORMATION_CLASS FileInformationClass) {
    switch (FileInformationClass) {
        case FileBasicInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileBasicInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileRenameInformation: {
            FILE_RENAME_INFORMATION* fri = FileInformation;

            if (Length < offsetof(FILE_RENAME_INFORMATION, FileName))
                return STATUS_INVALID_PARAMETER;

            if (Length < offsetof(FILE_RENAME_INFORMATION, FileName) + fri->FileNameLength)
                return STATUS_INVALID_PARAMETER;

            return unixfs_rename(obj, fri);
        }

        case FileLinkInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileLinkInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileDispositionInformation: {
            unixfs_file_object* ufo = (unixfs_file_object*)obj;
            FILE_DISPOSITION_INFORMATION* fdi = FileInformation;
            struct list_head* le;

            if (Length < sizeof(FILE_DISPOSITION_INFORMATION))
                return STATUS_INVALID_PARAMETER;

            if (!(access & DELETE))
                return STATUS_ACCESS_DENIED;

            down_write(&file_list_sem);

            le = file_list.next;
            while (le != &file_list) {
                unixfs_file_object* ufo2 = list_entry(le, unixfs_file_object, list);

                if (ufo2->f->f_inode == ufo->f->f_inode &&
                    ufo2->f->f_path.dentry == ufo->f->f_path.dentry &&
                    ufo2->fileobj.mapping_count != 0) {
                    up_write(&file_list_sem);
                    return STATUS_CANNOT_DELETE;
                }

                le = le->next;
            }

            up_write(&file_list_sem);

            ufo->delete_pending = fdi->DeleteFile;

            return STATUS_SUCCESS;
        }

        case FilePositionInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FilePositionInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileEndOfFileInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileEndOfFileInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileCompletionInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileCompletionInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileValidDataLengthInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileValidDataLengthInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileIoCompletionNotificationInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileIoCompletionNotificationInformation\n");
            return STATUS_INVALID_INFO_CLASS;

        case FileIoPriorityHintInformation:
            printk(KERN_INFO "unixfs_set_information: FIXME - FileIoPriorityHintInformation\n");
            return STATUS_INVALID_INFO_CLASS;

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
    ULONG* last_offset;
    struct file* dir_file;
    UNICODE_STRING* pattern_mask;
} query_directory_iterate;

static bool wchar_compare(WCHAR c1, WCHAR c2) {
    // FIXME - do this properly

    if (c1 >= 'a' && c1 <= 'z')
        c1 = c1 - 'a' + 'A';

    if (c2 >= 'a' && c2 <= 'z')
        c2 = c2 - 'a' + 'A';

    return c1 == c2;
}

// adapted from Wine's dll/ntdll/directory.c
static bool match_filename(const UNICODE_STRING* name_str, const UNICODE_STRING* mask_str) {
    const WCHAR* name = name_str->Buffer;
    const WCHAR* mask = mask_str->Buffer;
    const WCHAR* name_end = name + name_str->Length / sizeof(WCHAR);
    const WCHAR* mask_end = mask + mask_str->Length / sizeof(WCHAR);
    const WCHAR* lastjoker = NULL;
    const WCHAR* next_to_retry = NULL;

    while (name < name_end && mask < mask_end) {
        switch (*mask) {
            case '*':
                mask++;

                while (mask < mask_end && *mask == '*') { // Skip consecutive '*'
                    mask++;
                }

                if (mask == mask_end) // end of mask is all '*', so match
                    return true;

                lastjoker = mask;

                // skip to the next match after the joker(s)
                while (name < name_end && wchar_compare(*name, *mask)) {
                    name++;
                }

                next_to_retry = name;
            break;

            case '?':
                mask++;
                name++;
            break;

            default: {
                if (wchar_compare(*name, *mask)) {
                    mask++;
                    name++;

                    if (mask == mask_end) {
                        if (name == name_end)
                            return true;

                        if (lastjoker)
                            mask = lastjoker;
                    }
                } else { // mismatch!
                    if (lastjoker) { // we had an '*', so we can try unlimitedly
                        mask = lastjoker;

                        // this scan sequence was a mismatch, so restart 1 char after the first char we checked last time
                        next_to_retry++;
                        name = next_to_retry;
                    } else
                        return false; // bad luck
                }

                break;
            }
        }
    }

    while (mask < mask_end && (*mask == '.' || *mask == '*')) {
        mask++; // Ignore trailing '.' or '*' in mask
    }

    return name == name_end && mask == mask_end;
}

static int query_directory_iterate_func(struct dir_context* dc, const char* name, int name_len, loff_t pos,
                                        u64 ino, unsigned int type) {
    query_directory_iterate* qdi = (query_directory_iterate*)dc;
    NTSTATUS Status;
    UNICODE_STRING utf16name;
    ULONG dest_len;

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

    if (qdi->pattern_mask && !match_filename(&utf16name, qdi->pattern_mask)) {
        kfree(utf16name.Buffer);
        return 0;
    }

    switch (qdi->type) {
        case FileBothDirectoryInformation: {
            FILE_BOTH_DIR_INFORMATION* fbdi;
            unsigned int nudge = 0;

            if (!qdi->first && (uintptr_t)qdi->buf % 8 != 0) {
                nudge = 8 - ((uintptr_t)qdi->buf % 8);
                qdi->buf += nudge;
            }

            fbdi = qdi->buf;

            if (qdi->length < nudge + offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length) {
                if (qdi->first)
                    qdi->Status = STATUS_BUFFER_TOO_SMALL;

                kfree(utf16name.Buffer);

                return -1;
            }

            memset(fbdi, 0, offsetof(FILE_BOTH_DIR_INFORMATION, FileName));

            if (name_len == 1 && name[0] == '.') {
                fbdi->LastAccessTime.QuadPart = unix_time_to_win(&qdi->dir_file->f_inode->i_atime);
                fbdi->LastWriteTime.QuadPart = unix_time_to_win(&qdi->dir_file->f_inode->i_mtime);
                fbdi->ChangeTime.QuadPart = unix_time_to_win(&qdi->dir_file->f_inode->i_ctime);
            } else if (name_len == 2 && name[0] == '.' && name[1] == '.') {
                struct dentry* parent = dget_parent(qdi->dir_file->f_path.dentry);
                struct inode* inode = d_real_inode(parent);

                fbdi->LastAccessTime.QuadPart = unix_time_to_win(&inode->i_atime);
                fbdi->LastWriteTime.QuadPart = unix_time_to_win(&inode->i_mtime);
                fbdi->ChangeTime.QuadPart = unix_time_to_win(&inode->i_ctime);

                dput(parent);
            } else {
                struct dentry* dentry;
                struct qstr q = QSTR_INIT(name, name_len);

                dentry = d_alloc(file_dentry(qdi->dir_file), &q);
                if (!IS_ERR(dentry)) {
                    struct dentry* old;

                    old = qdi->dir_file->f_inode->i_op->lookup(qdi->dir_file->f_inode, dentry, 0);
                    if (old) {
                        dput(dentry);
                        dentry = old;
                    }

                    if (!IS_ERR(dentry)) {
                        struct inode* inode = d_real_inode(dentry);

                        if (inode) {
                            fbdi->LastAccessTime.QuadPart = unix_time_to_win(&inode->i_atime);
                            fbdi->LastWriteTime.QuadPart = unix_time_to_win(&inode->i_mtime);
                            fbdi->ChangeTime.QuadPart = unix_time_to_win(&inode->i_ctime);

                            if (type == DT_REG) {
                                fbdi->EndOfFile.QuadPart = inode->i_size;
                                fbdi->AllocationSize.QuadPart = (fbdi->EndOfFile.QuadPart + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
                            }
                        }

                        dput(dentry);
                    }
                }
            }

            // FIXME - get FileAttributes from xattr if set

            if (type == DT_DIR)
                fbdi->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            else if (type == DT_LNK)
                fbdi->FileAttributes = FILE_ATTRIBUTE_REPARSE_POINT;

            fbdi->FileAttributes |= FILE_ATTRIBUTE_ARCHIVE;

            if (name[0] == '.' && (name_len >= 3 || (name_len == 2 && name[1] != '.')))
                fbdi->FileAttributes |= FILE_ATTRIBUTE_HIDDEN;

            fbdi->FileNameLength = utf16name.Length;
//             ULONG EaSize; // FIXME - get from xattr
            memcpy(fbdi->FileName, utf16name.Buffer, utf16name.Length);

            if (qdi->last_offset)
                *qdi->last_offset = (uint8_t*)fbdi - (uint8_t*)qdi->last_offset;

            qdi->last_offset = &fbdi->NextEntryOffset;

            qdi->buf = (uint8_t*)qdi->buf + offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length;
            qdi->length -= nudge + offsetof(FILE_BOTH_DIR_INFORMATION, FileName) + utf16name.Length;

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
    unixfs_file_object* ufo = (unixfs_file_object*)obj;
    query_directory_iterate qdi;
    bool initial;

    if (RestartScan) {
        ufo->fileobj.query_dir_offset = 0;

        if (ufo->fileobj.query_string.Buffer) {
            kfree(ufo->fileobj.query_string.Buffer);
            ufo->fileobj.query_string.Buffer = NULL;
        }

        ufo->fileobj.query_string.Length = ufo->fileobj.query_string.MaximumLength = 0;
    }

    if (FileMask && FileMask->Length > 0) {
        if (ufo->fileobj.query_string.Buffer) {
            kfree(ufo->fileobj.query_string.Buffer);
            ufo->fileobj.query_string.Buffer = NULL;
        }

        ufo->fileobj.query_string.Buffer = kmalloc(FileMask->Length, GFP_KERNEL);
        if (!ufo->fileobj.query_string.Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        ufo->fileobj.query_string.Length = ufo->fileobj.query_string.MaximumLength = FileMask->Length;

        memcpy(ufo->fileobj.query_string.Buffer, FileMask->Buffer, FileMask->Length);
    }

    initial = ufo->fileobj.query_dir_offset == 0;

    vfs_llseek(ufo->f, ufo->fileobj.query_dir_offset, SEEK_SET);

    qdi.dc.pos = ufo->fileobj.query_dir_offset;
    qdi.dc.actor = query_directory_iterate_func;
    qdi.buf = FileInformation;
    qdi.length = Length;
    qdi.single_entry = ReturnSingleEntry;
    qdi.type = FileInformationClass;
    qdi.Status = STATUS_SUCCESS;
    qdi.first = true;
    qdi.last_offset = NULL;
    qdi.dir_file = ufo->f;
    qdi.pattern_mask = ufo->fileobj.query_string.Length > 0 ? &ufo->fileobj.query_string : NULL;

    if (ufo->f->f_op->iterate_shared) {
        down_read(&ufo->f->f_inode->i_rwsem);
        ufo->f->f_op->iterate_shared(ufo->f, &qdi.dc);
        up_read(&ufo->f->f_inode->i_rwsem);
    } else {
        down_write(&ufo->f->f_inode->i_rwsem);
        ufo->f->f_op->iterate(ufo->f, &qdi.dc);
        up_write(&ufo->f->f_inode->i_rwsem);
    }

    if (!NT_SUCCESS(qdi.Status))
        return qdi.Status;

    if (qdi.first)
        return initial ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;

    ufo->fileobj.query_dir_offset = qdi.dc.pos;

    IoStatusBlock->Information = Length - qdi.length;

    return STATUS_SUCCESS;
}

static NTSTATUS unixfs_query_volume_info(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                         ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    unixfs_file_object* ufo = (unixfs_file_object*)obj;

    switch (FsInformationClass) {
        case FileFsSizeInformation:
        {
            FILE_FS_SIZE_INFORMATION* ffsi = FsInformation;
            struct kstatfs sfs;
            int ret;

            if (Length < sizeof(FILE_FS_SIZE_INFORMATION))
                return STATUS_BUFFER_TOO_SMALL;

            ret = vfs_statfs(&ufo->f->f_path, &sfs);
            if (ret < 0)
                return muwine_error_to_ntstatus(ret);

            ffsi->TotalAllocationUnits.QuadPart = sfs.f_blocks;
            ffsi->AvailableAllocationUnits.QuadPart = sfs.f_bfree;
            ffsi->SectorsPerAllocationUnit = sfs.f_bsize / 512;
            ffsi->BytesPerSector = 512; // this is what Windows is expecting

            IoStatusBlock->Information = sizeof(FILE_FS_SIZE_INFORMATION);

            return STATUS_SUCCESS;
        }

        case FileFsDeviceInformation:
        {
            FILE_FS_DEVICE_INFORMATION* ffdi = FsInformation;

            if (Length < sizeof(FILE_FS_DEVICE_INFORMATION))
                return STATUS_BUFFER_TOO_SMALL;

            ffdi->DeviceType = FILE_DEVICE_DISK_FILE_SYSTEM; // FIXME - FILE_DEVICE_CD_ROM_FILE_SYSTEM if CD
            ffdi->Characteristics = FILE_DEVICE_IS_MOUNTED;

            // FIXME - set FILE_REMOVABLE_MEDIA if CD or USB (etc.)
            // FIXME - identify remote mounts as well?

            IoStatusBlock->Information = sizeof(FILE_FS_DEVICE_INFORMATION);

            return STATUS_SUCCESS;
        }

        case FileFsAttributeInformation:
            printk("unixfs_query_volume_info: FIXME - FileFsAttributeInformation\n"); // FIXME
            return STATUS_INVALID_INFO_CLASS;

        case FileFsVolumeInformation:
            printk("unixfs_query_volume_info: FIXME - FileFsVolumeInformation\n"); // FIXME
            return STATUS_INVALID_INFO_CLASS;

        case FileFsControlInformation:
            printk("unixfs_query_volume_info: FIXME - FileFsControlInformation\n"); // FIXME
            return STATUS_INVALID_INFO_CLASS;

        case FileFsFullSizeInformation:
            printk("unixfs_query_volume_info: FIXME - FileFsFullSizeInformation\n"); // FIXME
            return STATUS_INVALID_INFO_CLASS;

        case FileFsObjectIdInformation:
            printk("unixfs_query_volume_info: FIXME - FileFsObjectIdInformation\n"); // FIXME
            return STATUS_INVALID_INFO_CLASS;

        default:
            printk("unixfs_query_volume_info: unhandled info class %x\n", FsInformationClass);
            return STATUS_INVALID_INFO_CLASS;
    }
}

static struct file* unixfs_get_filp(file_object* obj) {
    unixfs_file_object* ufo = (unixfs_file_object*)obj;

    return ufo->f;
}

static void device_object_close(object_header* obj) {
    device* dev = (device*)obj;

    free_object(&dev->header);
}

NTSTATUS muwine_init_unixroot(void) {
    NTSTATUS Status;
    device* dev;
    UNICODE_STRING us;

    static const WCHAR name[] = L"\\Device\\UnixRoot";
    static const WCHAR device_name[] = L"Device";
    static const WCHAR file_name[] = L"File";

    us.Length = us.MaximumLength = sizeof(device_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)device_name;

    device_type = muwine_add_object_type(&us, device_object_close, NULL, 0, 0, 0, 0, 0);
    if (IS_ERR(device_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)device_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)device_type);
    }

    us.Length = us.MaximumLength = sizeof(file_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)file_name;

    file_type = muwine_add_object_type(&us, file_object_close, file_object_cleanup,
        STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
        STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE,
        STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_EXECUTE,
        FILE_ALL_ACCESS, FILE_ALL_ACCESS);

    if (IS_ERR(file_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)file_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)file_type);
    }

    dev = kzalloc(sizeof(device), GFP_KERNEL);
    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    dev->header.refcount = 1;

    dev->header.type = device_type;
    __sync_add_and_fetch(&dev->header.type->header.refcount, 1);

    spin_lock_init(&dev->header.path_lock);

    dev->header.path.Length = sizeof(name) - sizeof(WCHAR);
    dev->header.path.Buffer = kmalloc(dev->header.path.Length, GFP_KERNEL);
    if (!dev->header.path.Buffer) {
        dev->header.type->close(&dev->header);
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
        dev->header.type->close(&dev->header);
        return Status;
    }

    return STATUS_SUCCESS;
}
