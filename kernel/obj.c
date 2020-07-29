#include "muwine.h"

typedef struct {
    struct list_head list;
    object_header* object;
    unsigned int name_len;
    WCHAR name[1];
} dir_item;

typedef struct {
    object_header header;
    spinlock_t children_lock;
    struct list_head children;
} dir_object;

LIST_HEAD(dev_list);
DEFINE_SPINLOCK(dev_list_lock);

dir_object dir_root;

NTSTATUS muwine_add_device(device* dev) {
    // FIXME - calculate depth
    // FIXME - store devices in reverse order of depth

    spin_lock(&dev_list_lock);
    list_add_tail(&dev->list, &dev_list);
    spin_unlock(&dev_list_lock);

    return STATUS_SUCCESS;
}

void muwine_free_objs(void) {
    spin_lock(&dev_list_lock);

    while (!list_empty(&dev_list)) {
        device* dev = list_entry(dev_list.next, device, list);

        list_del(&dev->list);

        kfree(dev->path.Buffer);
        kfree(dev);
    }

    spin_unlock(&dev_list_lock);

    if (__sync_sub_and_fetch(&dir_root.header.refcount, 1) == 0)
        dir_root.header.close(&dir_root.header);
}

NTSTATUS muwine_find_device(UNICODE_STRING* us, device** dev) {
    struct list_head* le;

    // FIXME - resolve symlinks

    spin_lock(&dev_list_lock);

    le = dev_list.next;
    while (le != &dev_list) {
        device* d = list_entry(le, device, list);

        if (us->Length < d->path.Length) {
            le = le->next;
            continue;
        }

        if (wcsnicmp(us->Buffer, d->path.Buffer, d->path.Length / sizeof(WCHAR))) {
            le = le->next;
            continue;
        }

        if (us->Length > d->path.Length && us->Buffer[d->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        us->Buffer += d->path.Length / sizeof(WCHAR);
        us->Length -= d->path.Length;

        *dev = d;

        spin_unlock(&dev_list_lock);

        return STATUS_SUCCESS;
    }

    spin_unlock(&dev_list_lock);

    return STATUS_OBJECT_PATH_NOT_FOUND;
}

static void dir_object_close(object_header* obj) {
    dir_object* dir = (dir_object*)obj;

    while (!list_empty(&dir->children)) {
        dir_item* item = list_entry(dir->children.next, dir_item, list);

        if (__sync_sub_and_fetch(&item->object->refcount, 1) == 0)
            item->object->close(item->object);

        list_del(&item->list);

        kfree(item);
    }

    if (dir->header.path.Buffer)
        kfree(dir->header.path.Buffer);

    if (dir != &dir_root)
        kfree(dir);
}

static void init_dir(dir_object* dir) {
    dir->header.refcount = 1;
    dir->header.type = muwine_object_directory;

    spin_lock_init(&dir->header.path_lock);
    dir->header.close = dir_object_close;

    spin_lock_init(&dir->children_lock);
    INIT_LIST_HEAD(&dir->children);
}

static void next_part(UNICODE_STRING* left, UNICODE_STRING* part) {
    unsigned int i;

    while (left->Length >= sizeof(WCHAR) && left->Buffer[0] == '\\') {
        left->Buffer++;
        left->Length -= sizeof(WCHAR);
    }

    if (left->Length == 0) {
        part->Buffer = NULL;
        part->Length = 0;
        return;
    }

    for (i = 0; i < left->Length / sizeof(WCHAR); i++) {
        if (left->Buffer[i] == '\\') {
            part->Buffer = left->Buffer;
            part->Length = i * sizeof(WCHAR);

            left->Buffer = &left->Buffer[i];
            left->Length -= i * sizeof(WCHAR);

            return;
        }
    }

    part->Buffer = left->Buffer;
    part->Length = left->Length;
    left->Buffer = NULL;
    left->Length = 0;
}

NTSTATUS NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    UNICODE_STRING us, left, part;
    dir_object* parent;
    struct list_head* le;

    if (!ObjectAttributes || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    // FIXME - RootDirectory

    us.Length = ObjectAttributes->ObjectName->Length;
    us.Buffer = ObjectAttributes->ObjectName->Buffer;

    if (us.Length < sizeof(WCHAR) || us.Buffer[0] != '\\')
        return STATUS_INVALID_PARAMETER;

    // FIXME - resolve symlinks

    left.Buffer = &us.Buffer[1];
    left.Length = us.Length - sizeof(WCHAR);

    parent = &dir_root;
    next_part(&left, &part);

    __sync_add_and_fetch(&parent->header.refcount, 1);

    do {
        dir_object* new_parent = NULL;

        spin_lock(&parent->children_lock);

        le = parent->children.next;
        while (le != &parent->children) {
            dir_item* item = list_entry(le, dir_item, list);

            if (item->name_len == part.Length && !wcsnicmp(item->name, part.Buffer, part.Length / sizeof(WCHAR))) {
                if (left.Length == 0) {
                    spin_unlock(&parent->children_lock);

                    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                        parent->header.close(&parent->header);

                    return STATUS_OBJECT_NAME_COLLISION;
                }

                if (item->object->type != muwine_object_directory) {
                    spin_unlock(&parent->children_lock);

                    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                        parent->header.close(&parent->header);

                    return STATUS_OBJECT_PATH_INVALID;
                }

                __sync_add_and_fetch(&item->object->refcount, 1);
                new_parent = (dir_object*)item->object;

                break;
            }

            le = le->next;
        }

        if (!new_parent && left.Length == 0) {
            NTSTATUS Status;
            dir_object* obj = kzalloc(sizeof(dir_object), GFP_KERNEL);
            dir_item* item;

            if (!obj) {
                spin_unlock(&parent->children_lock);

                if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                    parent->header.close(&parent->header);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            init_dir(obj);

            obj->header.path.Length = us.Length;
            obj->header.path.Buffer = kmalloc(us.Length, GFP_KERNEL);
            if (!obj->header.path.Buffer) {
                obj->header.close(&obj->header);

                spin_unlock(&parent->children_lock);

                if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                    parent->header.close(&parent->header);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            memcpy(obj->header.path.Buffer, us.Buffer, us.Length);

            item = kmalloc(offsetof(dir_item, name) + part.Length, GFP_KERNEL);
            if (!item) {
                obj->header.close(&obj->header);

                spin_unlock(&parent->children_lock);

                if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                    parent->header.close(&parent->header);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            obj->header.refcount++; // for handle

            item->object = &obj->header;
            item->name_len = part.Length;
            memcpy(item->name, part.Buffer, part.Length);

            list_add_tail(&item->list, &parent->children);

            spin_unlock(&parent->children_lock);

            if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                parent->header.close(&parent->header);

            Status = muwine_add_handle(&obj->header, DirectoryHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE);

            if (!NT_SUCCESS(Status)) {
                if (__sync_sub_and_fetch(&obj->header.refcount, 1) == 0)
                    obj->header.close(&obj->header);

                return Status;
            }

            return STATUS_SUCCESS;
        }

        spin_unlock(&parent->children_lock);

        if (!new_parent)
            break;

        if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
            parent->header.close(&parent->header);

        parent = new_parent;
    } while (true);

    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
        parent->header.close(&parent->header);

    return STATUS_OBJECT_PATH_INVALID;
}

NTSTATUS user_NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!DirectoryHandle || !ObjectAttributes)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateDirectoryObject(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, DirectoryHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                    PUNICODE_STRING DestinationName) {
    printk(KERN_INFO "NtCreateSymbolicLinkObject(%lx, %x, %px, %px): stub\n", (uintptr_t)pHandle, DesiredAccess,
           ObjectAttributes, DestinationName);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                         PUNICODE_STRING DestinationName) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING dest;

    if (!pHandle || !ObjectAttributes || !DestinationName)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    if (!get_user_unicode_string(&dest, DestinationName)) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_ACCESS_VIOLATION;
    }

    Status = NtCreateSymbolicLinkObject(&h, DesiredAccess, &oa, &dest);

    if (DestinationName && dest.Buffer)
        kfree(dest.Buffer);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, pHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS muwine_init_objdir(void) {
    NTSTATUS Status;
    HANDLE dir;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;

    static const WCHAR device_dir[] = L"\\Device";

    init_dir(&dir_root);

    dir_root.header.path.Length = dir_root.header.path.MaximumLength = sizeof(WCHAR);
    dir_root.header.path.Buffer = kmalloc(dir_root.header.path.Length, GFP_KERNEL);

    if (!dir_root.header.path.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    dir_root.header.path.Buffer[0] = '\\';

    // create \\Device dir

    us.Buffer = (WCHAR*)device_dir;
    us.Length = us.MaximumLength = sizeof(device_dir) - sizeof(WCHAR);

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_KERNEL_HANDLE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateDirectoryObject(&dir, 0, &oa);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(dir);

    return STATUS_SUCCESS;
}
