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

dir_object dir_root;

static void next_part(UNICODE_STRING* left, UNICODE_STRING* part);

void muwine_free_objs(void) {
    if (__sync_sub_and_fetch(&dir_root.header.refcount, 1) == 0)
        dir_root.header.close(&dir_root.header);
}

NTSTATUS muwine_open_object(const UNICODE_STRING* us, object_header** obj, UNICODE_STRING* after) {
    UNICODE_STRING left, part;
    dir_object* parent;
    struct list_head* le;

    if (us->Length < sizeof(WCHAR) || us->Buffer[0] != '\\')
        return STATUS_INVALID_PARAMETER;

    // FIXME - resolve symlinks

    left.Buffer = &us->Buffer[1];
    left.Length = us->Length - sizeof(WCHAR);

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
                    *obj = item->object;

                    __sync_add_and_fetch(&item->object->refcount, 1);

                    spin_unlock(&parent->children_lock);

                    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                        parent->header.close(&parent->header);

                    after->Buffer = NULL;
                    after->Length = 0;

                    return STATUS_SUCCESS;
                }

                if (item->object->type != muwine_object_directory) {
                    *obj = item->object;

                    __sync_add_and_fetch(&item->object->refcount, 1);

                    spin_unlock(&parent->children_lock);

                    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                        parent->header.close(&parent->header);

                    after->Buffer = left.Buffer;
                    after->Length = left.Length;

                    return STATUS_SUCCESS;
                }

                __sync_add_and_fetch(&item->object->refcount, 1);
                new_parent = (dir_object*)item->object;

                break;
            }

            le = le->next;
        }

        if (!new_parent) {
            *obj = &parent->header;

            spin_unlock(&parent->children_lock);

            after->Buffer = left.Buffer;
            after->Length = left.Length;

            return STATUS_SUCCESS;
        }

        spin_unlock(&parent->children_lock);

        if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
            parent->header.close(&parent->header);

        parent = new_parent;
        next_part(&left, &part);
    } while (true);

    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
        parent->header.close(&parent->header);

    return STATUS_INTERNAL_ERROR;
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

NTSTATUS muwine_add_entry_in_hierarchy(const UNICODE_STRING* us, object_header* obj) {
    UNICODE_STRING left, part;
    dir_object* parent;
    struct list_head* le;

    if (us->Length < sizeof(WCHAR) || us->Buffer[0] != '\\')
        return STATUS_INVALID_PARAMETER;

    // FIXME - resolve symlinks

    left.Buffer = &us->Buffer[1];
    left.Length = us->Length - sizeof(WCHAR);

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
            dir_item* item;

            item = kmalloc(offsetof(dir_item, name) + part.Length, GFP_KERNEL);
            if (!item) {
                spin_unlock(&parent->children_lock);

                if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                    parent->header.close(&parent->header);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            item->object = obj;
            item->name_len = part.Length;
            memcpy(item->name, part.Buffer, part.Length);

            __sync_add_and_fetch(&obj->refcount, 1);

            list_add_tail(&item->list, &parent->children);

            spin_unlock(&parent->children_lock);

            if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
                parent->header.close(&parent->header);

            return STATUS_SUCCESS;
        }

        spin_unlock(&parent->children_lock);

        if (!new_parent)
            break;

        if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
            parent->header.close(&parent->header);

        parent = new_parent;
        next_part(&left, &part);
    } while (true);

    if (__sync_sub_and_fetch(&parent->header.refcount, 1) == 0)
        parent->header.close(&parent->header);

    return STATUS_OBJECT_PATH_INVALID;
}

NTSTATUS NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us;
    dir_object* obj;

    if (!ObjectAttributes || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    // FIXME - RootDirectory

    us.Length = ObjectAttributes->ObjectName->Length;
    us.Buffer = ObjectAttributes->ObjectName->Buffer;

    obj = kzalloc(sizeof(dir_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    init_dir(obj);

    obj->header.path.Length = us.Length;
    obj->header.path.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!obj->header.path.Buffer) {
        obj->header.close(&obj->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(obj->header.path.Buffer, us.Buffer, us.Length);

    Status = muwine_add_entry_in_hierarchy(&us, &obj->header);

    if (!NT_SUCCESS(Status)) {
        obj->header.close(&obj->header);
        return Status;
    }

    Status = muwine_add_handle(&obj->header, DirectoryHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE);

    if (!NT_SUCCESS(Status)) {
        if (__sync_sub_and_fetch(&obj->header.refcount, 1) == 0)
            obj->header.close(&obj->header);

        return Status;
    }

    return STATUS_SUCCESS;
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
    static const WCHAR global_dir[] = L"\\GLOBAL??";

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
    oa.Attributes = OBJ_KERNEL_HANDLE | OBJ_PERMANENT;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateDirectoryObject(&dir, 0, &oa);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(dir);

    // create \\GLOBAL?? dir

    us.Buffer = (WCHAR*)global_dir;
    us.Length = us.MaximumLength = sizeof(global_dir) - sizeof(WCHAR);

    Status = NtCreateDirectoryObject(&dir, 0, &oa);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(dir);

    return STATUS_SUCCESS;
}
