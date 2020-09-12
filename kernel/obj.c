#include "muwine.h"
#include "obj.h"
#include "reg.h"

static LIST_HEAD(symlink_list);
static DEFINE_SPINLOCK(symlink_list_lock);

static dir_object* dir_root = NULL;
static type_object* type_type = NULL;
static type_object* symlink_type = NULL;

type_object* dir_type = NULL;

static void next_part(UNICODE_STRING* left, UNICODE_STRING* part);

void muwine_free_objs(void) {
    dec_obj_refcount(&dir_root->header);
}

void free_object(object_header* obj) {
    if (obj->path.Buffer)
        kfree(obj->path.Buffer);

    if (obj != &type_type->header)
        dec_obj_refcount(&obj->type->header);

    if (obj->sd)
        kfree(obj->sd);

    kfree(obj);
}

static void type_object_close(object_header* obj) {
    type_object* to = (type_object*)obj;

    if (to->name.Buffer)
        kfree(to->name.Buffer);
}

type_object* muwine_add_object_type(const UNICODE_STRING* name, muwine_close_object close,
                                    muwine_cleanup_object cleanup, uint32_t generic_read,
                                    uint32_t generic_write, uint32_t generic_execute,
                                    uint32_t generic_all, uint32_t valid) {
    type_object* obj;

    obj = (type_object*)muwine_alloc_object(sizeof(type_object), type_type, NULL);
    if (!obj)
        return ERR_PTR(-ENOMEM);

    obj->name.Length = obj->name.MaximumLength = name->Length;

    if (obj->name.Length > 0) {
        obj->name.Buffer = kmalloc(obj->name.Length, GFP_KERNEL);
        if (!obj->name.Buffer) {
            kfree(obj);
            return ERR_PTR(-ENOMEM);
        }

        memcpy(obj->name.Buffer, name->Buffer, name->Length);
    }

    obj->close = close;
    obj->cleanup = cleanup;
    obj->generic_mapping.GenericRead = generic_read;
    obj->generic_mapping.GenericWrite = generic_write;
    obj->generic_mapping.GenericExecute = generic_execute;
    obj->generic_mapping.GenericAll = generic_all;
    obj->valid = valid;

    if (!type_type)
        obj->header.type = obj;

    return obj;
}

NTSTATUS muwine_resolve_obj_symlinks(UNICODE_STRING* us, bool* done_alloc) {
    UNICODE_STRING us2;
    bool alloc = false;
    unsigned int count = 0;

    us2.Buffer = us->Buffer;
    us2.Length = us->Length;

    spin_lock(&symlink_list_lock);

    while (true) {
        struct list_head* le;
        bool found = false;

        le = symlink_list.next;
        while (le != &symlink_list) {
            symlink_cache* sc = list_entry(le, symlink_cache, list);

            if (us2.Length < sc->src.Length) {
                le = le->next;
                continue;
            }

            if (us2.Length > sc->src.Length && us2.Buffer[sc->src.Length / sizeof(WCHAR)] != '\\') {
                le = le->next;
                continue;
            }

            if (wcsnicmp(us2.Buffer, sc->src.Buffer, sc->src.Length / sizeof(WCHAR))) {
                le = le->next;
                continue;
            }

            if (us2.Length == sc->src.Length) {
                WCHAR* buf = kmalloc(sc->dest.Length, GFP_KERNEL); // FIXME - handle malloc failure

                memcpy(buf, sc->dest.Buffer, sc->dest.Length);

                if (alloc)
                    kfree(us2.Buffer);

                us2.Buffer = buf;
                us2.Length = sc->dest.Length;

                alloc = true;
            } else {
                unsigned int newlen = sc->dest.Length + us2.Length - sc->src.Length;
                WCHAR* buf = kmalloc(newlen, GFP_KERNEL); // FIXME - handle malloc failure

                memcpy(buf, sc->dest.Buffer, sc->dest.Length);
                memcpy(&buf[sc->dest.Length / sizeof(WCHAR)],
                       &us2.Buffer[sc->src.Length / sizeof(WCHAR)], us2.Length - sc->src.Length);

                if (alloc)
                    kfree(us2.Buffer);

                us2.Buffer = buf;
                us2.Length = newlen;

                alloc = true;
            }

            found = true;
            break;
        }

        if (!found)
            break;

        count++;

        if (count == 20) { // don't loop too many times
            spin_unlock(&symlink_list_lock);
            kfree(us2.Buffer);
            *done_alloc = false;
            return STATUS_INVALID_PARAMETER;
        }
    }

    spin_unlock(&symlink_list_lock);

    *done_alloc = alloc;

    if (alloc) {
        us->Buffer = us2.Buffer;
        us->Length = us2.Length;
    }

    return STATUS_SUCCESS;
}

NTSTATUS muwine_open_object(const UNICODE_STRING* us, object_header** obj, UNICODE_STRING* after,
                            bool* after_alloc, bool open_parent) {
    NTSTATUS Status;
    UNICODE_STRING us2, left, part;
    dir_object* parent;
    struct list_head* le;
    bool us_alloc = false;

    us2.Length = us->Length;
    us2.Buffer = us->Buffer;

    Status = muwine_resolve_obj_symlinks(&us2, &us_alloc);
    if (!NT_SUCCESS(Status))
        return Status;

    if (us2.Length < sizeof(WCHAR) || us2.Buffer[0] != '\\') {
        if (us_alloc)
            kfree(us2.Buffer);

        return STATUS_INVALID_PARAMETER;
    }

    left.Buffer = &us2.Buffer[1];
    left.Length = us2.Length - sizeof(WCHAR);

    parent = dir_root;
    next_part(&left, &part);

    inc_obj_refcount(&parent->header);

    do {
        dir_object* new_parent = NULL;

        spin_lock(&parent->header.header_lock);
        spin_lock(&parent->children_lock);

        if (parent->header.handle_count > 0 || parent->header.permanent) {
            le = parent->children.next;
            while (le != &parent->children) {
                dir_item* item = list_entry(le, dir_item, list);

                if (item->name_len == part.Length && !wcsnicmp(item->name, part.Buffer, part.Length / sizeof(WCHAR))) {
                    if (left.Length == 0) {
                        if (open_parent) {
                            spin_unlock(&parent->children_lock);
                            spin_unlock(&parent->header.header_lock);

                            *obj = &parent->header;

                            if (us_alloc)
                                kfree(us2.Buffer);

                            *after_alloc = false;

                            after->Buffer = part.Buffer;
                            after->Length = part.Length;

                            return STATUS_SUCCESS;
                        }

                        *obj = item->object;

                        inc_obj_refcount(item->object);

                        spin_unlock(&parent->children_lock);
                        spin_unlock(&parent->header.header_lock);

                        dec_obj_refcount(&parent->header);

                        after->Buffer = NULL;
                        after->Length = 0;

                        *after_alloc = false;

                        return STATUS_SUCCESS;
                    }

                    if (item->object->type != dir_type) {
                        *obj = item->object;

                        inc_obj_refcount(item->object);

                        spin_unlock(&parent->children_lock);
                        spin_unlock(&parent->header.header_lock);

                        dec_obj_refcount(&parent->header);

                        *after_alloc = us_alloc;
                        after->Length = left.Length;

                        if (us_alloc) {
                            after->Buffer = kmalloc(after->Length, GFP_KERNEL);
                            if (!after->Buffer) {
                                kfree(us2.Buffer);
                                return STATUS_INSUFFICIENT_RESOURCES;
                            }

                            memcpy(after->Buffer, left.Buffer, left.Length);

                            kfree(us2.Buffer);
                        } else
                            after->Buffer = left.Buffer;

                        return STATUS_SUCCESS;
                    }

                    inc_obj_refcount(item->object);
                    new_parent = (dir_object*)item->object;

                    break;
                }

                le = le->next;
            }
        }

        if (!new_parent) {
            *obj = &parent->header;

            spin_unlock(&parent->children_lock);
            spin_unlock(&parent->header.header_lock);

            after->Buffer = left.Buffer;
            after->Length = left.Length;

            *after_alloc = us_alloc;
            after->Length = left.Length;

            if (us_alloc) {
                after->Buffer = kmalloc(after->Length, GFP_KERNEL);
                if (!after->Buffer) {
                    kfree(us2.Buffer);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                memcpy(after->Buffer, left.Buffer, left.Length);

                kfree(us2.Buffer);
            } else
                after->Buffer = left.Buffer;

            return STATUS_SUCCESS;
        }

        spin_unlock(&parent->children_lock);
        spin_unlock(&parent->header.header_lock);

        dec_obj_refcount(&parent->header);

        parent = new_parent;
        next_part(&left, &part);
    } while (true);

    dec_obj_refcount(&parent->header);

    if (us_alloc)
        kfree(us2.Buffer);

    return STATUS_INTERNAL_ERROR;
}

static void dir_object_close(object_header* obj) {
    dir_object* dir = (dir_object*)obj;

    while (!list_empty(&dir->children)) {
        dir_item* item = list_entry(dir->children.next, dir_item, list);

        dec_obj_refcount(item->object);

        list_del(&item->list);

        kfree(item);
    }
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

NTSTATUS muwine_add_entry_in_hierarchy(const UNICODE_STRING* us, object_header* obj,
                                       bool do_resolve_symlinks, bool permanent,
                                       object_header** old) {
    NTSTATUS Status;
    UNICODE_STRING us2, left, part;
    dir_object* parent;
    struct list_head* le;
    bool us_alloc;

    us2.Buffer = us->Buffer;
    us2.Length = us->Length;

    if (do_resolve_symlinks) {
        Status = muwine_resolve_obj_symlinks(&us2, &us_alloc);
        if (!NT_SUCCESS(Status))
            return Status;
    } else
        us_alloc = false;

    if (us2.Length < sizeof(WCHAR) || us2.Buffer[0] != '\\') {
        if (us_alloc)
            kfree(us2.Buffer);

        return STATUS_INVALID_PARAMETER;
    }

    left.Buffer = &us2.Buffer[1];
    left.Length = us2.Length - sizeof(WCHAR);

    parent = dir_root;
    next_part(&left, &part);

    inc_obj_refcount(&parent->header);

    do {
        dir_object* new_parent = NULL;

        spin_lock(&parent->children_lock);

        le = parent->children.next;
        while (le != &parent->children) {
            dir_item* item = list_entry(le, dir_item, list);

            if (item->name_len == part.Length && !wcsnicmp(item->name, part.Buffer, part.Length / sizeof(WCHAR))) {
                if (left.Length == 0) {
                    spin_unlock(&parent->children_lock);

                    if (old) {
                        *old = item->object;
                        inc_obj_refcount(item->object);
                    }

                    dec_obj_refcount(&parent->header);

                    if (us_alloc)
                        kfree(us2.Buffer);

                    return STATUS_OBJECT_NAME_COLLISION;
                }

                if (item->object->type != dir_type) {
                    spin_unlock(&parent->children_lock);

                    dec_obj_refcount(&parent->header);

                    if (us_alloc)
                        kfree(us2.Buffer);

                    return STATUS_OBJECT_PATH_INVALID;
                }

                inc_obj_refcount(item->object);
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

                dec_obj_refcount(&parent->header);

                if (us_alloc)
                    kfree(us2.Buffer);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            item->object = obj;
            item->name_len = part.Length;
            memcpy(item->name, part.Buffer, part.Length);

            inc_obj_refcount(obj);
            obj->permanent = permanent;

            list_add_tail(&item->list, &parent->children);

            spin_unlock(&parent->children_lock);

            dec_obj_refcount(&parent->header);

            if (us_alloc)
                kfree(us2.Buffer);

            return STATUS_SUCCESS;
        }

        spin_unlock(&parent->children_lock);

        if (!new_parent)
            break;

        dec_obj_refcount(&parent->header);

        parent = new_parent;
        next_part(&left, &part);
    } while (true);

    dec_obj_refcount(&parent->header);

    if (us_alloc)
        kfree(us2.Buffer);

    return STATUS_OBJECT_PATH_INVALID;
}

NTSTATUS muwine_add_entry_in_hierarchy2(object_header** obj, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us;
    bool us_alloc = false;
    object_header* old;

    if (!ObjectAttributes || !ObjectAttributes->ObjectName)
        return STATUS_SUCCESS;

    us.Length = ObjectAttributes->ObjectName->Length;
    us.Buffer = ObjectAttributes->ObjectName->Buffer;

    Status = muwine_resolve_obj_symlinks(&us, &us_alloc);
    if (!NT_SUCCESS(Status)) {
        if (us_alloc)
            kfree(us.Buffer);

        return Status;
    }

    if (us.Length < sizeof(WCHAR) || us.Buffer[0] != '\\') {
        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INVALID_PARAMETER;
    }

    (*obj)->path.Length = us.Length;
    (*obj)->path.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!(*obj)->path.Buffer) {
        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy((*obj)->path.Buffer, us.Buffer, us.Length);

    if (us_alloc)
        kfree(us.Buffer);

    Status = muwine_add_entry_in_hierarchy(&(*obj)->path, *obj, false,
                                           ObjectAttributes->Attributes & OBJ_PERMANENT,
                                           ObjectAttributes->Attributes & OBJ_OPENIF ? &old : NULL);

    if (Status == STATUS_OBJECT_NAME_COLLISION && ObjectAttributes->Attributes & OBJ_OPENIF && old) {
        // FIXME - check access against object SD

        if ((*obj)->type != old->type) {
            dec_obj_refcount(old);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }

        dec_obj_refcount(*obj);

        *obj = old;

        Status = STATUS_SUCCESS;
    }

    return Status;
}

NTSTATUS NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    dir_object* obj;

    if (!ObjectAttributes || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    obj = (dir_object*)muwine_alloc_object(sizeof(dir_object), dir_type, NULL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    spin_lock_init(&obj->children_lock);
    INIT_LIST_HEAD(&obj->children);

    Status = muwine_add_entry_in_hierarchy2((object_header**)&obj, ObjectAttributes);
    if (!NT_SUCCESS(Status))
        goto end;

    Status = muwine_add_handle(&obj->header, DirectoryHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, 0);

end:
    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&obj->header);

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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateDirectoryObject(&h, DesiredAccess, &oa);

    free_object_attributes(&oa);

    if (put_user(h, DirectoryHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    dir_object* dir;
    ACCESS_MASK access;
    bool after_alloc = false;

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        object_header* obj = get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!obj)
            return STATUS_INVALID_HANDLE;

        if (obj->type != dir_type) {
            dec_obj_refcount(obj);
            return STATUS_INVALID_HANDLE;
        }

        spin_lock(&obj->header_lock);

        us.Length = obj->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&obj->header_lock);
            dec_obj_refcount(obj);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, obj->path.Buffer, obj->path.Length);
        us.Buffer[obj->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(obj->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&obj->header_lock);

        dec_obj_refcount(obj);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    Status = muwine_open_object(&us, (object_header**)&dir, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (dir->header.type != dir_type || after.Length != 0) {
        dec_obj_refcount(&dir->header);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    access = sanitize_access_mask(DesiredAccess, dir_type);

    // FIXME - check against SD

    if (access == MAXIMUM_ALLOWED)
        access = DIRECTORY_ALL_ACCESS; // FIXME - should only be what SD allows

    Status = muwine_add_handle(&dir->header, DirectoryHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&dir->header);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes) {
    HANDLE h;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;

    if (!DirectoryHandle || !ObjectAttributes)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenDirectoryObject(&h, DesiredAccess, &oa);

    free_object_attributes(&oa);

    if (put_user(h, DirectoryHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static void symlink_object_close(object_header* obj) {
    symlink_object* symlink = (symlink_object*)obj;

    if (symlink->dest.Buffer)
        kfree(symlink->dest.Buffer);

    if (symlink->cache) {
        spin_lock(&symlink_list_lock);
        list_del(&symlink->cache->list);
        spin_unlock(&symlink_list_lock);

        kfree(symlink->cache->src.Buffer);
        kfree(symlink->cache->dest.Buffer);
        kfree(symlink->cache);
    }
}

static NTSTATUS add_symlink_cache_entry(UNICODE_STRING* src, UNICODE_STRING* dest,
                                        symlink_cache** cache) {
    symlink_cache* sc;
    unsigned int i;
    struct list_head* le;

    sc = kmalloc(sizeof(symlink_cache), GFP_KERNEL);
    if (!sc)
        return STATUS_INSUFFICIENT_RESOURCES;

    sc->depth = 0;

    for (i = 0; i < src->Length / sizeof(WCHAR); i++) {
        if (src->Buffer[i] == '\\')
            sc->depth++;
    }

    sc->src.Length = src->Length;
    sc->src.Buffer = kmalloc(sc->src.Length, GFP_KERNEL);

    if (!sc->src.Buffer) {
        kfree(sc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(sc->src.Buffer, src->Buffer, src->Length);

    sc->dest.Length = dest->Length;
    sc->dest.Buffer = kmalloc(sc->dest.Length, GFP_KERNEL);

    if (!sc->dest.Buffer) {
        kfree(sc->src.Buffer);
        kfree(sc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(sc->dest.Buffer, dest->Buffer, dest->Length);

    spin_lock(&symlink_list_lock);

    // insert into symlink list, reverse-ordered by depth

    le = symlink_list.next;
    while (le != &symlink_list) {
        symlink_cache* sc2 = list_entry(le, symlink_cache, list);

        if (sc2->depth < sc->depth) {
            list_add(&sc->list, le->prev);

            spin_unlock(&symlink_list_lock);

            *cache = sc;

            return STATUS_SUCCESS;
        }

        le = le->next;
    }

    list_add_tail(&sc->list, &symlink_list);

    spin_unlock(&symlink_list_lock);

    *cache = sc;

    return STATUS_SUCCESS;
}

NTSTATUS NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                    PUNICODE_STRING DestinationName) {
    NTSTATUS Status;
    UNICODE_STRING us;
    symlink_object* obj;
    symlink_cache* cache;
    bool us_alloc = false;

    if (!ObjectAttributes || !ObjectAttributes->ObjectName || !DestinationName || DestinationName->Length < sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    // FIXME - RootDirectory

    us.Length = ObjectAttributes->ObjectName->Length;
    us.Buffer = ObjectAttributes->ObjectName->Buffer;

    Status = muwine_resolve_obj_symlinks(&us, &us_alloc);
    if (!NT_SUCCESS(Status)) {
        if (us_alloc)
            kfree(us.Buffer);

        return Status;
    }

    if (us.Length < sizeof(WCHAR) || us.Buffer[0] != '\\') {
        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INVALID_PARAMETER;
    }

    obj = (symlink_object*)muwine_alloc_object(sizeof(symlink_object), symlink_type, NULL);
    if (!obj) {
        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->header.path.Length = us.Length;
    obj->header.path.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!obj->header.path.Buffer) {
        obj->header.type->close(&obj->header);

        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(obj->header.path.Buffer, us.Buffer, us.Length);

    obj->dest.Length = DestinationName->Length;
    obj->dest.Buffer = kmalloc(obj->dest.Length, GFP_KERNEL);

    if (!obj->dest.Buffer) {
        obj->header.type->close(&obj->header);

        if (us_alloc)
            kfree(us.Buffer);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(obj->dest.Buffer, DestinationName->Buffer, DestinationName->Length);

    Status = add_symlink_cache_entry(&obj->header.path, &obj->dest, &cache);
    if (!NT_SUCCESS(Status)) {
        obj->header.type->close(&obj->header);

        if (us_alloc)
            kfree(us.Buffer);

        return Status;
    }

    obj->cache = cache;

    Status = muwine_add_entry_in_hierarchy(&us, &obj->header, false,
                                           ObjectAttributes->Attributes & OBJ_PERMANENT, NULL);

    if (!NT_SUCCESS(Status)) {
        obj->header.type->close(&obj->header);

        if (us_alloc)
            kfree(us.Buffer);

        return Status;
    }

    if (us_alloc)
        kfree(us.Buffer);

    Status = muwine_add_handle(&obj->header, pHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, 0);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header);
        return Status;
    }

    return STATUS_SUCCESS;
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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    if (!get_user_unicode_string(&dest, DestinationName)) {
        free_object_attributes(&oa);
        return STATUS_ACCESS_VIOLATION;
    }

    Status = NtCreateSymbolicLinkObject(&h, DesiredAccess, &oa, &dest);

    if (DestinationName && dest.Buffer)
        kfree(dest.Buffer);

    free_object_attributes(&oa);

    if (put_user(h, pHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

object_header* muwine_alloc_object(size_t size, type_object* type,
                                   SECURITY_DESCRIPTOR_RELATIVE* sd) {
    object_header* obj;

    obj = kzalloc(size, GFP_KERNEL);
    if (!obj)
        return NULL;

    obj->refcount = 1;
    obj->sd = sd;
    obj->type = type;

    if (type)
        inc_obj_refcount(&type->header);

    spin_lock_init(&obj->header_lock);

    if (type && type->valid & SYNCHRONIZE) { // sync object
        sync_object* sync = (sync_object*)obj;

        spin_lock_init(&sync->sync_lock);
        INIT_LIST_HEAD(&sync->waiters);
    }

    return obj;
}

NTSTATUS muwine_open_object2(const POBJECT_ATTRIBUTES ObjectAttributes, object_header** obj,
                             UNICODE_STRING* ret_after, bool* ret_after_alloc, bool open_parent) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    bool after_alloc = false;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        object_header* dir = get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!dir)
            return STATUS_INVALID_HANDLE;

        if (dir->type != dir_type) {
            dec_obj_refcount(dir);
            return STATUS_INVALID_HANDLE;
        }

        spin_lock(&dir->header_lock);

        us.Length = dir->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&dir->header_lock);
            dec_obj_refcount(dir);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, dir->path.Buffer, dir->path.Length);
        us.Buffer[dir->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(dir->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&dir->header_lock);

        dec_obj_refcount(dir);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    Status = muwine_open_object(&us, obj, &after, &after_alloc, open_parent);

    if (ret_after) {
        ret_after->Length = after.Length;
        ret_after->MaximumLength = after.MaximumLength;
        ret_after->Buffer = after.Buffer;

        *ret_after_alloc = after_alloc;
    } else if (after.Length != 0) {
        dec_obj_refcount(*obj);
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

void object_cleanup(object_header* obj) {
    NTSTATUS Status;
    dir_object* dir;
    UNICODE_STRING after;
    bool after_alloc;
    struct list_head* le;

    if (obj->type->cleanup)
        obj->type->cleanup(obj);

    if (obj->permanent || obj->path.Length == 0 || obj->type == key_type)
        return;

    // remove temporary object from hierarchy

    Status = muwine_open_object(&obj->path, (object_header**)&dir, &after,
                                &after_alloc, true);
    if (!NT_SUCCESS(Status)) {
        printk(KERN_INFO "object_cleanup: muwine_open_object returned %08x\n", Status);
        return;
    }

    if (dir->header.type != dir_type) {
        dec_obj_refcount(&dir->header);
        return;
    }

    spin_lock(&dir->children_lock);

    le = dir->children.next;
    while (le != &dir->children) {
        dir_item* di = list_entry(le, dir_item, list);

        if (di->object == obj) {
            list_del(&di->list);
            break;
        }

        le = le->next;
    }

    spin_unlock(&dir->children_lock);

    dec_obj_refcount(&dir->header);
    dec_obj_refcount(obj);
}

void object_close(object_header* obj) {
    if (obj->type->close)
        obj->type->close(obj);

    free_object(obj);
}

NTSTATUS muwine_init_objdir(void) {
    NTSTATUS Status;
    HANDLE dir, symlink;
    UNICODE_STRING us, us2;
    OBJECT_ATTRIBUTES oa;
    SECURITY_DESCRIPTOR_RELATIVE* sd;

    static const WCHAR device_dir[] = L"\\Device";
    static const WCHAR global_dir[] = L"\\GLOBAL??";
    static const WCHAR kernel_objects[] = L"\\KernelObjects";
    static const WCHAR global_global[] = L"\\GLOBAL??\\Global";
    static const WCHAR qmqm[] = L"\\??";
    static const WCHAR dosdevices[] = L"\\DosDevices";
    static const WCHAR type_name[] = L"Type";
    static const WCHAR dir_name[] = L"Directory";
    static const WCHAR symlink_name[] = L"SymbolicLink";

    us.Length = us.MaximumLength = sizeof(type_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)type_name;

    type_type = muwine_add_object_type(&us, type_object_close, NULL, READ_CONTROL,
                                       READ_CONTROL, READ_CONTROL, OBJECT_TYPE_ALL_ACCESS,
                                       OBJECT_TYPE_ALL_ACCESS);
    if (IS_ERR(type_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)type_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)type_type);
    }

    us.Length = us.MaximumLength = sizeof(dir_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)dir_name;

    dir_type = muwine_add_object_type(&us, dir_object_close, NULL, DIRECTORY_GENERIC_READ,
                                      DIRECTORY_GENERIC_WRITE, DIRECTORY_GENERIC_EXECUTE,
                                      DIRECTORY_ALL_ACCESS, DIRECTORY_ALL_ACCESS);
    if (IS_ERR(dir_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)dir_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)dir_type);
    }

    us.Length = us.MaximumLength = sizeof(symlink_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)symlink_name;

    symlink_type = muwine_add_object_type(&us, symlink_object_close, NULL,
                                          SYMBOLIC_LINK_GENERIC_READ,
                                          SYMBOLIC_LINK_GENERIC_WRITE,
                                          SYMBOLIC_LINK_GENERIC_EXECUTE,
                                          SYMBOLIC_LINK_ALL_ACCESS, SYMBOLIC_LINK_ALL_ACCESS);
    if (IS_ERR(symlink_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)symlink_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)symlink_type);
    }

    sd = create_dir_root_sd();
    if (!sd)
        return -ENOMEM;

    dir_root = (dir_object*)muwine_alloc_object(sizeof(dir_object), dir_type, sd);
    if (!dir_root) {
        kfree(sd);
        return -ENOMEM;
    }

    spin_lock_init(&dir_root->children_lock);
    INIT_LIST_HEAD(&dir_root->children);

    dir_root->header.path.Length = dir_root->header.path.MaximumLength = sizeof(WCHAR);
    dir_root->header.path.Buffer = kmalloc(dir_root->header.path.Length, GFP_KERNEL);

    if (!dir_root->header.path.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    dir_root->header.path.Buffer[0] = '\\';
    dir_root->header.permanent = true;

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

    // create \\KernelObjects dir

    us.Buffer = (WCHAR*)kernel_objects;
    us.Length = us.MaximumLength = sizeof(kernel_objects) - sizeof(WCHAR);

    Status = NtCreateDirectoryObject(&dir, 0, &oa);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(dir);

    // create symlink: \\GLOBAL??\\Global -> \\GLOBAL??

    us.Buffer = (WCHAR*)global_global;
    us.Length = us.MaximumLength = sizeof(global_global) - sizeof(WCHAR);

    us2.Buffer = (WCHAR*)global_dir;
    us2.Length = us.MaximumLength = sizeof(global_dir) - sizeof(WCHAR);

    Status = NtCreateSymbolicLinkObject(&symlink, 0, &oa, &us2);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(symlink);

    // HACK - create symlink: \\?? -> \\GLOBAL??
    // FIXME - this isn't correct. \\?? is actually a pseudo-directory, combining both \\GLOBAL??
    // and the user's session directory

    us.Buffer = (WCHAR*)qmqm;
    us.Length = us.MaximumLength = sizeof(qmqm) - sizeof(WCHAR);

    us2.Buffer = (WCHAR*)global_dir;
    us2.Length = us.MaximumLength = sizeof(global_dir) - sizeof(WCHAR);

    Status = NtCreateSymbolicLinkObject(&symlink, 0, &oa, &us2);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(symlink);

    // create symlink: \\DosDevices -> \\??

    us.Buffer = (WCHAR*)dosdevices;
    us.Length = us.MaximumLength = sizeof(dosdevices) - sizeof(WCHAR);

    us2.Buffer = (WCHAR*)qmqm;
    us2.Length = us.MaximumLength = sizeof(qmqm) - sizeof(WCHAR);

    Status = NtCreateSymbolicLinkObject(&symlink, 0, &oa, &us2);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(symlink);

    return STATUS_SUCCESS;
}
