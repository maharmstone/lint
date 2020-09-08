#include "muwine.h"
#include "mutant.h"
#include "thread.h"

type_object* mutant_type = NULL;

static LIST_HEAD(mutant_list);
static DEFINE_SPINLOCK(mutant_list_lock);

static NTSTATUS NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    NTSTATUS Status;
    mutant_object* obj;
    ACCESS_MASK access;

    access = sanitize_access_mask(DesiredAccess, mutant_type);

    if (access == MAXIMUM_ALLOWED)
        access = MUTANT_ALL_ACCESS;

    // create object

    obj = kzalloc(sizeof(mutant_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.h.refcount = 1;

    obj->header.h.type = mutant_type;
    inc_obj_refcount(&mutant_type->header);

    spin_lock_init(&obj->header.h.path_lock);

    spin_lock_init(&obj->header.sync_lock);
    INIT_LIST_HEAD(&obj->header.waiters);
    obj->header.signalled = !InitialOwner;

    if (InitialOwner) {
        obj->thread = muwine_current_thread_object();
        obj->hold_count = 1;
    }

    spin_lock(&mutant_list_lock);
    list_add(&obj->list, &mutant_list);
    spin_unlock(&mutant_list_lock);

    Status = muwine_add_entry_in_hierarchy2((object_header**)&obj, ObjectAttributes);
    if (!NT_SUCCESS(Status))
        goto end;

    Status = muwine_add_handle(&obj->header.h, MutantHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

    if (NT_SUCCESS(Status) && InitialOwner)
        __sync_add_and_fetch(&obj->thread->mutant_count, 1);

end:
    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!MutantHandle)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes && !get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (ObjectAttributes && oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateMutant(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                            InitialOwner);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, MutantHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    mutant_object* mut;
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

        spin_lock(&obj->path_lock);

        us.Length = obj->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&obj->path_lock);
            dec_obj_refcount(obj);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, obj->path.Buffer, obj->path.Length);
        us.Buffer[obj->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(obj->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&obj->path_lock);

        dec_obj_refcount(obj);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    Status = muwine_open_object(&us, (object_header**)&mut, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (mut->header.h.type != mutant_type || after.Length != 0) {
        dec_obj_refcount(&mut->header.h);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    access = sanitize_access_mask(DesiredAccess, mutant_type);

    // FIXME - check against SD

    if (access == MAXIMUM_ALLOWED)
        access = MUTANT_ALL_ACCESS; // FIXME - should only be what SD allows

    Status = muwine_add_handle(&mut->header.h, MutantHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&mut->header.h);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!MutantHandle || !ObjectAttributes)
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

    Status = NtOpenMutant(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, MutantHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass,
                       PVOID MutantInformation, ULONG MutantInformationLength,
                       PULONG ResultLength) {
    printk(KERN_INFO "NtQueryMutant(%lx, %x, %px, %x, %px): stub\n",
           (uintptr_t)MutantHandle, MutantInformationClass, MutantInformation,
           MutantInformationLength, ResultLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {
    NTSTATUS Status;
    ACCESS_MASK access;
    mutant_object* obj;
    unsigned long flags;
    object_header* old_thread = NULL;

    obj = (mutant_object*)get_object_from_handle(MutantHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.h.type != mutant_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    // FIXME - what permissions do we need for this? SYNCHRONIZE?

    spin_lock_irqsave(&obj->header.sync_lock, flags);

    if (obj->hold_count == 0 || obj->thread->ts != current) {
        spin_unlock_irqrestore(&obj->header.sync_lock, flags);
        Status = STATUS_MUTANT_NOT_OWNED;
        goto end;
    }

    if (PreviousCount)
        *PreviousCount = 1 - obj->hold_count;

    obj->hold_count--;

    if (obj->hold_count == 0) {
        old_thread = &obj->thread->header.h;

        __sync_sub_and_fetch(&obj->thread->mutant_count, 1);

        obj->thread = NULL;
        obj->header.signalled = true;
        signal_object(&obj->header, true, true);
    }

    spin_unlock_irqrestore(&obj->header.sync_lock, flags);

    if (old_thread)
        dec_obj_refcount(old_thread);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {
    NTSTATUS Status;
    LONG count;

    if ((uintptr_t)MutantHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtReleaseMutant(MutantHandle, PreviousCount ? &count : NULL);

    if (PreviousCount && put_user(count, PreviousCount) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

void release_abandoned_mutants(thread_object* t) {
    struct list_head* le;

    spin_lock(&mutant_list_lock);

    le = mutant_list.next;
    while (le != &mutant_list) {
        mutant_object* mut = list_entry(le, mutant_object, list);

        if (mut->thread == t) {
            unsigned long flags;

            spin_lock_irqsave(&mut->header.sync_lock, flags);

            dec_obj_refcount(&t->header.h);

            mut->thread = NULL;
            mut->hold_count = 0;
            mut->header.signalled = true;
            signal_object(&mut->header, true, true);

            spin_unlock_irqrestore(&mut->header.sync_lock, flags);
        }

        le = le->next;
    }

    spin_unlock(&mutant_list_lock);
}

static void mutant_object_close(object_header* obj) {
    mutant_object* mut = (mutant_object*)obj;

    if (mut->thread)
        dec_obj_refcount(&mut->thread->header.h);

    spin_lock(&mutant_list_lock);
    list_del(&mut->list);
    spin_unlock(&mutant_list_lock);

    free_object(&mut->header.h);
}

NTSTATUS muwine_init_mutants(void) {
    UNICODE_STRING us;

    static const WCHAR mutant_name[] = L"Mutant";

    us.Length = us.MaximumLength = sizeof(mutant_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)mutant_name;

    mutant_type = muwine_add_object_type(&us, mutant_object_close, NULL,
                                         MUTANT_GENERIC_READ, MUTANT_GENERIC_WRITE,
                                         MUTANT_GENERIC_EXECUTE, MUTANT_ALL_ACCESS,
                                         MUTANT_ALL_ACCESS);
    if (IS_ERR(mutant_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)mutant_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)mutant_type);
    }

    return STATUS_SUCCESS;
}
