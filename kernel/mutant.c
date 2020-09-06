#include "muwine.h"
#include "mutant.h"
#include "thread.h"

static type_object* mutant_type = NULL;

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

    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        UNICODE_STRING us;
        bool us_alloc = false;

        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;

        Status = muwine_resolve_obj_symlinks(&us, &us_alloc);
        if (!NT_SUCCESS(Status)) {
            if (us_alloc)
                kfree(us.Buffer);

            goto end;
        }

        if (us.Length < sizeof(WCHAR) || us.Buffer[0] != '\\') {
            if (us_alloc)
                kfree(us.Buffer);

            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        obj->header.h.path.Length = us.Length;
        obj->header.h.path.Buffer = kmalloc(us.Length, GFP_KERNEL);
        if (!obj->header.h.path.Buffer) {
            if (us_alloc)
                kfree(us.Buffer);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        memcpy(obj->header.h.path.Buffer, us.Buffer, us.Length);

        if (us_alloc)
            kfree(us.Buffer);

        Status = muwine_add_entry_in_hierarchy(&obj->header.h.path, &obj->header.h, false,
                                               ObjectAttributes->Attributes & OBJ_PERMANENT);
        if (!NT_SUCCESS(Status))
            goto end;
    }

    Status = muwine_add_handle(&obj->header.h, MutantHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

end:
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return Status;
    }

    return STATUS_SUCCESS;
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
    printk(KERN_INFO "NtOpenMutant(%px, %x, %px): stub\n",
           MutantHandle, DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {
    printk(KERN_INFO "NtReleaseMutant(%lx, %px): stub\n",
           (uintptr_t)MutantHandle, PreviousCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static void mutant_object_close(object_header* obj) {
    mutant_object* mut = (mutant_object*)obj;

    if (mut->thread)
        dec_obj_refcount(&mut->thread->header.h);

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
