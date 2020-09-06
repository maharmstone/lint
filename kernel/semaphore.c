#include "muwine.h"
#include "semaphore.h"

type_object* sem_type = NULL;

static NTSTATUS NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount,
                                  LONG MaximumCount) {
    NTSTATUS Status;
    sem_object* obj;
    ACCESS_MASK access;

    access = sanitize_access_mask(DesiredAccess, sem_type);

    if (access == MAXIMUM_ALLOWED)
        access = SEMAPHORE_ALL_ACCESS;

    if (MaximumCount <= 0 || InitialCount > MaximumCount)
        return STATUS_INVALID_PARAMETER;

    // create object

    obj = kzalloc(sizeof(sem_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.h.refcount = 1;

    obj->header.h.type = sem_type;
    inc_obj_refcount(&sem_type->header);

    spin_lock_init(&obj->header.h.path_lock);

    spin_lock_init(&obj->header.sync_lock);
    INIT_LIST_HEAD(&obj->header.waiters);
    obj->count = InitialCount;
    obj->max_count = MaximumCount;
    obj->header.signalled = obj->count > 0;

    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        UNICODE_STRING us;
        bool us_alloc = false;
        object_header* old;

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
                                               ObjectAttributes->Attributes & OBJ_PERMANENT,
                                               ObjectAttributes->Attributes & OBJ_OPENIF ? &old : NULL);

        if (Status == STATUS_OBJECT_NAME_COLLISION && ObjectAttributes->Attributes & OBJ_OPENIF && old) {
            // FIXME - check access against object SD

            dec_obj_refcount(&obj->header.h);

            obj = (sem_object*)old;

            if (obj->header.h.type != sem_type) {
                Status = STATUS_OBJECT_TYPE_MISMATCH;
                goto end;
            }

            Status = STATUS_SUCCESS;
        }

        if (!NT_SUCCESS(Status))
            goto end;
    }

    Status = muwine_add_handle(&obj->header.h, SemaphoreHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

end:
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS user_NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount,
                                LONG MaximumCount) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!SemaphoreHandle)
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

    Status = NtCreateSemaphore(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                               InitialCount, MaximumCount);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, SemaphoreHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    sem_object* sem;
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

    Status = muwine_open_object(&us, (object_header**)&sem, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (sem->header.h.type != sem_type || after.Length != 0) {
        dec_obj_refcount(&sem->header.h);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    access = sanitize_access_mask(DesiredAccess, sem_type);

    // FIXME - check against SD

    if (access == MAXIMUM_ALLOWED)
        access = SEMAPHORE_ALL_ACCESS; // FIXME - should only be what SD allows

    Status = muwine_add_handle(&sem->header.h, SemaphoreHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&sem->header.h);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!SemaphoreHandle || !ObjectAttributes)
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

    Status = NtOpenSemaphore(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, SemaphoreHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtQuerySemaphore(HANDLE SemaphoreHandle,
                          SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
                          PVOID SemaphoreInformation, ULONG SemaphoreInformationLength,
                          PULONG ReturnLength) {
    printk(KERN_INFO "NtQuerySemaphore(%lx, %x, %px, %x, %px): stub\n",
           (uintptr_t)SemaphoreHandle, SemaphoreInformationClass, SemaphoreInformation,
           SemaphoreInformationLength, ReturnLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount) {
    NTSTATUS Status;
    ACCESS_MASK access;
    sem_object* obj;
    unsigned long flags;

    obj = (sem_object*)get_object_from_handle(SemaphoreHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.h.type != sem_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & SEMAPHORE_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    spin_lock_irqsave(&obj->header.sync_lock, flags);

    if (PreviousCount)
        *PreviousCount = obj->count;

    if (obj->count + ReleaseCount > obj->max_count) {
        spin_unlock_irqrestore(&obj->header.sync_lock, flags);
        Status = STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        goto end;
    }

    if (obj->count == 0) {
        unsigned int i;

        obj->count = ReleaseCount;

        for (i = 0; i < ReleaseCount; i++) {
            obj->header.signalled = true;

            signal_object(&obj->header, true, true);

            if (obj->header.signalled) // nothing woken up
                break;
        }

        obj->header.signalled = obj->count > 0;
    } else
        obj->count += ReleaseCount;

    spin_unlock_irqrestore(&obj->header.sync_lock, flags);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount) {
    NTSTATUS Status;
    ULONG count;

    if ((uintptr_t)SemaphoreHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtReleaseSemaphore(SemaphoreHandle, ReleaseCount, PreviousCount ? &count : NULL);

    if (PreviousCount && put_user(count, PreviousCount) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static void sem_object_close(object_header* obj) {
    sem_object* sem = (sem_object*)obj;

    free_object(&sem->header.h);
}

NTSTATUS muwine_init_semaphores(void) {
    UNICODE_STRING us;

    static const WCHAR sem_name[] = L"Semaphore";

    us.Length = us.MaximumLength = sizeof(sem_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)sem_name;

    sem_type = muwine_add_object_type(&us, sem_object_close, NULL,
                                      SEMAPHORE_GENERIC_READ, SEMAPHORE_GENERIC_WRITE,
                                      SEMAPHORE_GENERIC_EXECUTE, SEMAPHORE_ALL_ACCESS,
                                      SEMAPHORE_ALL_ACCESS);
    if (IS_ERR(sem_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)sem_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)sem_type);
    }

    return STATUS_SUCCESS;
}
