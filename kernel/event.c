#include "muwine.h"
#include "event.h"

static type_object* event_type = NULL;

static NTSTATUS NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                              BOOLEAN InitialState) {
    NTSTATUS Status;
    event_object* obj;
    ACCESS_MASK access;

    access = sanitize_access_mask(DesiredAccess, event_type);

    if (access == MAXIMUM_ALLOWED)
        access = EVENT_ALL_ACCESS;

    if (EventType != SynchronizationEvent && EventType != NotificationEvent)
        return STATUS_INVALID_PARAMETER;

    // create object

    obj = kzalloc(sizeof(event_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.h.refcount = 1;

    obj->header.h.type = event_type;
    inc_obj_refcount(&event_type->header);

    spin_lock_init(&obj->header.h.path_lock);

    spin_lock_init(&obj->header.sync_lock);
    INIT_LIST_HEAD(&obj->header.waiters);
    obj->header.signalled = InitialState;

    obj->type = EventType;

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

    Status = muwine_add_handle(&obj->header.h, EventHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

end:
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS user_NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                            BOOLEAN InitialState) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!EventHandle)
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

    Status = NtCreateEvent(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                           EventType, InitialState);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, EventHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    event_object* ev;
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

    Status = muwine_open_object(&us, (object_header**)&ev, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (ev->header.h.type != event_type || after.Length != 0) {
        dec_obj_refcount(&ev->header.h);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    access = sanitize_access_mask(DesiredAccess, event_type);

    // FIXME - check against SD

    if (access == MAXIMUM_ALLOWED)
        access = EVENT_ALL_ACCESS; // FIXME - should only be what SD allows

    Status = muwine_add_handle(&ev->header.h, EventHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&ev->header.h);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!EventHandle || !ObjectAttributes)
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

    Status = NtOpenEvent(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, EventHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {
    printk(KERN_INFO "NtSetEvent(%lx, %px): stub\n", (uintptr_t)EventHandle,
           PreviousState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtResetEvent(HANDLE EventHandle, PLONG PreviousState) {
    printk(KERN_INFO "NtResetEvent(%lx, %px): stub\n", (uintptr_t)EventHandle,
           PreviousState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtClearEvent(HANDLE EventHandle) {
    printk(KERN_INFO "NtClearEvent(%lx): stub\n", (uintptr_t)EventHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtPulseEvent(HANDLE EventHandle, PLONG PreviousState) {
    printk(KERN_INFO "NtPulseEvent(%lx, %px): stub\n", (uintptr_t)EventHandle,
           PreviousState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass,
                      PVOID EventInformation, ULONG EventInformationLength,
                      PULONG ReturnLength) {
    printk(KERN_INFO "NtQueryEvent(%lx, %x, %px, %x, %px): stub\n", (uintptr_t)EventHandle,
           EventInformationClass, EventInformation, EventInformationLength,
           ReturnLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static void event_object_close(object_header* obj) {
    event_object* ev = (event_object*)obj;

    free_object(&ev->header.h);
}

NTSTATUS muwine_init_events(void) {
    UNICODE_STRING us;

    static const WCHAR event_name[] = L"Event";

    us.Length = us.MaximumLength = sizeof(event_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)event_name;

    event_type = muwine_add_object_type(&us, event_object_close, NULL,
                                        EVENT_GENERIC_READ, EVENT_GENERIC_WRITE,
                                        EVENT_GENERIC_EXECUTE, EVENT_ALL_ACCESS,
                                        EVENT_ALL_ACCESS);
    if (IS_ERR(event_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)event_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)event_type);
    }

    return STATUS_SUCCESS;
}
