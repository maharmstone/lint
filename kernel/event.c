#include "muwine.h"
#include "event.h"

static type_object* event_type = NULL;

static NTSTATUS NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                              BOOLEAN InitialState) {
    NTSTATUS Status;
    event_object* obj;
    ACCESS_MASK access;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    object_header* parent = NULL;
    token_object* token;

    Status = access_check_type(event_type, DesiredAccess, &access);
    if (!NT_SUCCESS(Status))
        return Status;

    if (EventType != SynchronizationEvent && EventType != NotificationEvent)
        return STATUS_INVALID_PARAMETER;

    // create object

    if (ObjectAttributes && ObjectAttributes->ObjectName) {
        Status = muwine_open_object2(ObjectAttributes, &parent, NULL, NULL, true);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    token = muwine_get_current_token();

    Status = muwine_create_sd(parent,
                              ObjectAttributes ? ObjectAttributes->SecurityDescriptor : NULL,
                              token, &event_type->generic_mapping, 0, false, &sd, NULL);

    if (parent)
        dec_obj_refcount(parent);

    if (token)
        dec_obj_refcount((object_header*)token);

    if (!NT_SUCCESS(Status))
        return Status;

    obj = (event_object*)muwine_alloc_object(sizeof(event_object), event_type, sd);
    if (!obj) {
        kfree(sd);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->header.signalled = InitialState;

    obj->type = EventType;
    spin_lock_init(&obj->lock);

    Status = muwine_add_entry_in_hierarchy2((object_header**)&obj, ObjectAttributes);
    if (!NT_SUCCESS(Status))
        goto end;

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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateEvent(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                           EventType, InitialState);

    if (ObjectAttributes)
        free_object_attributes(&oa);

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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenEvent(&h, DesiredAccess, &oa);

    free_object_attributes(&oa);

    if (put_user(h, EventHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    ACCESS_MASK access;
    event_object* obj;

    obj = (event_object*)get_object_from_handle(EventHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.h.type != event_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & EVENT_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (obj->type == NotificationEvent) {
        spin_lock(&obj->lock);

        if (PreviousState)
            *PreviousState = obj->header.signalled;

        obj->header.signalled = true;

        spin_unlock(&obj->lock);
    } else {
        if (PreviousState)
            *PreviousState = false;
    }

    signal_object(&obj->header, obj->type == SynchronizationEvent, false);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    LONG state;

    if ((uintptr_t)EventHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtSetEvent(EventHandle, PreviousState ? &state : NULL);

    if (PreviousState && put_user(state, PreviousState) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtResetEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    ACCESS_MASK access;
    event_object* obj;

    obj = (event_object*)get_object_from_handle(EventHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.h.type != event_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & EVENT_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    spin_lock(&obj->lock);

    if (PreviousState)
        *PreviousState = obj->header.signalled;

    obj->header.signalled = false;

    spin_unlock(&obj->lock);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtResetEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    LONG state;

    if ((uintptr_t)EventHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtResetEvent(EventHandle, PreviousState ? &state : NULL);

    if (PreviousState && put_user(state, PreviousState) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtClearEvent(HANDLE EventHandle) {
    return NtResetEvent(EventHandle, NULL);
}

NTSTATUS user_NtClearEvent(HANDLE EventHandle) {
    if ((uintptr_t)EventHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    return NtClearEvent(EventHandle);
}

static NTSTATUS NtPulseEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    ACCESS_MASK access;
    event_object* obj;

    obj = (event_object*)get_object_from_handle(EventHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.h.type != event_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & EVENT_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (obj->type == NotificationEvent) {
        spin_lock(&obj->lock);

        if (PreviousState)
            *PreviousState = obj->header.signalled;

        obj->header.signalled = false;

        spin_unlock(&obj->lock);
    } else {
        if (PreviousState)
            *PreviousState = false;
    }

    signal_object(&obj->header, obj->type == SynchronizationEvent, false);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtPulseEvent(HANDLE EventHandle, PLONG PreviousState) {
    NTSTATUS Status;
    LONG state;

    if ((uintptr_t)EventHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtPulseEvent(EventHandle, PreviousState ? &state : NULL);

    if (PreviousState && put_user(state, PreviousState) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
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

NTSTATUS muwine_init_events(void) {
    UNICODE_STRING us;

    static const WCHAR event_name[] = L"Event";

    us.Length = us.MaximumLength = sizeof(event_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)event_name;

    event_type = muwine_add_object_type(&us, NULL, NULL,
                                        EVENT_GENERIC_READ, EVENT_GENERIC_WRITE,
                                        EVENT_GENERIC_EXECUTE, EVENT_ALL_ACCESS,
                                        EVENT_ALL_ACCESS);
    if (IS_ERR(event_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)event_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)event_type);
    }

    return STATUS_SUCCESS;
}
