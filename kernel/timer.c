#include "muwine.h"
#include "timer.h"
#include <linux/timer.h>

static type_object* timer_type = NULL;

static void timer_fire(struct timer_list* timer) {
    timer_object* t = list_entry(timer, timer_object, timer);

    if (t->type == NotificationTimer)
        t->header.signalled = true;

    signal_object(&t->header, t->type == SynchronizationTimer, false);

    if (t->period != 0 && t->type == SynchronizationTimer)
        mod_timer(&t->timer, jiffies + msecs_to_jiffies(t->period));
}

static NTSTATUS NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    NTSTATUS Status;
    timer_object* obj;
    ACCESS_MASK access;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    object_header* parent = NULL;
    token_object* token;

    Status = access_check_type(timer_type, DesiredAccess, &access);
    if (!NT_SUCCESS(Status))
        return Status;

    if (TimerType != SynchronizationTimer && TimerType != NotificationTimer)
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
                              token, &timer_type->generic_mapping, 0, false, &sd, NULL);

    if (parent)
        dec_obj_refcount(parent);

    if (token)
        dec_obj_refcount((object_header*)token);

    if (!NT_SUCCESS(Status))
        return Status;

    obj = (timer_object*)muwine_alloc_object(sizeof(timer_object), timer_type, sd);
    if (!obj) {
        kfree(sd);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->type = TimerType;
    spin_lock_init(&obj->lock);
    lockdep_register_key(&obj->key);
    init_timer_key(&obj->timer, timer_fire, 0, "muw-timer", &obj->key);

    Status = muwine_add_entry_in_hierarchy2((object_header**)&obj, ObjectAttributes);
    if (!NT_SUCCESS(Status))
        goto end;

    Status = muwine_add_handle(&obj->header.h, TimerHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

end:
    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&obj->header.h);

    return Status;
}

NTSTATUS user_NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!TimerHandle)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes && !get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (ObjectAttributes && oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateTimer(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, TimerType);

    if (ObjectAttributes)
        free_object_attributes(&oa);

    if (put_user(h, TimerHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    timer_object* t;
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

    Status = muwine_open_object(&us, (object_header**)&t, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (t->header.h.type != timer_type || after.Length != 0) {
        dec_obj_refcount(&t->header.h);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Status = access_check_object(&t->header.h, DesiredAccess, &access);
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&t->header.h);
        goto end;
    }

    Status = muwine_add_handle(&t->header.h, TimerHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&t->header.h);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!TimerHandle || !ObjectAttributes)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenTimer(&h, DesiredAccess, &oa);

    free_object_attributes(&oa);

    if (put_user(h, TimerHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass,
                      PVOID TimerInformation, ULONG TimerInformationLength,
                      PULONG ReturnLength) {
    printk(KERN_INFO "NtQueryTimer(%lx, %x, %px, %x, %px): stub\n", (uintptr_t)TimerHandle,
           TimerInformationClass, TimerInformation, TimerInformationLength,
           ReturnLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime,
                           PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                           BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    NTSTATUS Status;
    timer_object* t;
    ACCESS_MASK access;

    // FIXME - APCs

    t = (timer_object*)get_object_from_handle(TimerHandle, &access);
    if (!t)
        return STATUS_INVALID_HANDLE;

    if (t->header.h.type != timer_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & TIMER_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (DueTime->QuadPart > 0) {
        printk("NtSetTimer: FIXME - support absolute times\n"); // FIXME
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    spin_lock(&t->lock);

    t->header.signalled = false;

    mod_timer(&t->timer, jiffies + msecs_to_jiffies(-DueTime->QuadPart / 10000));

    t->period = Period;

    if (PreviousState)
        *PreviousState = t->header.signalled;

    spin_unlock(&t->lock);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&t->header.h);

    return Status;
}

NTSTATUS user_NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime,
                         PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                         BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    NTSTATUS Status;
    LARGE_INTEGER time;
    BOOLEAN prev_state;

    if ((uintptr_t)TimerHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!DueTime)
        return STATUS_INVALID_PARAMETER;

    if (get_user(time.QuadPart, &DueTime->QuadPart) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtSetTimer(TimerHandle, &time, TimerApcRoutine, TimerContext, ResumeTimer,
                        Period, PreviousState ? &prev_state : NULL);

    if (PreviousState && put_user(prev_state, PreviousState) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    NTSTATUS Status;
    ACCESS_MASK access;
    timer_object* t;

    t = (timer_object*)get_object_from_handle(TimerHandle, &access);
    if (!t)
        return STATUS_INVALID_HANDLE;

    if (t->header.h.type != timer_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & TIMER_MODIFY_STATE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    spin_lock(&t->lock);

    del_timer(&t->timer);

    if (CurrentState)
        *CurrentState = t->header.signalled;

    spin_unlock(&t->lock);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&t->header.h);

    return Status;
}

NTSTATUS user_NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    NTSTATUS Status;
    BOOLEAN state;

    if ((uintptr_t)TimerHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtCancelTimer(TimerHandle, CurrentState ? &state : NULL);

    if (CurrentState && put_user(state, CurrentState) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static void timer_object_close(object_header* obj) {
    timer_object* t = (timer_object*)obj;

    del_timer_sync(&t->timer);
    lockdep_unregister_key(&t->key);
}

NTSTATUS muwine_init_timers(void) {
    UNICODE_STRING us;

    static const WCHAR timer_name[] = L"Timer";

    us.Length = us.MaximumLength = sizeof(timer_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)timer_name;

    timer_type = muwine_add_object_type(&us, timer_object_close, NULL,
                                        TIMER_GENERIC_READ, TIMER_GENERIC_WRITE,
                                        TIMER_GENERIC_EXECUTE, TIMER_ALL_ACCESS,
                                        TIMER_ALL_ACCESS);
    if (IS_ERR(timer_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)timer_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)timer_type);
    }

    return STATUS_SUCCESS;
}
