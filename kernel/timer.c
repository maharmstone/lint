#include "muwine.h"
#include "timer.h"
#include <linux/timer.h>

static type_object* timer_type = NULL;

static void timer_fire(struct timer_list* timer) {
    timer_object* t = list_entry(timer, timer_object, timer);

    if (t->type == NotificationTimer)
        t->header.signalled = true;

    signal_object(&t->header, t->type == SynchronizationTimer);

    if (t->period != 0 && t->type == SynchronizationTimer)
        mod_timer(&t->timer, jiffies + msecs_to_jiffies(t->period));
}

static NTSTATUS NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    NTSTATUS Status;
    timer_object* obj;
    ACCESS_MASK access;

    access = sanitize_access_mask(DesiredAccess, timer_type);

    if (access == MAXIMUM_ALLOWED)
        access = TIMER_ALL_ACCESS;

    if (TimerType != SynchronizationTimer && TimerType != NotificationTimer)
        return STATUS_INVALID_PARAMETER;

    // create object

    obj = kzalloc(sizeof(timer_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.h.refcount = 1;

    obj->header.h.type = timer_type;
    inc_obj_refcount(&timer_type->header);

    spin_lock_init(&obj->header.h.path_lock);

    spin_lock_init(&obj->header.sync_lock);
    INIT_LIST_HEAD(&obj->header.waiters);

    obj->type = TimerType;
    spin_lock_init(&obj->lock);
    lockdep_register_key(&obj->key);
    init_timer_key(&obj->timer, timer_fire, 0, "muw-timer", &obj->key);

    // FIXME - add to hierarchy if ObjectAttributes set

    Status = muwine_add_handle(&obj->header.h, TimerHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return Status;
    }

    return STATUS_SUCCESS;
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
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateTimer(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, TimerType);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, TimerHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                     POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenTimer(%px, %x, %px): stub\n", TimerHandle,
           DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

    free_object(&t->header.h);
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
