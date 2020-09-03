#include "muwine.h"
#include "timer.h"

static type_object* timer_type = NULL;

static NTSTATUS NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    printk(KERN_INFO "NtCreateTimer(%px, %x, %px, %x): stub\n", TimerHandle,
           DesiredAccess, ObjectAttributes, TimerType);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime,
                    PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                    BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {
    printk(KERN_INFO "NtSetTimer(%lx, %px, %px, %px, %x, %x, %px): stub\n",
           (uintptr_t)TimerHandle, DueTime, TimerApcRoutine, TimerContext,
           ResumeTimer, Period, PreviousState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {
    printk(KERN_INFO "NtCancelTimer(%lx, %px): stub\n", (uintptr_t)TimerHandle,
           CurrentState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static void timer_object_close(object_header* obj) {
    timer_object* t = (timer_object*)obj;

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
