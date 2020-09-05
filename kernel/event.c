#include "muwine.h"
#include "event.h"

static type_object* event_type = NULL;

static NTSTATUS NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                              BOOLEAN InitialState) {
    printk(KERN_INFO "NtCreateEvent(%px, %x, %px, %x, %x): stub\n", EventHandle,
           DesiredAccess, ObjectAttributes, EventType, InitialState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                     POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenEvent(%px, %x, %px): stub\n", EventHandle,
           DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
