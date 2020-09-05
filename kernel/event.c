#include "muwine.h"

NTSTATUS NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess,
                       POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType,
                       BOOLEAN InitialState) {
    printk(KERN_INFO "NtCreateEvent(%px, %x, %px, %x, %x): stub\n", EventHandle,
           DesiredAccess, ObjectAttributes, EventType, InitialState);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
