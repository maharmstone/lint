#include "muwine.h"

NTSTATUS NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                       POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
    printk(KERN_INFO "NtCreateTimer(%px, %x, %px, %x): stub\n", TimerHandle,
           DesiredAccess, ObjectAttributes, TimerType);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
