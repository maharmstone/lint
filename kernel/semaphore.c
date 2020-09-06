#include "muwine.h"

NTSTATUS NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount,
                           LONG MaximumCount) {
    printk(KERN_INFO "NtCreateSemaphore(%px, %x, %px, %x, %x): stub\n",
           SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount,
           MaximumCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                         POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenSemaphore(%px, %x, %px): stub\n",
           SemaphoreHandle, DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount) {
    printk(KERN_INFO "NtReleaseSemaphore(%lx, %x, %px): stub\n",
           (uintptr_t)SemaphoreHandle, ReleaseCount, PreviousCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
