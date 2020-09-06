#include "muwine.h"

static NTSTATUS NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount,
                                  LONG MaximumCount) {
    printk(KERN_INFO "NtCreateSemaphore(%px, %x, %px, %x, %x): stub\n",
           SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount,
           MaximumCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
