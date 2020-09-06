#include "muwine.h"
#include "semaphore.h"

static type_object* sem_type = NULL;

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

static void sem_object_close(object_header* obj) {
    sem_object* sem = (sem_object*)obj;

    free_object(&sem->header.h);
}

NTSTATUS muwine_init_semaphores(void) {
    UNICODE_STRING us;

    static const WCHAR sem_name[] = L"Semaphore";

    us.Length = us.MaximumLength = sizeof(sem_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)sem_name;

    sem_type = muwine_add_object_type(&us, sem_object_close, NULL,
                                      SEMAPHORE_GENERIC_READ, SEMAPHORE_GENERIC_WRITE,
                                      SEMAPHORE_GENERIC_EXECUTE, SEMAPHORE_ALL_ACCESS,
                                      SEMAPHORE_ALL_ACCESS);
    if (IS_ERR(sem_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)sem_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)sem_type);
    }

    return STATUS_SUCCESS;
}
