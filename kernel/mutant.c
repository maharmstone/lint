#include "muwine.h"

static NTSTATUS NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    printk(KERN_INFO "NtCreateMutant(%px, %x, %px, %x): stub\n",
           MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!MutantHandle)
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

    Status = NtCreateMutant(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                            InitialOwner);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, MutantHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenMutant(%px, %x, %px): stub\n",
           MutantHandle, DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass,
                       PVOID MutantInformation, ULONG MutantInformationLength,
                       PULONG ResultLength) {
    printk(KERN_INFO "NtQueryMutant(%lx, %x, %px, %x, %px): stub\n",
           (uintptr_t)MutantHandle, MutantInformationClass, MutantInformation,
           MutantInformationLength, ResultLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {
    printk(KERN_INFO "NtReleaseMutant(%lx, %px): stub\n",
           (uintptr_t)MutantHandle, PreviousCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
