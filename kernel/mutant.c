#include "muwine.h"

NTSTATUS NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                        POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {
    printk(KERN_INFO "NtCreateMutant(%px, %x, %px, %x): stub\n",
           MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
