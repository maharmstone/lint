#include "muwine.h"

NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                         PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                         HANDLE FileHandle) {
    printk(KERN_INFO "NtCreateSection(%px, %x, %px, %px, %x, %x, %lx): stub\n", SectionHandle,
           DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes,
           (uintptr_t)FileHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
