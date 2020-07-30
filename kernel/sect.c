#include "muwine.h"

static NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                HANDLE FileHandle) {
    printk(KERN_INFO "NtCreateSection(%px, %x, %px, %px, %x, %x, %lx): stub\n", SectionHandle,
           DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes,
           (uintptr_t)FileHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                              PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                              HANDLE FileHandle) {
    NTSTATUS Status;
    LARGE_INTEGER maxsize;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!SectionHandle)
        return STATUS_INVALID_PARAMETER;

    if (MaximumSize) {
        if (copy_from_user(&maxsize.QuadPart, &MaximumSize->QuadPart, sizeof(int64_t)) != 0)
            return STATUS_ACCESS_VIOLATION;
    }

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

    Status = NtCreateSection(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, MaximumSize ? &maxsize : NULL,
                             SectionPageProtection, AllocationAttributes, FileHandle);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, SectionHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                            SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                            ULONG AllocationType, ULONG Win32Protect) {
    printk(KERN_INFO "NtMapViewOfSection(%lx, %lx, %px, %lx, %lx, %px, %px, %x, %x, %x): stub\n", (uintptr_t)SectionHandle,
           (uintptr_t)ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition,
           AllocationType, Win32Protect);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    printk(KERN_INFO "NtUnmapViewOfSection(%lx, %px): stub\n", (uintptr_t)ProcessHandle, BaseAddress);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
