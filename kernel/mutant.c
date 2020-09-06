#include "muwine.h"
#include "mutant.h"

static type_object* mutant_type = NULL;

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

static void mutant_object_close(object_header* obj) {
    mutant_object* mut = (mutant_object*)obj;

    free_object(&mut->header.h);
}

NTSTATUS muwine_init_mutants(void) {
    UNICODE_STRING us;

    static const WCHAR mutant_name[] = L"Mutant";

    us.Length = us.MaximumLength = sizeof(mutant_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)mutant_name;

    mutant_type = muwine_add_object_type(&us, mutant_object_close, NULL,
                                         MUTANT_GENERIC_READ, MUTANT_GENERIC_WRITE,
                                         MUTANT_GENERIC_EXECUTE, MUTANT_ALL_ACCESS,
                                         MUTANT_ALL_ACCESS);
    if (IS_ERR(mutant_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)mutant_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)mutant_type);
    }

    return STATUS_SUCCESS;
}
