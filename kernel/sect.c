#include "muwine.h"

typedef struct {
    object_header header;
    uint64_t max_size;
    ULONG page_protection;
    ULONG alloc_attributes;
    file_object* file;
} section_object;

static void section_object_close(object_header* obj) {
    section_object* sect = (section_object*)obj;

    if (sect->file) {
        if (__sync_sub_and_fetch(&sect->file->header.refcount, 1) == 0)
            sect->file->header.close(&sect->file->header);
    }

    if (sect->header.path.Buffer)
        kfree(sect->header.path.Buffer);

    kfree(sect);
}

static NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                HANDLE FileHandle) {
    NTSTATUS Status;
    file_object* file = NULL;
    section_object* obj;

    if (FileHandle) {
        file = (file_object*)get_object_from_handle(FileHandle);

        if (!file || file->header.type != muwine_object_file)
            return STATUS_INVALID_HANDLE;

        __sync_add_and_fetch(&file->header.refcount, 1);
    }

    // FIXME - make sure we're not trying to map a read-only file handle read-write

    // FIXME - add support for creating section in hierarchy

    obj = kzalloc(sizeof(section_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.refcount = 1;
    obj->header.type = muwine_object_section;
    spin_lock_init(&obj->header.path_lock);
    obj->header.close = section_object_close;

    if (MaximumSize)
        obj->max_size = MaximumSize->QuadPart;

    obj->page_protection = SectionPageProtection;
    obj->alloc_attributes = AllocationAttributes;
    obj->file = file;

    Status = muwine_add_handle(&obj->header, SectionHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false);

    if (!NT_SUCCESS(Status)) {
        if (__sync_sub_and_fetch(&obj->header.refcount, 1) == 0)
            obj->header.close(&obj->header);

        return Status;
    }

    return STATUS_SUCCESS;
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
