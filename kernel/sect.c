#include "muwine.h"
#include <linux/mman.h>

typedef struct {
    object_header header;
    uint64_t max_size;
    ULONG page_protection;
    ULONG alloc_attributes;
    file_object* file;
} section_object;

// NT_ prefix added to avoid collision with pgtable_types.h
#define NT_PAGE_NOACCESS 0x01
#define NT_PAGE_READONLY 0x02
#define NT_PAGE_READWRITE 0x04
#define NT_PAGE_WRITECOPY 0x08
#define NT_PAGE_EXECUTE 0x10
#define NT_PAGE_EXECUTE_READ 0x20
#define NT_PAGE_EXECUTE_READWRITE 0x40
#define NT_PAGE_EXECUTE_WRITECOPY 0x80
#define NT_PAGE_GUARD 0x100
#define NT_PAGE_NOCACHE 0x200
#define NT_PAGE_WRITECOMBINE 0x400

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

static NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                   SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                   ULONG AllocationType, ULONG Win32Protect) {
    section_object* sect;
    unsigned long prot, ret;

    printk(KERN_INFO "NtMapViewOfSection(%lx, %lx, %px, %lx, %lx, %px, %px, %x, %x, %x): stub\n", (uintptr_t)SectionHandle,
           (uintptr_t)ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition,
           AllocationType, Win32Protect);

    sect = (section_object*)get_object_from_handle(SectionHandle);

    if (!sect || sect->header.type != muwine_object_section)
        return STATUS_INVALID_HANDLE;

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtMapViewOfSection: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    if (sect->file) {
        printk("NtMapViewOfSection: FIXME - non-anonymous mappings\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    // FIXME - ZeroBits

    // FIXME - SectionOffset
    // FIXME - make sure SectionOffset + ViewSize not more than MaximumSize

    if (Win32Protect & NT_PAGE_EXECUTE_READ || Win32Protect & NT_PAGE_EXECUTE_WRITECOPY)
        prot = PROT_EXEC | PROT_READ;
    else if (Win32Protect & NT_PAGE_EXECUTE_READWRITE)
        prot = PROT_EXEC | PROT_READ | PROT_WRITE;
    else if (Win32Protect & NT_PAGE_READONLY || Win32Protect & NT_PAGE_WRITECOPY)
        prot = PROT_READ;
    else if (Win32Protect & NT_PAGE_READWRITE)
        prot = PROT_READ | PROT_WRITE;
    else {
        printk("NtMapViewOfSection: unhandle Win32Protect value %x\n", Win32Protect);
        return STATUS_NOT_IMPLEMENTED;
    }

    // FIXME - SEC_IMAGE
    // FIXME - inheritance

    ret = vm_mmap(NULL, (uintptr_t)*BaseAddress, sect->max_size, prot,
                  MAP_SHARED/*FIXME - not if SEC_IMAGE?*/, 0);

    printk(KERN_INFO "vm_mmap returned %lx\n", ret);

    if (ret < 0)
        return muwine_error_to_ntstatus(ret);

    *BaseAddress = (void*)(uintptr_t)ret;
    *ViewSize = sect->max_size; // FIXME - should be actual size

    return STATUS_SUCCESS;
}

NTSTATUS user_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                 ULONG AllocationType, ULONG Win32Protect) {
    NTSTATUS Status;
    void* addr = NULL;
    LARGE_INTEGER off;
    SIZE_T size;

    if (!BaseAddress || !ViewSize)
        return STATUS_INVALID_PARAMETER;

    if ((uintptr_t)SectionHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)SectionHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (get_user(addr, BaseAddress) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (SectionOffset) {
        if (get_user(off.QuadPart, &SectionOffset->QuadPart) < 0)
            return STATUS_ACCESS_VIOLATION;
    } else
        off.QuadPart = 0;

    if (get_user(size, ViewSize) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtMapViewOfSection(SectionHandle, ProcessHandle, &addr, ZeroBits, CommitSize, &off, &size, InheritDisposition, AllocationType, Win32Protect);

    if (put_user(addr, BaseAddress) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (SectionOffset && put_user(off.QuadPart, &SectionOffset->QuadPart) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(size, ViewSize) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    printk(KERN_INFO "NtUnmapViewOfSection(%lx, %px): stub\n", (uintptr_t)ProcessHandle, BaseAddress);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize) {
    printk(KERN_INFO "NtExtendSection(%lx, %px): stub\n", (uintptr_t)SectionHandle, NewSectionSize);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenSection(%px, %x, %px): stub\n", SectionHandle, DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer,
                        ULONG InformationBufferSize, PULONG ResultLength) {
    printk(KERN_INFO "NtQuerySection(%lx, %x, %px, %x, %px): stub\n", (uintptr_t)SectionHandle, InformationClass,
           InformationBuffer, InformationBufferSize, ResultLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
