#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include "muwine.h"
#include "sect.h"

static void section_object_close(object_header* obj) {
    section_object* sect = (section_object*)obj;

    if (sect->file) {
        if (__sync_sub_and_fetch(&sect->file->header.refcount, 1) == 0)
            sect->file->header.close(&sect->file->header);
    }

    if (sect->anon_file)
        filp_close(sect->anon_file, 0);

    if (sect->header.path.Buffer)
        kfree(sect->header.path.Buffer);

    kfree(sect);
}

static NTSTATUS load_image(HANDLE file_handle, uint64_t file_size, struct file** anon_file, uint32_t* ret_image_size) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_header;
    uint32_t image_size, header_size;
    uint8_t* buf;
    IMAGE_SECTION_HEADER* sections;
    struct file* file;
    unsigned int i;
    ssize_t written;
    loff_t pos;

    // FIXME - check error codes are right

    if (file_size < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_PARAMETER;

    off.QuadPart = 0;

    Status = NtReadFile(file_handle, NULL, NULL, NULL, &iosb, &dos_header, sizeof(IMAGE_DOS_HEADER),
                        &off, NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    if (iosb.Information < sizeof(IMAGE_DOS_HEADER))
        return STATUS_INVALID_PARAMETER;

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_PARAMETER;

    if (file_size < dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS))
        return STATUS_INVALID_PARAMETER;

    off.QuadPart = dos_header.e_lfanew;

    Status = NtReadFile(file_handle, NULL, NULL, NULL, &iosb, &nt_header, sizeof(IMAGE_NT_HEADERS),
                        &off, NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    if (nt_header.Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_PARAMETER;

    if (nt_header.OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        nt_header.OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    if (nt_header.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_size = nt_header.OptionalHeader64.SizeOfImage;
        header_size = nt_header.OptionalHeader64.SizeOfHeaders;
    } else {
        image_size = nt_header.OptionalHeader32.SizeOfImage;
        header_size = nt_header.OptionalHeader32.SizeOfHeaders;
    }

    if (file_size < header_size)
        return STATUS_INVALID_PARAMETER;

    buf = vzalloc(image_size);
    if (!buf)
        return STATUS_INSUFFICIENT_RESOURCES;

    off.QuadPart = 0;

    Status = NtReadFile(file_handle, NULL, NULL, NULL, &iosb, buf, header_size,
                        &off, NULL);
    if (!NT_SUCCESS(Status)) {
        vfree(buf);
        return Status;
    }

    sections = (IMAGE_SECTION_HEADER*)(buf + dos_header.e_lfanew +
                offsetof(IMAGE_NT_HEADERS, OptionalHeader32) +
                nt_header.FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < nt_header.FileHeader.NumberOfSections; i++) {
        if (sections[i].VirtualAddress > image_size || sections[i].VirtualAddress + sections[i].VirtualSize > image_size) {
            vfree(buf);
            return STATUS_INVALID_PARAMETER;
        }

        if (sections[i].PointerToRawData > file_size || sections[i].PointerToRawData + sections[i].SizeOfRawData > file_size) {
            vfree(buf);
            return STATUS_INVALID_PARAMETER;
        }

        if (sections[i].SizeOfRawData > 0) {
            off.QuadPart = sections[i].PointerToRawData;

            Status = NtReadFile(file_handle, NULL, NULL, NULL, &iosb, buf + sections[i].VirtualAddress,
                                sections[i].SizeOfRawData, &off, NULL);
            if (!NT_SUCCESS(Status)) {
                vfree(buf);
                return Status;
            }
        }
    }

    file = shmem_file_setup("ntsection", image_size, 0);
    if (IS_ERR(file)) {
        vfree(buf);
        return muwine_error_to_ntstatus((int)(uintptr_t)file);
    }

    pos = 0;

    written = kernel_write(file, buf, image_size, &pos);

    vfree(buf);

    if (written < 0) {
        filp_close(file, NULL);
        return muwine_error_to_ntstatus(written);
    }

    *anon_file = file;
    *ret_image_size = image_size;

    return STATUS_SUCCESS;
}

static NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                HANDLE FileHandle) {
    NTSTATUS Status;
    file_object* file = NULL;
    section_object* obj;
    struct file* anon_file = NULL;
    uint64_t file_size = 0;

    if (AllocationAttributes & SEC_IMAGE && !FileHandle)
        return STATUS_INVALID_PARAMETER;

    if (FileHandle) {
        FILE_STANDARD_INFORMATION fsi;
        IO_STATUS_BLOCK iosb;

        file = (file_object*)get_object_from_handle(FileHandle);

        if (!file || file->header.type != muwine_object_file)
            return STATUS_INVALID_HANDLE;

        Status = NtQueryInformationFile(FileHandle, &iosb, &fsi, sizeof(fsi),
                                        FileStandardInformation);
        if (!NT_SUCCESS(Status))
            return Status;

        file_size = fsi.EndOfFile.QuadPart;

        __sync_add_and_fetch(&file->header.refcount, 1);
    } else {
        if (!MaximumSize)
            return STATUS_INVALID_PARAMETER;

        anon_file = shmem_file_setup("ntsection", MaximumSize->QuadPart, 0);
        if (IS_ERR(anon_file))
            return muwine_error_to_ntstatus((int)(uintptr_t)anon_file);
    }

    // FIXME - make sure we're not trying to map a read-only file handle read-write

    // FIXME - add support for creating section in hierarchy

    if (AllocationAttributes & SEC_IMAGE) {
        uint32_t image_size;

        Status = load_image(FileHandle, file_size, &anon_file, &image_size);
        if (!NT_SUCCESS(Status)) {
            if (__sync_sub_and_fetch(&file->header.refcount, 1) == 0)
                obj->header.close(&obj->header);

            return Status;
        }

        if (__sync_sub_and_fetch(&file->header.refcount, 1) == 0)
            obj->header.close(&obj->header);

        file = NULL;

        file_size = image_size;
    }

    obj = kzalloc(sizeof(section_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.refcount = 1;
    obj->header.type = muwine_object_section;
    spin_lock_init(&obj->header.path_lock);
    obj->header.close = section_object_close;

    if (MaximumSize && MaximumSize->QuadPart != 0) {
        obj->max_size = MaximumSize->QuadPart;

        if ((file || AllocationAttributes & SEC_IMAGE) && obj->max_size > file_size)
            obj->max_size = file_size;
    } else if (file || AllocationAttributes & SEC_IMAGE)
        obj->max_size = file_size;

    if (obj->max_size & (PAGE_SIZE - 1))
        obj->max_size += PAGE_SIZE - (obj->max_size & (PAGE_SIZE - 1));

    obj->page_protection = SectionPageProtection;
    obj->alloc_attributes = AllocationAttributes;
    obj->file = file;
    obj->anon_file = anon_file;

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
    section_object* sect = (section_object*)get_object_from_handle(SectionHandle);
    unsigned long prot, ret, flags, len, off;
    struct file* file;
    section_map* map;
    process* p;

    if (!sect || sect->header.type != muwine_object_section)
        return STATUS_INVALID_HANDLE;

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process();

        if (!p)
            return STATUS_INTERNAL_ERROR;
    } else {
        printk("NtMapViewOfSection: FIXME - support process handles\n"); // FIXME
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

    // FIXME - Windows insists on 0x10000 increments for SectionOffset?

    // FIXME - inheritance

    // FIXME - should we be returning error if SectionOffset more than 2^32 on x86?

    if (SectionOffset)
        off = SectionOffset->QuadPart;
    else
        off = 0;

    if (off > sect->max_size)
        return STATUS_INVALID_PARAMETER;

    if (*ViewSize == 0)
        len = sect->max_size - off;
    else {
        len = *ViewSize;

        if (off + len > sect->max_size)
            len = sect->max_size - len;
    }

    flags = MAP_SHARED; // FIXME - not if SEC_IMAGE?

    if (sect->file) {
        file = sect->file->dev->get_filp(sect->file);

        if (!file)
            return STATUS_INVALID_PARAMETER;
    } else
        file = sect->anon_file;

    map = kmalloc(sizeof(section_map), GFP_KERNEL);
    if (!map)
        return STATUS_INSUFFICIENT_RESOURCES;

    ret = vm_mmap(file, (uintptr_t)*BaseAddress, len, prot, flags, off);
    if (IS_ERR((void*)ret)) {
        kfree(map);
        return muwine_error_to_ntstatus(ret);
    }

    map->address = (uintptr_t)ret;
    map->length = len;
    map->sect = &sect->header;
    __sync_add_and_fetch(&map->sect->refcount, 1);

    spin_lock(&p->mapping_list_lock);
    list_add_tail(&map->list, &p->mapping_list);
    spin_unlock(&p->mapping_list_lock);

    *BaseAddress = (void*)(uintptr_t)ret;
    *ViewSize = len;

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

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
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

static NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    section_map* sm = NULL;
    struct list_head* le;
    process* p;

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process();

        if (!p)
            return STATUS_INTERNAL_ERROR;
    } else {
        printk("NtUnmapViewOfSection: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    spin_lock(&p->mapping_list_lock);

    le = p->mapping_list.next;
    while (le != &p->mapping_list) {
        section_map* sm2 = list_entry(le, section_map, list);

        if ((uintptr_t)BaseAddress >= sm2->address && (uintptr_t)BaseAddress < sm2->address + sm2->length) {
            sm = sm2;
            list_del(&sm->list);
            break;
        }

        le = le->next;
    }

    spin_unlock(&p->mapping_list_lock);

    if (!sm)
        return STATUS_INVALID_PARAMETER;

    vm_munmap(sm->address, sm->length);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    return NtUnmapViewOfSection(ProcessHandle, BaseAddress);
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
