#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/rmap.h>
#include <linux/kprobes.h>
#include "muwine.h"
#include "sect.h"
#include "proc.h"

static type_object* section_type = NULL;

extern type_object* file_type;
extern type_object* dir_type;

typedef int (*func_mprotect_fixup)(struct vm_area_struct *vma,
                                   struct vm_area_struct **pprev,
                                   unsigned long start, unsigned long end,
                                   unsigned long newflags);

func_mprotect_fixup _mprotect_fixup;

static void section_object_close(object_header* obj) {
    section_object* sect = (section_object*)obj;

    if (sect->file)
        dec_obj_refcount(&sect->file->header);

    if (sect->anon_file)
        filp_close(sect->anon_file, NULL);
}

static char* get_sect_name(HANDLE file_handle) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_NAME_INFORMATION fni;
    FILE_NAME_INFORMATION* fni2;
    ULONG as_len;
    char* s;
    unsigned int i, bs;

    Status = NtQueryInformationFile(file_handle, &iosb, &fni, offsetof(FILE_NAME_INFORMATION, FileName),
                                    FileNameInformation);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        return NULL;

    fni2 = kmalloc(offsetof(FILE_NAME_INFORMATION, FileName) + fni.FileNameLength, GFP_KERNEL);
    if (!fni2)
        return NULL;

    Status = NtQueryInformationFile(file_handle, &iosb, fni2,
                                    offsetof(FILE_NAME_INFORMATION, FileName) + fni.FileNameLength,
                                    FileNameInformation);
    if (!NT_SUCCESS(Status)) {
        kfree(fni2);
        return NULL;
    }

    if (!NT_SUCCESS(utf16_to_utf8(NULL, 0, &as_len, fni2->FileName, fni2->FileNameLength))) {
        kfree(fni2);
        return NULL;
    }

    s = kmalloc(as_len + 1, GFP_KERNEL);
    if (!s) {
        kfree(fni2);
        return NULL;
    }

    if (!NT_SUCCESS(utf16_to_utf8(s, as_len, &as_len, fni2->FileName, fni2->FileNameLength))) {
        kfree(s);
        kfree(fni2);
        return NULL;
    }

    kfree(fni2);

    s[as_len] = 0;

    // remove all but filename

    bs = as_len;
    for (i = 0; i < as_len; i++) {
        if (s[i] == '\\')
            bs = i;
    }

    if (bs != as_len)
        memcpy(s, &s[bs + 1], as_len - bs);

    return s;
}

static NTSTATUS load_image(HANDLE file_handle, uint64_t file_size, struct file** anon_file,
                           uint32_t* ret_image_size, section_object** obj) {
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
    section_object* sect;
    char* sect_name;

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
            uint32_t section_size;

            off.QuadPart = sections[i].PointerToRawData;

            section_size = sections[i].VirtualSize;

            if (sections[i].SizeOfRawData < section_size)
                section_size = sections[i].SizeOfRawData;

            Status = NtReadFile(file_handle, NULL, NULL, NULL, &iosb, buf + sections[i].VirtualAddress,
                                section_size, &off, NULL);
            if (!NT_SUCCESS(Status)) {
                vfree(buf);
                return Status;
            }
        }
    }

    sect_name = get_sect_name(file_handle);

    file = shmem_file_setup(sect_name ? sect_name : "ntsection", image_size, 0);
    if (IS_ERR(file)) {
        if (sect_name)
            kfree(sect_name);

        vfree(buf);
        return muwine_error_to_ntstatus((int)(uintptr_t)file);
    }

    if (sect_name)
        kfree(sect_name);

    pos = 0;

    written = kernel_write(file, buf, image_size, &pos);

    if (written < 0) {
        filp_close(file, NULL);
        vfree(buf);
        return muwine_error_to_ntstatus(written);
    }

    sect = (section_object*)muwine_alloc_object(offsetof(section_object, sections) + (nt_header.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)),
                                                section_type, NULL);
    if (!sect) {
        filp_close(file, NULL);
        vfree(buf);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *anon_file = file;
    *ret_image_size = image_size;

    if (nt_header.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        sect->preferred_base = (void*)(uintptr_t)nt_header.OptionalHeader64.ImageBase;
    else
        sect->preferred_base = (void*)(uintptr_t)nt_header.OptionalHeader32.ImageBase;

    sect->fixed_base = nt_header.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED;

    sect->num_sections = nt_header.FileHeader.NumberOfSections;
    memcpy(sect->sections, sections, sect->num_sections * sizeof(IMAGE_SECTION_HEADER));

    vfree(buf);

    *obj = sect;

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
    ACCESS_MASK file_access;

    if (AllocationAttributes & SEC_IMAGE && !FileHandle)
        return STATUS_INVALID_PARAMETER;

    if (FileHandle) {
        FILE_STANDARD_INFORMATION fsi;
        IO_STATUS_BLOCK iosb;

        file = (file_object*)get_object_from_handle(FileHandle, &file_access);

        if (!file)
            return STATUS_INVALID_HANDLE;

        if (file->header.type != file_type) {
            dec_obj_refcount(&file->header);
            return STATUS_INVALID_HANDLE;
        }

        Status = NtQueryInformationFile(FileHandle, &iosb, &fsi, sizeof(fsi),
                                        FileStandardInformation);
        if (!NT_SUCCESS(Status)) {
            dec_obj_refcount(&file->header);
            return Status;
        }

        file_size = fsi.EndOfFile.QuadPart;
    } else {
        if (!MaximumSize)
            return STATUS_INVALID_PARAMETER;

        anon_file = shmem_file_setup("ntsection", MaximumSize->QuadPart, 0);
        if (IS_ERR(anon_file))
            return muwine_error_to_ntstatus((int)(uintptr_t)anon_file);
    }

    // FIXME - make sure we're not trying to map a read-only file handle read-write

    if (AllocationAttributes & SEC_IMAGE) {
        uint32_t image_size;

        Status = load_image(FileHandle, file_size, &anon_file, &image_size, &obj);
        if (!NT_SUCCESS(Status)) {
            dec_obj_refcount(&file->header);
            return Status;
        }

        file_size = image_size;
    } else {
        obj = (section_object*)muwine_alloc_object(offsetof(section_object, sections),
                                                   section_type, NULL);
        if (!obj) {
            if (file)
                dec_obj_refcount(&file->header);

            if (anon_file)
                filp_close(anon_file, NULL);

            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

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

    Status = muwine_add_entry_in_hierarchy2((object_header**)&obj, ObjectAttributes);
    if (!NT_SUCCESS(Status))
        goto end;

    Status = muwine_add_handle(&obj->header, SectionHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, 0);

end:
    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&obj->header);

    return Status;
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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateSection(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, MaximumSize ? &maxsize : NULL,
                             SectionPageProtection, AllocationAttributes, FileHandle);

    if (ObjectAttributes)
        free_object_attributes(&oa);

    if (put_user(h, SectionHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                   SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                   ULONG AllocationType, ULONG Win32Protect) {
    NTSTATUS Status;
    ACCESS_MASK access;
    section_object* sect = (section_object*)get_object_from_handle(SectionHandle, &access);
    unsigned long prot, ret, flags, len, off;
    struct file* file;
    section_map* map;
    process_object* p;
    void* addr;
    struct list_head* le;
    unsigned int i;

    if (!sect)
        return STATUS_INVALID_HANDLE;

    if (sect->header.type != section_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process_object();

        if (!p) {
            Status = STATUS_INTERNAL_ERROR;
            goto end2;
        }
    } else {
        printk("NtMapViewOfSection: FIXME - support process handles\n"); // FIXME
        Status = STATUS_NOT_IMPLEMENTED;
        goto end2;
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
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    // FIXME - Windows insists on 0x10000 increments for SectionOffset?

    // FIXME - inheritance

    // FIXME - should we be returning error if SectionOffset more than 2^32 on x86?

    if (SectionOffset)
        off = SectionOffset->QuadPart;
    else
        off = 0;

    if (off > sect->max_size) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (*ViewSize == 0)
        len = sect->max_size - off;
    else {
        len = *ViewSize;

        if (off + len > sect->max_size)
            len = sect->max_size - len;
    }

    if (len % PAGE_SIZE != 0)
        len += PAGE_SIZE - (len % PAGE_SIZE);

    flags = MAP_PRIVATE;

    if (sect->anon_file)
        file = sect->anon_file;
    else {
        if (!sect->file) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        file = sect->file->dev->get_filp(sect->file);

        if (!file) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }
    }

    map = kmalloc(sizeof(section_map), GFP_KERNEL);
    if (!map) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    addr = *BaseAddress;

    if (sect->alloc_attributes & SEC_IMAGE && (!addr || sect->fixed_base))
        addr = (uint8_t*)sect->preferred_base + off;

    if (sect->alloc_attributes & SEC_IMAGE && sect->fixed_base)
        flags |= MAP_FIXED;

    // HACK - make sure KUSER_SHARED_DATA always gets put at right place
    if (addr == (void*)0x7ffe0000 && len == PAGE_SIZE)
        flags |= MAP_FIXED;

    // FIXME - fail if MAP_FIXED, and we've already mapped something here? Or do we unmap it?

    map->file_offset = off;

    ret = vm_mmap(file, (uintptr_t)addr, len, prot, flags, off);
    if (IS_ERR((void*)ret)) {
        kfree(map);
        Status = muwine_error_to_ntstatus(ret);
        goto end;
    }

    addr = (void*)(uintptr_t)ret;

    map->address = (uintptr_t)addr;
    map->length = len;
    map->committed = true;

    if (sect->alloc_attributes & SEC_IMAGE) {
        for (i = 0; i < sect->num_sections; i++) {
            uint32_t section_size = sect->sections[i].VirtualSize;

            if (section_size % PAGE_SIZE)
                section_size += PAGE_SIZE - (section_size % PAGE_SIZE);

            if (sect->sections[i].VirtualAddress < off + len &&
                sect->sections[i].VirtualAddress + section_size > off) {
                uint32_t off2 = off, end = sect->sections[i].VirtualAddress + section_size;

                if (sect->sections[i].VirtualAddress > off2)
                    off2 = sect->sections[i].VirtualAddress;

                if (end > off + len)
                    end = off + len;

                prot = PROT_READ;

                if (sect->sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                    prot |= PROT_WRITE;

                if (sect->sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    prot |= PROT_EXEC;

                ret = vm_mmap(file, (uintptr_t)addr + off2 - off, end - off2, prot,
                              flags | MAP_FIXED, off2);
                if (IS_ERR((void*)ret)) {
                    kfree(map);
                    Status = muwine_error_to_ntstatus(ret);
                    goto end;
                }
            }
        }
    }

    map->sect = &sect->header;
    inc_obj_refcount(map->sect);

    *BaseAddress = addr;
    *ViewSize = len;

    down_write(&p->mapping_list_sem);

    if (sect->file)
        __sync_add_and_fetch(&sect->file->mapping_count, 1);

    le = p->mapping_list.next;
    while (le != &p->mapping_list) {
        section_map* sm2 = list_entry(le, section_map, list);

        if (sm2->address > map->address) {
            list_add(&map->list, le->prev);
            up_write(&p->mapping_list_sem);

            Status = STATUS_SUCCESS;
            goto end;
        }

        le = le->next;
    }

    list_add_tail(&map->list, &p->mapping_list);
    up_write(&p->mapping_list_sem);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&p->header.h);

end2:
    dec_obj_refcount(&sect->header);

    return Status;
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
    process_object* p;

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process_object();

        if (!p)
            return STATUS_INTERNAL_ERROR;
    } else {
        printk("NtUnmapViewOfSection: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    down_write(&p->mapping_list_sem);

    le = p->mapping_list.next;
    while (le != &p->mapping_list) {
        section_map* sm2 = list_entry(le, section_map, list);

        if ((uintptr_t)BaseAddress >= sm2->address && (uintptr_t)BaseAddress < sm2->address + sm2->length && sm2->sect) {
            sm = sm2;
            list_del(&sm->list);
            break;
        }

        le = le->next;
    }

    up_write(&p->mapping_list_sem);

    if (!sm) {
        dec_obj_refcount(&p->header.h);
        return STATUS_INVALID_PARAMETER;
    }

    vm_munmap(sm->address, sm->length);

    if (((section_object*)sm->sect)->file)
        __sync_add_and_fetch(&((section_object*)sm->sect)->file->mapping_count, 1);

    dec_obj_refcount(sm->sect);

    kfree(sm);

    dec_obj_refcount(&p->header.h);

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

static NTSTATUS NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    section_object* sect;
    bool after_alloc = false;

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        object_header* obj = get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!obj)
            return STATUS_INVALID_HANDLE;

        if (obj->type != dir_type) {
            dec_obj_refcount(obj);
            return STATUS_INVALID_HANDLE;
        }

        spin_lock(&obj->header_lock);

        us.Length = obj->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&obj->header_lock);
            dec_obj_refcount(obj);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, obj->path.Buffer, obj->path.Length);
        us.Buffer[obj->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(obj->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&obj->header_lock);

        dec_obj_refcount(obj);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    Status = muwine_open_object(&us, (object_header**)&sect, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (sect->header.type != section_type || after.Length != 0) {
        dec_obj_refcount(&sect->header);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Status = muwine_add_handle(&sect->header, SectionHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, 0);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&sect->header);
        goto end;
    }

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;

    if (!SectionHandle || !ObjectAttributes)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenSection(&h, DesiredAccess, &oa);

    free_object_attributes(&oa);

    if (put_user(h, SectionHandle) < 0) {
        if (NT_SUCCESS(Status))
            NtClose(h);

        Status = STATUS_ACCESS_VIOLATION;
    }

    return Status;
}

NTSTATUS NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer,
                        ULONG InformationBufferSize, PULONG ResultLength) {
    printk(KERN_INFO "NtQuerySection(%lx, %x, %px, %x, %px): stub\n", (uintptr_t)SectionHandle, InformationClass,
           InformationBuffer, InformationBufferSize, ResultLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                       ULONG NewAccessProtection, PULONG OldAccessProtection) {
    uintptr_t addr = (uintptr_t)*BaseAddress;
    size_t size = *NumberOfBytesToProtect;
    unsigned long prot, nstart, oldflags;
    int ret;
    struct vm_area_struct* vma;
    struct vm_area_struct* prev;

    if (ProcessHandle == NtCurrentProcess()) {
        // FIXME - get process object
    } else {
        printk("NtProtectVirtualMemory: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    if (addr % PAGE_SIZE) {
        size += addr % PAGE_SIZE;
        addr -= addr % PAGE_SIZE;
    }

    if (size % PAGE_SIZE)
        size += PAGE_SIZE - (size % PAGE_SIZE);

    *BaseAddress = (void*)addr;
    *NumberOfBytesToProtect = size;

    if (NewAccessProtection & NT_PAGE_EXECUTE_READ || NewAccessProtection & NT_PAGE_EXECUTE_WRITECOPY)
        prot = VM_EXEC | VM_READ;
    else if (NewAccessProtection & NT_PAGE_EXECUTE_READWRITE)
        prot = VM_EXEC | VM_READ | VM_WRITE;
    else if (NewAccessProtection & NT_PAGE_READONLY || NewAccessProtection & NT_PAGE_WRITECOPY)
        prot = VM_READ;
    else if (NewAccessProtection & NT_PAGE_READWRITE)
        prot = VM_READ | VM_WRITE;
    else {
        printk("NtProtectVirtualMemory: unhandled NewAccessProtection value %x\n", NewAccessProtection);
        return STATUS_NOT_IMPLEMENTED;
    }

    // FIXME - fail if region not fully committed?
    // FIXME - do we need to make sure userspace doesn't specify kernel address?

    ret = mmap_write_lock_killable(current->mm);
    if (ret < 0)
        return muwine_error_to_ntstatus(ret);

    vma = find_vma(current->mm, addr);

    if (!vma || vma->vm_start > addr) {
        mmap_write_unlock(current->mm);
        return STATUS_INVALID_PARAMETER;
    }

    prev = vma->vm_prev;

    if (addr > vma->vm_start)
        prev = vma;

    nstart = addr;

    while (true) {
        unsigned long newflags = prot;
        unsigned long tmp;

        newflags |= vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC | VM_ARCH_CLEAR);

        tmp = vma->vm_end;
        if (tmp > addr + size)
            tmp = addr + size;

        if (nstart == addr)
            oldflags = vma->vm_flags;

        ret = _mprotect_fixup(vma, &prev, nstart, tmp, newflags);
        if (ret) {
            mmap_write_unlock(current->mm);
            return muwine_error_to_ntstatus(ret);
        }

        nstart = tmp;

        if (nstart < prev->vm_end)
            nstart = prev->vm_end;

        if (nstart >= addr + size)
            break;

        vma = prev->vm_next;
        if (!vma || vma->vm_start != nstart) {
            mmap_write_unlock(current->mm);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    mmap_write_unlock(current->mm);

    if (oldflags & VM_READ && oldflags & VM_WRITE && oldflags & VM_EXEC)
        *OldAccessProtection = NT_PAGE_EXECUTE_READWRITE;
    else if (oldflags & VM_READ && oldflags & VM_EXEC)
        *OldAccessProtection = NT_PAGE_EXECUTE_READ;
    else if (oldflags & VM_READ && oldflags & VM_WRITE)
        *OldAccessProtection = NT_PAGE_READWRITE;
    else if (oldflags & VM_READ)
        *OldAccessProtection = NT_PAGE_READONLY;
    else
        *OldAccessProtection = 0;

    return STATUS_SUCCESS;
}

NTSTATUS user_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect,
                                     ULONG NewAccessProtection, PULONG OldAccessProtection) {
    NTSTATUS Status;
    void* addr;
    SIZE_T size;
    ULONG old;

    if (!BaseAddress || !NumberOfBytesToProtect || !OldAccessProtection)
        return STATUS_INVALID_PARAMETER;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (get_user(addr, BaseAddress) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (get_user(size, NumberOfBytesToProtect) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtProtectVirtualMemory(ProcessHandle, &addr, &size, NewAccessProtection, &old);

    if (put_user(addr, BaseAddress) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(size, NumberOfBytesToProtect) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(old, OldAccessProtection) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                 PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    NTSTATUS Status;
    process_object* p;
    uintptr_t addr = (uintptr_t)*BaseAddress;
    size_t size = *RegionSize;
    unsigned long ret, prot, flags;
    section_map* map;
    struct list_head* le;

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process_object();

        if (!p)
            return STATUS_INTERNAL_ERROR;
    } else {
        printk(KERN_INFO "NtAllocateVirtualMemory: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    if (addr % PAGE_SIZE) {
        size += addr % PAGE_SIZE;
        addr -= addr % PAGE_SIZE;
    }

    if (size % PAGE_SIZE)
        size += PAGE_SIZE - (size % PAGE_SIZE);

    if (!(AllocationType & (MEM_COMMIT | MEM_RESERVE | MEM_RESET))) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (AllocationType & MEM_RESET && (MEM_COMMIT | MEM_RESERVE)) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (AllocationType & MEM_RESET) {
        printk(KERN_INFO "NtAllocateVirtualMemory: FIXME - MEM_RESET\n"); // FIXME
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    if (AllocationType & MEM_RESERVE && !(AllocationType & MEM_COMMIT))
        prot = PROT_NONE;
    else if (Protect & NT_PAGE_EXECUTE_READ || Protect & NT_PAGE_EXECUTE_WRITECOPY)
        prot = PROT_EXEC | PROT_READ;
    else if (Protect & NT_PAGE_EXECUTE_READWRITE)
        prot = PROT_EXEC | PROT_READ | PROT_WRITE;
    else if (Protect & NT_PAGE_READONLY || Protect & NT_PAGE_WRITECOPY)
        prot = PROT_READ;
    else if (Protect & NT_PAGE_READWRITE)
        prot = PROT_READ | PROT_WRITE;
    else {
        printk("NtAllocateVirtualMemory: unhandled Protect value %x\n", Protect);
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    // check if committing previously reserved memory
    if (addr && prot != PROT_NONE) {
        down_write(&p->mapping_list_sem);

        le = p->mapping_list.next;
        while (le != &p->mapping_list) {
            section_map* sm2 = list_entry(le, section_map, list);

            if (sm2->address <= addr && sm2->address + sm2->length >= addr + size && !sm2->sect) {
                unsigned long off = (addr - sm2->address) / PAGE_SIZE;
                bool committing = !sm2->committed;

                if (committing) {
                    ret = vm_mmap(NULL, (uintptr_t)addr, size, prot, MAP_PRIVATE | MAP_FIXED, 0);
                    if (IS_ERR((void*)ret)) {
                        Status = muwine_error_to_ntstatus(ret);
                        goto end;
                    }

                    if (addr == sm2->address && size == sm2->length) // commiting whole entry
                        sm2->committed = true;
                    else {
                        if (off > 0) { // add entry before
                            map = kmalloc(sizeof(section_map), GFP_KERNEL);
                            if (!map) {
                                up_write(&p->mapping_list_sem);
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            map->address = sm2->address;
                            map->length = addr - sm2->address;
                            map->sect = NULL;
                            map->file_offset = 0;
                            map->committed = false;

                            list_add(&map->list, sm2->list.prev);

                            sm2->length -= addr - sm2->address;
                            sm2->address = addr;
                        }

                        // add new entry

                        map = kmalloc(sizeof(section_map), GFP_KERNEL);
                        if (!map) {
                            up_write(&p->mapping_list_sem);
                            Status = STATUS_INSUFFICIENT_RESOURCES;
                            goto end;
                        }

                        map->address = addr;
                        map->length = size;
                        map->sect = NULL;
                        map->file_offset = 0;
                        map->committed = true;

                        list_add(&map->list, sm2->list.prev);

                        // add entry after

                        if (addr + size < sm2->address + sm2->length) {
                            map = kmalloc(sizeof(section_map), GFP_KERNEL);
                            if (!map) {
                                up_write(&p->mapping_list_sem);
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            map->address = addr + size;
                            map->length = sm2->address + sm2->length - addr - size;
                            map->sect = NULL;
                            map->file_offset = 0;
                            map->committed = false;

                            list_add(&map->list, sm2->list.prev);
                        }

                        list_del(&sm2->list);
                        kfree(sm2);
                    }

                    *BaseAddress = (void*)addr;
                    *RegionSize = size;

                    up_write(&p->mapping_list_sem);

                    Status = STATUS_SUCCESS;
                    goto end;
                }
            }

            le = le->next;
        }

        up_write(&p->mapping_list_sem);
    }

    map = kmalloc(sizeof(section_map), GFP_KERNEL);
    if (!map) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    flags = MAP_PRIVATE;

    if (addr)
        flags |= MAP_FIXED_NOREPLACE;

    ret = vm_mmap(NULL, addr, size, prot, flags, 0);
    if (IS_ERR((void*)ret)) {
        kfree(map);

        if (ret == -EEXIST)
            Status = STATUS_CONFLICTING_ADDRESSES;
        else
            Status = muwine_error_to_ntstatus(ret);

        goto end;
    }

    map->address = ret;
    map->length = size;
    map->sect = NULL;
    map->file_offset = 0;
    map->committed = prot != PROT_NONE;

    *BaseAddress = (void*)ret;
    *RegionSize = size;

    down_write(&p->mapping_list_sem);

    le = p->mapping_list.next;
    while (le != &p->mapping_list) {
        section_map* sm2 = list_entry(le, section_map, list);

        if (sm2->address > map->address) {
            list_add(&map->list, le->prev);
            up_write(&p->mapping_list_sem);

            Status = STATUS_SUCCESS;
            goto end;
        }

        le = le->next;
    }

    list_add_tail(&map->list, &p->mapping_list);
    up_write(&p->mapping_list_sem);

    Status = STATUS_SUCCESS;

end:
    dec_obj_refcount(&p->header.h);

    return Status;
}

NTSTATUS user_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    NTSTATUS Status;
    void* addr;
    SIZE_T size;

    if (!BaseAddress || !RegionSize)
        return STATUS_INVALID_PARAMETER;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (get_user(addr, BaseAddress) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (get_user(size, RegionSize) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtAllocateVirtualMemory(ProcessHandle, &addr, ZeroBits, &size,
                                     AllocationType, Protect);

    if (put_user(addr, BaseAddress) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(size, RegionSize) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                             PSIZE_T RegionSize, ULONG FreeType) {
    process_object* p;
    uintptr_t addr = (uintptr_t)*BaseAddress;
    size_t size = *RegionSize;
    struct list_head* le;
    section_map* sm = NULL;

    if (ProcessHandle == NtCurrentProcess()) {
        p = muwine_current_process_object();

        if (!p)
            return STATUS_INTERNAL_ERROR;
    } else {
        printk("NtFreeVirtualMemory: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    if (addr % PAGE_SIZE) {
        size += addr % PAGE_SIZE;
        addr -= addr % PAGE_SIZE;
    }

    if (size % PAGE_SIZE)
        size += PAGE_SIZE - (size % PAGE_SIZE);

    down_write(&p->mapping_list_sem);

    le = p->mapping_list.next;
    while (le != &p->mapping_list) {
        section_map* sm2 = list_entry(le, section_map, list);

        if (addr >= sm2->address && addr < sm2->address + sm2->length && !sm2->sect) {
            sm = sm2;
            list_del(&sm->list);
            break;
        }

        le = le->next;
    }

    up_write(&p->mapping_list_sem);

    dec_obj_refcount(&p->header.h);

    if (!sm)
        return STATUS_INVALID_PARAMETER;

    vm_munmap(sm->address, sm->length);

    *BaseAddress = (void*)sm->address;
    *RegionSize = sm->length;

    kfree(sm);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
                                  ULONG FreeType) {
    NTSTATUS Status;
    void* addr;
    size_t size;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!BaseAddress || !RegionSize)
        return STATUS_INVALID_PARAMETER;

    if (get_user(addr, BaseAddress) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (get_user(size, RegionSize) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtFreeVirtualMemory(ProcessHandle, &addr, &size, FreeType);

    if (put_user(addr, BaseAddress) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(size, RegionSize) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS init_user_shared_data(void) {
    NTSTATUS Status;
    HANDLE h;
    LARGE_INTEGER size;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;

    static const WCHAR usd[] = L"\\KernelObjects\\__wine_user_shared_data";

    us.Buffer = (WCHAR*)usd;
    us.Length = us.MaximumLength = sizeof(usd) - sizeof(WCHAR);

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_KERNEL_HANDLE | OBJ_PERMANENT;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    size.QuadPart = PAGE_SIZE; // FIXME - should be size of KUSER_SHARED_DATA struct

    Status = NtCreateSection(&h, SECTION_MAP_WRITE, &oa, &size, NT_PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    NtClose(h);

    // FIXME - spawn thread updating time every second

    return STATUS_SUCCESS;
}

NTSTATUS muwine_init_sections(void) {
    NTSTATUS Status;
    UNICODE_STRING us;

    static const WCHAR sect_name[] = L"Section";

    us.Length = us.MaximumLength = sizeof(sect_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)sect_name;

    section_type = muwine_add_object_type(&us, section_object_close, NULL,
                                          SECTION_GENERIC_READ, SECTION_GENERIC_WRITE,
                                          SECTION_GENERIC_EXECUTE, SECTION_ALL_ACCESS,
                                          SECTION_ALL_ACCESS);
    if (IS_ERR(section_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)section_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)section_type);
    }

    Status = init_user_shared_data();
    if (!NT_SUCCESS(Status))
        return Status;

    Status = get_func_ptr("mprotect_fixup", (void**)&_mprotect_fixup);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}
