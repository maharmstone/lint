#include "muwine.h"

extern type_object* device_type;
extern type_object* file_type;

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                      ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                      PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS Status;
    UNICODE_STRING us, after;
    WCHAR* oa_us_alloc = NULL;
    device* dev;
    bool after_alloc = false;

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        object_header* obj = get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!obj)
            return STATUS_INVALID_HANDLE;

        if (obj->type != file_type) {
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

    Status = muwine_open_object(&us, (object_header**)&dev, &after, &after_alloc, false);
    if (!NT_SUCCESS(Status))
        goto end;

    if (dev->header.type != device_type) {
        dec_obj_refcount(&dev->header);
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    if (!dev->create) {
        dec_obj_refcount(&dev->header);
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    DesiredAccess = sanitize_access_mask(DesiredAccess, file_type);

    Status = dev->create(dev, FileHandle, DesiredAccess, &after, IoStatusBlock, AllocationSize, FileAttributes,
                         ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength,
                         ObjectAttributes->Attributes);

    dec_obj_refcount(&dev->header);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

    if (after_alloc)
        kfree(after.Buffer);

    return Status;
}

NTSTATUS user_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                           PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                           ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                           PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER alloc;
    void* ea = NULL;

    if (!FileHandle || !ObjectAttributes || !IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (AllocationSize) {
        if (copy_from_user(&alloc.QuadPart, &AllocationSize->QuadPart, sizeof(int64_t)) != 0)
            return STATUS_ACCESS_VIOLATION;
    }

    if (EaBuffer && EaLength > 0) {
        ea = kmalloc(EaLength, GFP_KERNEL);
        if (!ea)
            return STATUS_INSUFFICIENT_RESOURCES;

        if (copy_from_user(ea, EaBuffer, EaLength) != 0)
            return STATUS_ACCESS_VIOLATION;
    }

    if (!get_user_object_attributes(&oa, ObjectAttributes)) {
        if (ea)
            kfree(ea);

        return STATUS_ACCESS_VIOLATION;
    }

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (ea)
            kfree(ea);

        free_object_attributes(&oa);

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateFile(&h, DesiredAccess, &oa, &iosb, AllocationSize ? &alloc : NULL, FileAttributes,
                          ShareAccess, CreateDisposition, CreateOptions, ea, EaLength);

    if (ea)
        kfree(ea);

    free_object_attributes(&oa);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(h, FileHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, NULL, 0);
}

NTSTATUS user_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                         PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    if (!FileHandle || !ObjectAttributes || !IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenFile(&h, DesiredAccess, &oa, &iosb, ShareAccess, OpenOptions);

    free_object_attributes(&oa);

    if (put_user(h, FileHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->read) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = obj->dev->read(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length,
                            ByteOffset, Key);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                         PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                         PULONG Key) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    uint8_t* buf = NULL;
    LARGE_INTEGER off;
    ULONG key;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (ByteOffset) {
        if (copy_from_user(&off.QuadPart, &ByteOffset->QuadPart, sizeof(int64_t)) != 0)
            return STATUS_ACCESS_VIOLATION;
    }

    if (Key) {
        if (get_user(key, Key) < 0)
            return STATUS_ACCESS_VIOLATION;
    }

    iosb.Information = 0;

    Status = NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, &iosb, buf, Length,
                        ByteOffset ? &off : NULL, Key ? &key : NULL);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf) {
        if (copy_to_user(Buffer, buf, iosb.Information) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    return Status;
}

NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->query_information) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = obj->dev->query_information(obj, access, IoStatusBlock, FileInformation,
                                         Length, FileInformationClass);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                     ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    uint8_t* buf = NULL;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    iosb.Information = 0;

    Status = NtQueryInformationFile(FileHandle, &iosb, buf, Length, FileInformationClass);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf) {
        if (copy_to_user(FileInformation, buf, iosb.Information) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    return Status;
}

NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                     PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                     PULONG Key) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->write) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = obj->dev->write(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length,
                             ByteOffset, Key);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                          PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                          PULONG Key) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    uint8_t* buf = NULL;
    LARGE_INTEGER off;
    ULONG key;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!IoStatusBlock)
        return STATUS_INVALID_PARAMETER;

    if (ByteOffset) {
        if (copy_from_user(&off.QuadPart, &ByteOffset->QuadPart, sizeof(int64_t)) != 0)
            return STATUS_ACCESS_VIOLATION;
    }

    if (Key) {
        if (get_user(key, Key) < 0)
            return STATUS_ACCESS_VIOLATION;
    }

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;

        if (copy_from_user(buf, Buffer, Length) != 0) {
            kfree(buf);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    Status = NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, &iosb, buf, Length,
                         ByteOffset ? &off : NULL, Key ? &key : NULL);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf)
        kfree(buf);

    return Status;
}

NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                              ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->set_information) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    if (FileInformationClass == FileRenameInformation) {
        FILE_RENAME_INFORMATION* fri = FileInformation;
        UNICODE_STRING us;
        bool us_alloc = false;
        ULONG fri2len;
        FILE_RENAME_INFORMATION* fri2;

        if (Length < offsetof(FILE_RENAME_INFORMATION, FileName)) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        if (Length < offsetof(FILE_RENAME_INFORMATION, FileName) + fri->FileNameLength) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        if (fri->RootDirectory) {
            ACCESS_MASK dir_access;
            file_object* obj2 = (file_object*)get_object_from_handle(fri->RootDirectory, &dir_access);

            if (!obj2) {
                Status = STATUS_INVALID_HANDLE;
                goto end;
            }

            if (obj2->header.type != file_type) {
                dec_obj_refcount(&obj2->header);
                Status = STATUS_INVALID_HANDLE;
                goto end;
            }

            spin_lock(&obj2->header.header_lock);

            us.Length = obj2->header.path.Length + sizeof(WCHAR) + fri->FileNameLength;
            us.Buffer = kmalloc(us.Length, GFP_KERNEL);

            if (!us.Buffer) {
                spin_unlock(&obj2->header.header_lock);
                dec_obj_refcount(&obj2->header);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            memcpy(us.Buffer, obj2->header.path.Buffer, obj2->header.path.Length);
            us.Buffer[obj2->header.path.Length / sizeof(WCHAR)] = '\\';
            memcpy(&us.Buffer[obj2->header.path.Length / sizeof(WCHAR)],
                   fri->FileName, fri->FileNameLength);

            spin_unlock(&obj2->header.header_lock);

            us_alloc = true;

            dec_obj_refcount(&obj2->header);
        } else {
            // FIXME - resolve device symlinks in FileName
            us.Buffer = fri->FileName;
            us.Length = fri->FileNameLength;
        }

        // check same device, and return STATUS_NOT_SAME_DEVICE if not

        if (us.Length < obj->dev->header.path.Length) {
            if (us_alloc)
                kfree(us.Buffer);

            Status = STATUS_NOT_SAME_DEVICE;
            goto end;
        }

        if (wcsnicmp(us.Buffer, obj->dev->header.path.Buffer, obj->dev->header.path.Length / sizeof(WCHAR)) ||
            (us.Length > obj->dev->header.path.Length && us.Buffer[obj->dev->header.path.Length / sizeof(WCHAR)] != '\\')) {
            if (us_alloc)
                kfree(us.Buffer);

            Status = STATUS_NOT_SAME_DEVICE;
            goto end;
        }

        fri2len = offsetof(FILE_RENAME_INFORMATION, FileName) + us.Length - obj->dev->header.path.Length;

        fri2 = kmalloc(fri2len, GFP_KERNEL);
        if (!fri2) {
            if (us_alloc)
                kfree(us.Buffer);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        fri2->ReplaceIfExists = fri->ReplaceIfExists;
        fri2->RootDirectory = NULL;
        fri2->FileNameLength = us.Length - obj->dev->header.path.Length;
        memcpy(fri2->FileName, us.Buffer + (obj->dev->header.path.Length / sizeof(WCHAR)), fri2->FileNameLength);

        if (us_alloc)
            kfree(us.Buffer);

        // pass device-relative filename to unixfs_set_information

        Status = obj->dev->set_information(obj, access, IoStatusBlock, fri2, fri2len, FileInformationClass);

        kfree(fri2);
    } else
        Status = obj->dev->set_information(obj, access, IoStatusBlock, FileInformation, Length, FileInformationClass);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                   ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    void* buf = NULL;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;

        if (copy_from_user(buf, FileInformation, Length) != 0) {
            kfree(buf);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    if (FileInformationClass == FileRenameInformation) {
        FILE_RENAME_INFORMATION* fri = buf;

        if (Length >= offsetof(FILE_RENAME_INFORMATION, FileName) && (uintptr_t)fri->RootDirectory & KERNEL_HANDLE_MASK) {
            kfree(buf);
            return STATUS_INVALID_HANDLE;
        }
    }

    Status = NtSetInformationFile(FileHandle, &iosb, buf, Length, FileInformationClass);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf)
        kfree(buf);

    return Status;
}

NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                              PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                              FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                              PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->query_directory) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = obj->dev->query_directory(obj, Event, ApcRoutine, ApcContext, IoStatusBlock,
                                       FileInformation, Length, FileInformationClass,
                                       ReturnSingleEntry, FileMask, RestartScan);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                   PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                   FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                   PUNICODE_STRING FileMask, BOOLEAN RestartScan) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    uint8_t* buf = NULL;
    UNICODE_STRING mask;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (FileMask) {
        if (!get_user_unicode_string(&mask, FileMask)) {
            if (buf)
                kfree(buf);

            return STATUS_ACCESS_VIOLATION;
        }
    }

    iosb.Information = 0;

    Status = NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, &iosb, buf, Length,
                                  FileInformationClass, ReturnSingleEntry, FileMask ? &mask : NULL,
                                  RestartScan);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf) {
        if (copy_to_user(FileInformation, buf, iosb.Information) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    if (FileMask && mask.Buffer)
        kfree(mask.Buffer);

    return Status;
}

static NTSTATUS NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                             ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    NTSTATUS Status;
    ACCESS_MASK access;
    file_object* obj = (file_object*)get_object_from_handle(FileHandle, &access);

    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (obj->header.type != file_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!obj->dev->query_volume_information) {
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = obj->dev->query_volume_information(obj, IoStatusBlock, FsInformation, Length,
                                                FsInformationClass);

end:
    dec_obj_refcount(&obj->header);

    return Status;
}

NTSTATUS user_NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                           ULONG Length, FS_INFORMATION_CLASS FsInformationClass) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    void* buf = NULL;

    if (!IoStatusBlock || !FsInformation)
        return STATUS_INVALID_PARAMETER;

    if ((uintptr_t)FileHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    iosb.Information = 0;

    Status = NtQueryVolumeInformationFile(FileHandle, &iosb, buf, Length, FsInformationClass);

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (buf) {
        if (copy_to_user(FsInformation, buf, iosb.Information) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    return Status;
}

NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                               PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                               PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                               ULONG OutputBufferLength) {
    printk(KERN_INFO "NtDeviceIoControlFile(%lx, %lx, %px, %px, %px, %x, %px, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           IoControlCode, InputBuffer, InputBufferLength, OutputBuffer,
           OutputBufferLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                         PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                         ULONG OutputBufferLength) {
    printk(KERN_INFO "NtFsControlFile(%lx, %lx, %px, %px, %px, %x, %px, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           IoControlCode, InputBuffer, InputBufferLength, OutputBuffer,
           OutputBufferLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetVolumeInformationFile(HANDLE hFile, PIO_STATUS_BLOCK io, PVOID ptr, ULONG len,
                                    FILE_INFORMATION_CLASS FileInformationClass) {
    printk(KERN_INFO "NtSetVolumeInformationFile(%lx, %px, %px, %x, %x): stub\n",
           (uintptr_t)hFile, io, ptr, len, FileInformationClass);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                    PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately,
                    BOOLEAN ExclusiveLock) {
    printk(KERN_INFO "NtLockFile(%lx, %lx, %px, %px, %px, %px, %px, %x, %x, %x): stub\n",
           (uintptr_t)FileHandle, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           ByteOffset, Length, Key, FailImmediately, ExclusiveLock);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                     ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList,
                                     ULONG SidListLength, SID* StartSid, BOOLEAN RestartScan) {
    printk(KERN_INFO "NtQueryQuotaInformationFile(%lx, %px, %px, %x, %x, %px, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, SidList,
           SidListLength, StartSid, RestartScan);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                                   ULONG Length) {
    printk(KERN_INFO "NtSetQuotaInformationFile(%lx, %px, %px, %x): stub\n",
           (uintptr_t)FileHandle, IoStatusBlock, Buffer, Length);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
                      PLARGE_INTEGER Length, ULONG Key) {
    printk(KERN_INFO "NtUnlockFile(%lx, %px, %px, %px, %x): stub\n", (uintptr_t)FileHandle,
           IoStatusBlock, ByteOffset, Length, Key);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtDeleteFile(%px): stub\n", ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    printk(KERN_INFO "NtFlushBuffersFile(%lx, %px): stub\n", (uintptr_t)FileHandle, IoStatusBlock);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                      FILE_BASIC_INFORMATION* FileInformation) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;

    Status = NtOpenFile(&h, FILE_READ_ATTRIBUTES, ObjectAttributes, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtQueryInformationFile(h, &iosb, FileInformation, sizeof(FILE_BASIC_INFORMATION),
                                    FileBasicInformation);

    NtClose(h);

    return Status;
}

NTSTATUS user_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                    FILE_BASIC_INFORMATION* FileInformation) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    FILE_BASIC_INFORMATION fbi;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtQueryAttributesFile(&oa, &fbi);

    free_object_attributes(&oa);

    if (copy_to_user(FileInformation, &fbi, sizeof(FILE_BASIC_INFORMATION)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                       ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength,
                       PULONG EaIndex, BOOLEAN RestartScan) {
    printk(KERN_INFO "NtQueryEaFile(%lx, %px, %px, %x, %x, %px, %x, %px, %x): stub\n",
           (uintptr_t)FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry,
           EaList, EaListLength, EaIndex, RestartScan);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                          FILE_NETWORK_OPEN_INFORMATION* FileInformation) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;

    Status = NtOpenFile(&h, FILE_READ_ATTRIBUTES, ObjectAttributes, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtQueryInformationFile(h, &iosb, FileInformation,
                                    sizeof(FILE_NETWORK_OPEN_INFORMATION),
                                    FileNetworkOpenInformation);

    NtClose(h);

    return Status;
}

NTSTATUS user_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                        FILE_NETWORK_OPEN_INFORMATION* FileInformation) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    FILE_NETWORK_OPEN_INFORMATION fnoi;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtQueryFullAttributesFile(&oa, &fnoi);

    free_object_attributes(&oa);

    if (copy_to_user(FileInformation, &fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                     ULONG Length) {
    printk(KERN_INFO "NtSetEaFile(%lx, %px, %px, %x): stub\n", (uintptr_t)FileHandle,
           IoStatusBlock, Buffer, Length);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
