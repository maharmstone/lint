#include "muwine.h"

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
        object_header* obj = get_object_from_handle(ObjectAttributes->RootDirectory);
        if (!obj || obj->type != muwine_object_file)
            return STATUS_INVALID_HANDLE;

        spin_lock(&obj->path_lock);

        us.Length = obj->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&obj->path_lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, obj->path.Buffer, obj->path.Length);
        us.Buffer[obj->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(obj->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&obj->path_lock);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    Status = muwine_open_object(&us, (object_header**)&dev, &after, &after_alloc);
    if (!NT_SUCCESS(Status))
        goto end;

    if (dev->header.type != muwine_object_device) {
        if (__sync_sub_and_fetch(&dev->header.refcount, 1) == 0)
            dev->header.close(&dev->header);

        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    if (!dev->create) {
        if (__sync_sub_and_fetch(&dev->header.refcount, 1) == 0)
            dev->header.close(&dev->header);

        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    Status = dev->create(dev, FileHandle, DesiredAccess, &after, IoStatusBlock, AllocationSize, FileAttributes,
                         ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength,
                         ObjectAttributes->Attributes);

    if (__sync_sub_and_fetch(&dev->header.refcount, 1) == 0)
        dev->header.close(&dev->header);

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

        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateFile(&h, DesiredAccess, &oa, &iosb, AllocationSize ? &alloc : NULL, FileAttributes,
                          ShareAccess, CreateDisposition, CreateOptions, ea, EaLength);

    if (ea)
        kfree(ea);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

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
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenFile(&h, DesiredAccess, &oa, &iosb, ShareAccess, OpenOptions);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, FileHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (copy_to_user(IoStatusBlock, &iosb, sizeof(IO_STATUS_BLOCK)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key) {
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    if (!obj->dev->read)
        return STATUS_NOT_IMPLEMENTED;

    return obj->dev->read(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length,
                          ByteOffset, Key);
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
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    if (!obj->dev->query_information)
        return STATUS_NOT_IMPLEMENTED;

    return obj->dev->query_information(obj, IoStatusBlock, FileInformation, Length,
                                       FileInformationClass);
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
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    if (!obj->dev->write)
        return STATUS_NOT_IMPLEMENTED;

    return obj->dev->write(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length,
                           ByteOffset, Key);
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
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    if (!obj->dev->set_information)
        return STATUS_NOT_IMPLEMENTED;

    if (FileInformationClass == FileRenameInformation) {
        NTSTATUS Status;
        FILE_RENAME_INFORMATION* fri = FileInformation;
        UNICODE_STRING us;
        bool us_alloc = false;
        ULONG fri2len;
        FILE_RENAME_INFORMATION* fri2;

        if (Length < offsetof(FILE_RENAME_INFORMATION, FileName))
            return STATUS_INVALID_PARAMETER;

        if (Length < offsetof(FILE_RENAME_INFORMATION, FileName) + fri->FileNameLength)
            return STATUS_INVALID_PARAMETER;

        if (fri->RootDirectory) {
            file_object* obj2 = (file_object*)get_object_from_handle(fri->RootDirectory);
            if (!obj2 || obj2->header.type != muwine_object_file)
                return STATUS_INVALID_HANDLE;

            spin_lock(&obj2->header.path_lock);

            us.Length = obj2->header.path.Length + sizeof(WCHAR) + fri->FileNameLength;
            us.Buffer = kmalloc(us.Length, GFP_KERNEL);

            if (!us.Buffer) {
                spin_unlock(&obj2->header.path_lock);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            memcpy(us.Buffer, obj2->header.path.Buffer, obj2->header.path.Length);
            us.Buffer[obj2->header.path.Length / sizeof(WCHAR)] = '\\';
            memcpy(&us.Buffer[obj2->header.path.Length / sizeof(WCHAR)],
                   fri->FileName, fri->FileNameLength);

            spin_unlock(&obj2->header.path_lock);

            us_alloc = true;
        } else {
            // FIXME - resolve device symlinks in FileName
            us.Buffer = fri->FileName;
            us.Length = fri->FileNameLength;
        }

        // check same device, and return STATUS_NOT_SAME_DEVICE if not

        if (us.Length < obj->dev->header.path.Length) {
            if (us_alloc)
                kfree(us.Buffer);

            return STATUS_NOT_SAME_DEVICE;
        }

        if (wcsnicmp(us.Buffer, obj->dev->header.path.Buffer, obj->dev->header.path.Length / sizeof(WCHAR)) ||
            (us.Length > obj->dev->header.path.Length && us.Buffer[obj->dev->header.path.Length / sizeof(WCHAR)] != '\\')) {
            if (us_alloc)
                kfree(us.Buffer);

            return STATUS_NOT_SAME_DEVICE;
        }

        fri2len = offsetof(FILE_RENAME_INFORMATION, FileName) + us.Length - obj->dev->header.path.Length;

        fri2 = kmalloc(fri2len, GFP_KERNEL);
        if (!fri2) {
            if (us_alloc)
                kfree(us.Buffer);

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        fri2->ReplaceIfExists = fri->ReplaceIfExists;
        fri2->RootDirectory = NULL;
        fri2->FileNameLength = us.Length - obj->dev->header.path.Length;
        memcpy(fri2->FileName, us.Buffer + (obj->dev->header.path.Length / sizeof(WCHAR)), fri2->FileNameLength);

        if (us_alloc)
            kfree(us.Buffer);

        // pass device-relative filename to unixfs_set_information

        Status = obj->dev->set_information(obj, IoStatusBlock, fri2, fri2len, FileInformationClass);

        kfree(fri2);

        return Status;
    } else
        return obj->dev->set_information(obj, IoStatusBlock, FileInformation, Length, FileInformationClass);
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

    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    if (!obj->dev->query_directory)
        return STATUS_NOT_IMPLEMENTED;

    Status = obj->dev->query_directory(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
                                     Length, FileInformationClass, ReturnSingleEntry, FileMask,
                                     RestartScan);

    printk(KERN_INFO "query_directory returned %08x\n", Status);

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
    printk(KERN_INFO "NtQueryVolumeInformationFile(%lx, %px, %px, %x, %x): stub\n", (uintptr_t)FileHandle,
           IoStatusBlock, FsInformation, Length, FsInformationClass);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
