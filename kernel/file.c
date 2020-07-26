#include "muwine.h"

NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                      PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                      ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                      PVOID EaBuffer, ULONG EaLength) {
    NTSTATUS Status;
    UNICODE_STRING us;
    WCHAR* oa_us_alloc = NULL;

    static const WCHAR prefix[] = L"\\Device\\UnixRoot";

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        object_header* obj = get_object_from_handle(ObjectAttributes->RootDirectory);
        if (!obj || obj->type != muwine_object_file)
            return STATUS_INVALID_HANDLE;

        us.Length = obj->path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        memcpy(us.Buffer, obj->path.Buffer, obj->path.Length);
        us.Buffer[obj->path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(obj->path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    // FIXME - resolve symlinks
    // FIXME - check against object manager devices

    if (us.Length <= sizeof(prefix) - sizeof(WCHAR)) {
        Status = STATUS_OBJECT_PATH_INVALID;
        goto end;
    }

    if (wcsnicmp(us.Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1)) {
        Status = STATUS_OBJECT_PATH_INVALID;
        goto end;
    }

    us.Buffer += (sizeof(prefix) / sizeof(WCHAR)) - 1;
    us.Length -= sizeof(prefix) - sizeof(WCHAR);

    if (us.Length >= sizeof(WCHAR) && us.Buffer[0] != '\\') {
        Status = STATUS_OBJECT_PATH_INVALID;
        goto end;
    }

    Status = unixfs_create_file(FileHandle, DesiredAccess, &us, IoStatusBlock, AllocationSize, FileAttributes,
                                ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

end:
    if (oa_us_alloc)
        kfree(oa_us_alloc);

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

NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                    PULONG Key) {
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    // FIXME - get FS device from object

    return unixfs_read(obj, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length,
                       ByteOffset, Key);
}

NTSTATUS NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
                                ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    file_object* obj = (file_object*)get_object_from_handle(FileHandle);
    if (!obj || obj->header.type != muwine_object_file)
        return STATUS_INVALID_HANDLE;

    // FIXME - get FS device from object

    return unixfs_query_information(obj, IoStatusBlock, FileInformation, Length,
                                    FileInformationClass);
}
