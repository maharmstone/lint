#include "muwine.h"

LIST_HEAD(dev_list);
DEFINE_SPINLOCK(dev_list_lock);

NTSTATUS muwine_add_device(device* dev) {
    // FIXME - calculate depth
    // FIXME - store devices in reverse order of depth

    spin_lock(&dev_list_lock);
    list_add_tail(&dev->list, &dev_list);
    spin_unlock(&dev_list_lock);

    return STATUS_SUCCESS;
}

void muwine_free_objs(void) {
    spin_lock(&dev_list_lock);

    while (!list_empty(&dev_list)) {
        device* dev = list_entry(dev_list.next, device, list);

        list_del(&dev->list);

        kfree(dev->path.Buffer);
        kfree(dev);
    }

    spin_unlock(&dev_list_lock);
}

NTSTATUS muwine_find_device(UNICODE_STRING* us, device** dev) {
    struct list_head* le;

    // FIXME - resolve symlinks

    spin_lock(&dev_list_lock);

    le = dev_list.next;
    while (le != &dev_list) {
        device* d = list_entry(le, device, list);

        if (us->Length < d->path.Length) {
            le = le->next;
            continue;
        }

        if (wcsnicmp(us->Buffer, d->path.Buffer, d->path.Length / sizeof(WCHAR))) {
            le = le->next;
            continue;
        }

        if (us->Length > d->path.Length && us->Buffer[d->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        us->Buffer += d->path.Length / sizeof(WCHAR);
        us->Length -= d->path.Length;

        *dev = d;

        spin_unlock(&dev_list_lock);

        return STATUS_SUCCESS;
    }

    spin_unlock(&dev_list_lock);

    return STATUS_OBJECT_PATH_NOT_FOUND;
}

NTSTATUS NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtCreateDirectoryObject(%lx, %x, %px): stub\n", (uintptr_t)DirectoryHandle,
           DesiredAccess, ObjectAttributes);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;

    if (!DirectoryHandle || !ObjectAttributes)
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

    Status = NtCreateDirectoryObject(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, DirectoryHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                    PUNICODE_STRING DestinationName) {
    printk(KERN_INFO "NtCreateSymbolicLinkObject(%lx, %x, %px, %px): stub\n", (uintptr_t)pHandle, DesiredAccess,
           ObjectAttributes, DestinationName);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtCreateSymbolicLinkObject(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                                         PUNICODE_STRING DestinationName) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING dest;

    if (!pHandle || !ObjectAttributes || !DestinationName)
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

    if (!get_user_unicode_string(&dest, DestinationName)) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_ACCESS_VIOLATION;
    }

    Status = NtCreateSymbolicLinkObject(&h, DesiredAccess, &oa, &dest);

    if (DestinationName && dest.Buffer)
        kfree(dest.Buffer);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, pHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}
