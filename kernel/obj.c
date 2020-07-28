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
