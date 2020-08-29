#include "muwine.h"

static uintptr_t next_kernel_handle_no = KERNEL_HANDLE_MASK;

static LIST_HEAD(kernel_handle_list);
static DEFINE_SPINLOCK(kernel_handle_list_lock);

NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h, bool kernel, ACCESS_MASK access) {
    handle* hand;
    spinlock_t* lock;
    uintptr_t* next_handle;
    struct list_head* list;

    if (kernel) {
        lock = &kernel_handle_list_lock;
        next_handle = &next_kernel_handle_no;
        list = &kernel_handle_list;
    } else {
        process* p = muwine_current_process();

        if (!p)
            return STATUS_INTERNAL_ERROR;

        lock = &p->handle_list_lock;
        next_handle = &p->next_handle_no;
        list = &p->handle_list;
    }

    // add entry to handle list for pid

    hand = kmalloc(sizeof(handle), GFP_KERNEL);
    if (!hand)
        return STATUS_INSUFFICIENT_RESOURCES;

    hand->object = obj;
    hand->access = access;

    spin_lock(lock);

    hand->number = *next_handle;
    *next_handle += 4;

    list_add_tail(&hand->list, list);

    spin_unlock(lock);

    *h = (HANDLE)hand->number;

    __sync_add_and_fetch(&obj->handle_count, 1);

    return STATUS_SUCCESS;
}

object_header* get_object_from_handle(HANDLE h, ACCESS_MASK* access) {
    struct list_head* le;
    spinlock_t* lock;
    struct list_head* list;

    if ((uintptr_t)h & KERNEL_HANDLE_MASK) {
        lock = &kernel_handle_list_lock;
        list = &kernel_handle_list;
    } else {
        process* p = muwine_current_process();

        if (!p)
            return NULL;

        lock = &p->handle_list_lock;
        list = &p->handle_list;
    }

    // get handle from list

    spin_lock(lock);

    le = list->next;

    while (le != list) {
        handle* h2 = list_entry(le, handle, list);

        if (h2->number == (uintptr_t)h) {
            object_header* obj = h2->object;

            *access = h2->access;

            spin_unlock(lock);

            return obj;
        }

        le = le->next;
    }

    spin_unlock(lock);

    return NULL;
}

NTSTATUS NtClose(HANDLE Handle) {
    struct list_head* le;
    handle* h = NULL;
    spinlock_t* lock;
    struct list_head* list;

    if ((uintptr_t)h & KERNEL_HANDLE_MASK) {
        lock = &kernel_handle_list_lock;
        list = &kernel_handle_list;
    } else {
        process* p = muwine_current_process();

        if (!p)
            return STATUS_INTERNAL_ERROR;

        lock = &p->handle_list_lock;
        list = &p->handle_list;
    }

    // get handle from list

    spin_lock(lock);

    le = list->next;

    while (le != list) {
        handle* h2 = list_entry(le, handle, list);

        if (h2->number == (uintptr_t)Handle) {
            list_del(&h2->list);
            h = h2;
            break;
        }

        le = le->next;
    }

    spin_unlock(lock);

    if (!h)
        return STATUS_INVALID_HANDLE;

    if (__sync_sub_and_fetch(&h->object->handle_count, 1) == 0) {
        if (h->object->type->cleanup)
            h->object->type->cleanup(h->object);
    }

    if (__sync_sub_and_fetch(&h->object->refcount, 1) == 0)
        h->object->type->close(h->object);

    kfree(h);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtClose(HANDLE Handle) {
    if ((uintptr_t)Handle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    return NtClose(Handle);
}

void muwine_free_kernel_handles(void) {
    while (!list_empty(&kernel_handle_list)) {
        handle* hand = list_entry(kernel_handle_list.next, handle, list);

        list_del(&hand->list);

        if (__sync_sub_and_fetch(&hand->object->handle_count, 1) == 0) {
            if (hand->object->type->cleanup)
                hand->object->type->cleanup(hand->object);
        }

        if (__sync_sub_and_fetch(&hand->object->refcount, 1) == 0)
            hand->object->type->close(hand->object);

        kfree(hand);
    }
}

NTSTATUS NtWaitForMultipleObjects(ULONG ObjectCount, PHANDLE ObjectsArray,
                                  OBJECT_WAIT_TYPE WaitType, BOOLEAN Alertable,
                                  PLARGE_INTEGER TimeOut) {
    printk(KERN_INFO "NtWaitForMultipleObjects(%x, %px, %x, %x, %px): stub\n", ObjectCount,
           ObjectsArray, WaitType, Alertable, TimeOut);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    printk(KERN_INFO "NtWaitForSingleObject(%lx, %x, %px): stub\n", (uintptr_t)ObjectHandle,
           Alertable, TimeOut);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    LARGE_INTEGER to;

    if ((uintptr_t)ObjectHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (TimeOut && get_user(to.QuadPart, &TimeOut->QuadPart) < 0)
        return STATUS_ACCESS_VIOLATION;

    return NtWaitForSingleObject(ObjectHandle, Alertable, TimeOut ? &to : NULL);
}
