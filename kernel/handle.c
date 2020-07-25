#include "muwine.h"

NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h) {
    process* p = muwine_current_process();
    handle* hand;

    if (!p)
        return STATUS_INTERNAL_ERROR;

    // add entry to handle list for pid

    hand = kmalloc(sizeof(handle), GFP_KERNEL);
    if (!hand)
        return STATUS_INSUFFICIENT_RESOURCES;

    hand->object = obj;

    spin_lock(&p->handle_list_lock);

    hand->number = p->next_handle_no;
    p->next_handle_no += 4;

    list_add_tail(&hand->list, &p->handle_list);

    spin_unlock(&p->handle_list_lock);

    *h = (HANDLE)hand->number;

    return STATUS_SUCCESS;
}

object_header* get_object_from_handle(HANDLE h) {
    struct list_head* le;
    process* p = muwine_current_process();

    if (!p)
        return NULL;

    // get handle from list

    spin_lock(&p->handle_list_lock);

    le = p->handle_list.next;

    while (le != &p->handle_list) {
        handle* h2 = list_entry(le, handle, list);

        if (h2->number == (uintptr_t)h) {
            object_header* obj = h2->object;

            spin_unlock(&p->handle_list_lock);

            return obj;
        }

        le = le->next;
    }

    spin_unlock(&p->handle_list_lock);

    return NULL;
}

NTSTATUS NtClose(HANDLE Handle) {
    struct list_head* le;
    process* p = muwine_current_process();
    handle* h = NULL;

    if (!p)
        return STATUS_INTERNAL_ERROR;

    // get handle from list

    spin_lock(&p->handle_list_lock);

    le = p->handle_list.next;

    while (le != &p->handle_list) {
        handle* h2 = list_entry(le, handle, list);

        if (h2->number == (uintptr_t)Handle) {
            list_del(&h2->list);
            h = h2;
            break;
        }

        le = le->next;
    }

    spin_unlock(&p->handle_list_lock);

    if (!h)
        return STATUS_INVALID_HANDLE;

    if (__sync_sub_and_fetch(&h->object->refcount, 1) == 0)
        h->object->close(h->object);

    kfree(h);

    return STATUS_SUCCESS;
}
