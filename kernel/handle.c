#include "muwine.h"
#include "thread.h"

static uintptr_t next_kernel_handle_no = KERNEL_HANDLE_MASK;

typedef struct {
    thread_object* thread;
    struct list_head list;
} waiter;

static LIST_HEAD(kernel_handle_list);
static DEFINE_SPINLOCK(kernel_handle_list_lock);

NTSTATUS muwine_add_handle(object_header* obj, PHANDLE h, bool kernel, ACCESS_MASK access) {
    handle* hand;
    spinlock_t* lock;
    uintptr_t* next_handle;
    struct list_head* list;
    process_object* p = NULL;

    if (kernel) {
        lock = &kernel_handle_list_lock;
        next_handle = &next_kernel_handle_no;
        list = &kernel_handle_list;
    } else {
        process_object* p = muwine_current_process_object();

        if (!p)
            return STATUS_INTERNAL_ERROR;

        lock = &p->handle_list_lock;
        next_handle = &p->next_handle_no;
        list = &p->handle_list;
    }

    // add entry to handle list for pid

    hand = kmalloc(sizeof(handle), GFP_KERNEL);
    if (!hand) {
        if (p)
            dec_obj_refcount(&p->header.h);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    hand->object = obj;
    hand->access = access;

    spin_lock(lock);

    hand->number = *next_handle;
    *next_handle += 4;

    list_add_tail(&hand->list, list);

    spin_unlock(lock);

    *h = (HANDLE)hand->number;

    __sync_add_and_fetch(&obj->handle_count, 1);

    if (p)
        dec_obj_refcount(&p->header.h);

    return STATUS_SUCCESS;
}

object_header* get_object_from_handle(HANDLE h, ACCESS_MASK* access) {
    struct list_head* le;
    spinlock_t* lock;
    struct list_head* list;
    process_object* p = NULL;

    if ((uintptr_t)h & KERNEL_HANDLE_MASK) {
        lock = &kernel_handle_list_lock;
        list = &kernel_handle_list;
    } else {
        p = muwine_current_process_object();

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

            inc_obj_refcount(obj);
            *access = h2->access;

            spin_unlock(lock);

            if (p)
                dec_obj_refcount(&p->header.h);

            return obj;
        }

        le = le->next;
    }

    spin_unlock(lock);

    if (p)
        dec_obj_refcount(&p->header.h);

    return NULL;
}

NTSTATUS NtClose(HANDLE Handle) {
    struct list_head* le;
    handle* h = NULL;
    spinlock_t* lock;
    struct list_head* list;
    process_object* p = NULL;

    if ((uintptr_t)h & KERNEL_HANDLE_MASK) {
        lock = &kernel_handle_list_lock;
        list = &kernel_handle_list;
    } else {
        p = muwine_current_process_object();

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

    if (!h) {
        if (p)
            dec_obj_refcount(&p->header.h);

        return STATUS_INVALID_HANDLE;
    }

    if (__sync_sub_and_fetch(&h->object->handle_count, 1) == 0)
        object_cleanup(h->object);

    dec_obj_refcount(h->object);

    kfree(h);

    if (p)
        dec_obj_refcount(&p->header.h);

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

        if (__sync_sub_and_fetch(&hand->object->handle_count, 1) == 0)
            object_cleanup(hand->object);

        dec_obj_refcount(hand->object);

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
    NTSTATUS Status;
    ACCESS_MASK access;
    sync_object* obj;
    waiter* w;
    signed long timeout;
    thread_object* thread;
    unsigned long flags;

    if (TimeOut && TimeOut->QuadPart > 0) {
        // FIXME - this would imply timeout at an absolute rather than relative time
        // Does Windows allow this?
        return STATUS_INVALID_PARAMETER;
    }

    obj = (sync_object*)get_object_from_handle(ObjectHandle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    if (!(access & SYNCHRONIZE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (obj->signalled) {
        Status = STATUS_WAIT_0;
        goto end;
    }

    if (TimeOut && TimeOut->QuadPart == 0) {
        Status = STATUS_TIMEOUT;
        goto end;
    }

    thread = muwine_current_thread_object();
    if (!thread) {
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    w = kmalloc(sizeof(waiter), GFP_KERNEL);
    if (!w) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end2;
    }

    spin_lock_irqsave(&obj->sync_lock, flags);

    // check again if signalled
    if (obj->signalled) {
        spin_unlock_irqrestore(&obj->sync_lock, flags);
        kfree(w);
        Status = STATUS_WAIT_0;
        goto end2;
    }

    w->thread = thread;
    inc_obj_refcount(&w->thread->header.h);

    list_add_tail(&w->list, &obj->waiters);

    thread->wait_count = 1;

    spin_unlock_irqrestore(&obj->sync_lock, flags);

    if (TimeOut)
        timeout = msecs_to_jiffies(-TimeOut->QuadPart / 10000);
    else
        timeout = MAX_SCHEDULE_TIMEOUT;

    // FIXME - make sure waiter freed if thread killed while waiting

    while (true) {
        spin_lock_irqsave(&obj->sync_lock, flags);

        if (thread->wait_count == 0) {
            spin_unlock_irqrestore(&obj->sync_lock, flags);

            kfree(w);

            Status = STATUS_WAIT_0;
            goto end2;
        }

        if (signal_pending(current)) {
            list_del(&w->list);
            kfree(w);

            spin_unlock_irqrestore(&obj->sync_lock, flags);

            Status = -EINTR;

            if (TimeOut)
                TimeOut->QuadPart = -jiffies_to_msecs(timeout) * 10000;

            goto end2;
        }

        spin_unlock_irqrestore(&obj->sync_lock, flags);

        timeout = schedule_timeout_interruptible(timeout);
        if (timeout == 0) {
            Status = STATUS_TIMEOUT;
            goto end2;
        }
    }

    // FIXME - APCs

end2:
    dec_obj_refcount(&thread->header.h);

end:
    dec_obj_refcount(&obj->h);
    return Status;
}

NTSTATUS user_NtWaitForSingleObject(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    NTSTATUS Status;
    LARGE_INTEGER to;

    if ((uintptr_t)ObjectHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (TimeOut && get_user(to.QuadPart, &TimeOut->QuadPart) < 0)
        return STATUS_ACCESS_VIOLATION;

    Status = NtWaitForSingleObject(ObjectHandle, Alertable, TimeOut ? &to : NULL);

    if (Status == -EINTR && TimeOut) {
        if (put_user(to.QuadPart, &TimeOut->QuadPart) < 0)
            Status = STATUS_ACCESS_VIOLATION;
    }

    return Status;
}

void signal_object(sync_object* obj, bool single_thread) {
    unsigned long flags;

    obj->signalled = true;

    spin_lock_irqsave(&obj->sync_lock, flags);

    // wake up waiting threads

    if (single_thread) {
        if (!list_empty(&obj->waiters)) {
            waiter* w = list_entry(obj->waiters.next, waiter, list);

            list_del(&w->list);

            __sync_sub_and_fetch(&w->thread->wait_count, 1);
            wake_up_process(w->thread->ts);

            obj->signalled = false;
        }
    } else {
        while (!list_empty(&obj->waiters)) {
            waiter* w = list_entry(obj->waiters.next, waiter, list);

            list_del(&w->list);

            __sync_sub_and_fetch(&w->thread->wait_count, 1);
            wake_up_process(w->thread->ts);
        }
    }

    spin_unlock_irqrestore(&obj->sync_lock, flags);
}
