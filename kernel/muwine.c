#include "ioctls.h"
#include "muwine.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Harmstone");
MODULE_DESCRIPTION("Multi-user Wine");
MODULE_VERSION("0.01");

static int major_num;

static int muwine_open(struct inode* inode, struct file* file);
static int muwine_release(struct inode* inode, struct file* file);
static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

static struct muwine_func funcs[] = {
    { user_NtOpenKey, 3 },
    { NtClose, 1 },
    { user_NtEnumerateKey, 6 },
    { user_NtEnumerateValueKey, 6 },
    { user_NtQueryValueKey, 6 },
    { user_NtSetValueKey, 6 },
    { user_NtDeleteValueKey, 2 },
    { user_NtCreateKey, 7 },
    { NtDeleteKey, 1 },
    { user_NtLoadKey, 2 },
    { user_NtUnloadKey, 1 },
    { NtFlushKey, 1 },
    { user_NtOpenKeyEx, 4 },
    { user_NtQueryKey, 5 },
    { NtSaveKey, 2 },
    { NtNotifyChangeKey, 10 },
    { NtNotifyChangeMultipleKeys, 12 }
};

// FIXME - compat_ioctl for 32-bit ioctls on 64-bit system

typedef struct {
    struct list_head list;
    object_header* object;
    uintptr_t number;
} handle;

LIST_HEAD(pid_list);
DEFINE_SPINLOCK(pid_list_lock);

static struct file_operations file_ops = {
    .open = muwine_open,
    .release = muwine_release,
    .unlocked_ioctl = muwine_ioctl
};

bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen) {
    while (maxlen > 0) {
        char c;

        if (get_user(c, str_us) < 0)
            return false;

        *str_ks = c;
        str_ks++;
        str_us++;
        maxlen--;

        if (c == 0)
            return true;
    }

    return false;
}

bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us) {
    WCHAR* srcbuf;

    if (get_user(ks->Length, &us->Length) < 0)
        return false;

    if (get_user(ks->MaximumLength, &us->MaximumLength) < 0)
        return false;

    if (ks->Length == 0) {
        ks->Buffer = NULL;
        return true;
    }

    if (get_user(srcbuf, &us->Buffer) < 0)
        return false;

    ks->Buffer = kmalloc(ks->Length, GFP_KERNEL);
    if (!ks->Buffer)
        return false;

    if (copy_from_user(ks->Buffer, srcbuf, ks->Length) != 0) {
        kfree(ks->Buffer);
        return false;
    }

    return true;
}

bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us) {
    UNICODE_STRING* usus;

    if (get_user(ks->Length, &us->Length) < 0)
        return false;

    if (get_user(ks->RootDirectory, &us->RootDirectory) < 0)
        return false;

    if (get_user(ks->Attributes, &us->Attributes) < 0)
        return false;

    if (get_user(ks->SecurityDescriptor, &us->SecurityDescriptor) < 0) // FIXME - copy buffer to user space
        return false;

    if (get_user(ks->SecurityQualityOfService, &us->SecurityQualityOfService) < 0) // FIXME - copy buffer to user space
        return false;

    if (get_user(usus, &us->ObjectName) < 0)
        return false;

    if (usus) {
        ks->ObjectName = kmalloc(sizeof(UNICODE_STRING), GFP_KERNEL);
        if (!ks->ObjectName)
            return false;

        if (!get_user_unicode_string(ks->ObjectName, usus)) {
            kfree(ks->ObjectName);
            return false;
        }
    } else
        ks->ObjectName = NULL;

    return true;
}

process* muwine_current_process(void) {
    struct list_head* le;
    pid_t pid = task_tgid_vnr(current);

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == pid) {
            spin_unlock(&pid_list_lock);

            return p2;
        }

        le = le->next;
    }

    spin_unlock(&pid_list_lock);

    return NULL;
}

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

    h->object->close(h->object);

    kfree(h);

    return STATUS_SUCCESS;
}

int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        WCHAR c1 = *string1;
        WCHAR c2 = *string2;

        if (c1 >= 'A' && c1 <= 'Z')
            c1 -= 'A' + 'a';

        if (c2 >= 'A' && c2 <= 'Z')
            c2 -= 'A' + 'a';

        if (c1 < c2)
            return -1;
        else if (c1 > c2)
            return 1;

        string1++;
        string2++;
    }

    return 0;
}

NTSTATUS muwine_error_to_ntstatus(int err) {
    switch (err) {
        case -ENOENT:
            return STATUS_OBJECT_NAME_NOT_FOUND;

        default:
            printk(KERN_INFO "muwine: Unable to translate error %d to NTSTATUS.\n", err);
            return STATUS_INTERNAL_ERROR;
    }
}

static int muwine_open(struct inode* inode, struct file* file) {
    process* p;
    struct list_head* le;
    bool found = false;

    // add pid to process list

    p = kmalloc(sizeof(process), GFP_KERNEL);

    p->pid = task_tgid_vnr(current);
    p->refcount = 1;
    INIT_LIST_HEAD(&p->handle_list);
    spin_lock_init(&p->handle_list_lock);
    p->next_handle_no = MUW_FIRST_HANDLE + 4;
    muwine_make_process_token(&p->token);

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == p->pid) {
            p2->refcount++;
            found = true;
            break;
        }

        le = le->next;
    }

    if (!found)
        list_add_tail(&p->list, &pid_list);
    else
        kfree(p);

    spin_unlock(&pid_list_lock);

    try_module_get(THIS_MODULE);

    return 0;
}

static int muwine_release(struct inode* inode, struct file* file) {
    pid_t pid = task_tgid_vnr(current);
    struct list_head* le;
    process* p = NULL;

    // remove pid from process list

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == pid) {
            p2->refcount--;

            if (p2->refcount == 0) {
                list_del(&p2->list);
                p = p2;
            }

            break;
        }

        le = le->next;
    }

    spin_unlock(&pid_list_lock);

    if (p) {
        // force close of all open handles

        spin_lock(&p->handle_list_lock);

        while (!list_empty(&p->handle_list)) {
            handle* hand = list_entry(p->handle_list.next, handle, list);

            list_del(&hand->list);

            hand->object->close(hand->object);

            kfree(hand);
        }

        spin_unlock(&p->handle_list_lock);

        muwine_free_token(p->token);

        kfree(p);
    }

    module_put(THIS_MODULE);

    return 0;
}

static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg) {
    uintptr_t* temp;
    uintptr_t num_args;

    cmd = _IOC_NR(cmd);

    if (cmd > MUWINE_IOCTL_MAX)
        return STATUS_NOT_IMPLEMENTED;

    temp = (uintptr_t*)arg;

    if (!temp)
        return STATUS_INVALID_PARAMETER;

    if (get_user(num_args, temp) < 0)
        return STATUS_INVALID_PARAMETER;

    temp++;

    if (num_args != funcs[cmd].num_args) {
        printk(KERN_INFO "muwine_ioctl: ioctl %u passed %u args, expected %u\n", cmd, (unsigned int)num_args, funcs[cmd].num_args);
        return STATUS_INVALID_PARAMETER;
    }

    if (num_args == 1) {
        uintptr_t arg1;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func1arg)funcs[cmd].func)(arg1);
    } else if (num_args == 2) {
        uintptr_t arg1, arg2;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func2arg)funcs[cmd].func)(arg1, arg2);
    } else if (num_args == 3) {
        uintptr_t arg1, arg2, arg3;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func3arg)funcs[cmd].func)(arg1, arg2, arg3);
    } else if (num_args == 4) {
        uintptr_t arg1, arg2, arg3, arg4;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func4arg)funcs[cmd].func)(arg1, arg2, arg3, arg4);
    } else if (num_args == 5) {
        uintptr_t arg1, arg2, arg3, arg4, arg5;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func5arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5);
    } else if (num_args == 6) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func6arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6);
    } else if (num_args == 7) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func7arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
    } else if (num_args == 8) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func8arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    } else if (num_args == 9) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func9arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  arg9);
    } else if (num_args == 10) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func10arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10);
    } else if (num_args == 11) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg11, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func11arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10, arg11);
    } else if (num_args == 12) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg11, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg12, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func12arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10, arg11, arg12);
    } else {
        printk(KERN_ALERT "muwine_ioctl: unexpected number of arguments %u\n", (unsigned int)num_args);
        return STATUS_INVALID_PARAMETER;
    }
}

static int __init muwine_init(void) {
    NTSTATUS Status;

    major_num = register_chrdev(0, "muwine", &file_ops);

    if (major_num < 0) {
        printk(KERN_ALERT "Could not register device: %d\n", major_num);
        return major_num;
    }

    Status = muwine_init_registry();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_registry returned %08x\n", Status);
        return -ENOMEM;
    }

    printk(KERN_INFO "muwine module loaded with device major number %d\n", major_num);

    return 0;
}

static void __exit muwine_exit(void) {
    unregister_chrdev(major_num, "muwine");

    muwine_free_reg();

    printk(KERN_INFO "muwine unloaded\n");
}

module_init(muwine_init);
module_exit(muwine_exit);
