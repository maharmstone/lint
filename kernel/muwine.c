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
    { muwine_init_registry, 1 },
    { user_NtOpenKey, 3},
    { NtClose, 1}
};

// FIXME - compat_ioctl for 32-bit ioctls on 64-bit system

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
    // FIXME - add pid to process list

    try_module_get(THIS_MODULE);

    return 0;
}

static int muwine_release(struct inode* inode, struct file* file) {
    // FIXME - remove pid from process list

    module_put(THIS_MODULE);

    return 0;
}

static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg) {
    uintptr_t* temp;
    uintptr_t num_args;

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
    } else {
        printk(KERN_ALERT "muwine_ioctl: unexpected number of arguments %u\n", (unsigned int)num_args);
        return STATUS_INVALID_PARAMETER;
    }
}


static int __init muwine_init(void) {
    major_num = register_chrdev(0, "muwine", &file_ops);

    if (major_num < 0) {
        printk(KERN_ALERT "Could not register device: %d\n", major_num);
        return major_num;
    } else {
        printk(KERN_INFO "muwine module loaded with device major number %d\n", major_num);
        return 0;
    }
}

static void __exit muwine_exit(void) {
    unregister_chrdev(major_num, "muwine");

    muwine_free_reg();

    printk(KERN_INFO "muwine unloaded\n");
}

module_init(muwine_init);
module_exit(muwine_exit);
