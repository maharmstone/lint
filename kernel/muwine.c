#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "ioctls.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Harmstone");
MODULE_DESCRIPTION("Multi-user Wine");
MODULE_VERSION("0.01");

static int major_num;

static int muwine_open(struct inode* inode, struct file* file);
static int muwine_release(struct inode* inode, struct file* file);
static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

static struct file_operations file_ops = {
    .open = muwine_open,
    .release = muwine_release,
    .unlocked_ioctl = muwine_ioctl
};

// FIXME - compat_ioctl for 32-bit ioctls on 64-bit system

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
    printk(KERN_INFO "muwine_ioctl(%p, %x, %lx)\n", file, cmd, arg);

    if (cmd > MUWINE_IOCTL_MAX)
        return -EINVAL;

    // FIXME

    return 0;
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

    printk(KERN_INFO "Multi-user Wine unloaded.\n");
}

module_init(muwine_init);
module_exit(muwine_exit);
