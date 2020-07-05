#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Harmstone");
MODULE_DESCRIPTION("Multi-user Wine");
MODULE_VERSION("0.01");

static int major_num;

static int device_open(struct inode* inode, struct file* file);
static int device_release(struct inode* inode, struct file* file);

static struct file_operations file_ops = {
    .open = device_open,
    .release = device_release
};

static int device_open(struct inode* inode, struct file* file) {
    // FIXME - add pid to process list

    try_module_get(THIS_MODULE);

    return 0;
}

static int device_release(struct inode* inode, struct file* file) {
    // FIXME - remove pid from process list

    module_put(THIS_MODULE);

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
