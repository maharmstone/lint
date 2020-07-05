#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Harmstone");
MODULE_DESCRIPTION("Multi-user Wine");
MODULE_VERSION("0.01");

static int __init muwine_init(void) {
    printk(KERN_INFO "Hello, World!\n");
    return 0;
}

static void __exit muwine_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(muwine_init);
module_exit(muwine_exit);
