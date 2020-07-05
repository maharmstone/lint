#include <linux/vmalloc.h>
#include "muwine.h"

static char* system_hive = NULL;
static size_t system_hive_size;

NTSTATUS muwine_init_registry(const char* user_system_hive_path) {
    char system_hive_path[255];
    struct file* f;
    loff_t pos;

    // FIXME - make sure uid is root
    // FIXME - make sure not already called

    printk(KERN_INFO "muwine_init_registry(%p)\n", user_system_hive_path);

    if (!user_system_hive_path)
        return STATUS_INVALID_PARAMETER;

    if (!read_user_string(user_system_hive_path, system_hive_path, sizeof(system_hive_path)))
        return STATUS_INVALID_PARAMETER;

    if (system_hive_path[0] == 0)
        return STATUS_INVALID_PARAMETER;

    printk(KERN_INFO "opening file %s\n", system_hive_path);

    f = filp_open(system_hive_path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_INFO "muwine_init_registry: could not open %s\n", system_hive_path);
        return muwine_error_to_ntstatus((int)(uintptr_t)f);
    }

    if (!f->f_inode) {
        printk(KERN_INFO "muwine_init_registry: file did not have an inode\n");
        filp_close(f, NULL);
        return STATUS_INTERNAL_ERROR;
    }

    system_hive_size = f->f_inode->i_size;

    if (system_hive_size == 0) {
        filp_close(f, NULL);
        return STATUS_REGISTRY_CORRUPT;
    }

    system_hive = vmalloc(system_hive_size);
    if (!system_hive) {
        filp_close(f, NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pos = 0;

    while (pos < system_hive_size) {
        ssize_t read = kernel_read(f, (uint8_t*)system_hive + pos, system_hive_size - pos, &pos);

        if (read < 0) {
            printk(KERN_INFO "muwine_init_registry: read returned %ld\n", read);
            filp_close(f, NULL);
            return muwine_error_to_ntstatus(read);
        }
    }

    printk(KERN_INFO "muwine_init_registry: Loaded %lu bytes of system hive into memory.\n", system_hive_size);

    // FIXME - check valid

    filp_close(f, NULL);

    return STATUS_INVALID_PARAMETER;
}

void muwine_free_reg(void) {
    if (system_hive)
        vfree(system_hive);
}
