#include "muwine.h"
#include <linux/vmalloc.h>

#define HV_HBLOCK_SIGNATURE 0x66676572  // "regf"

#define CM_KEY_HASH_LEAF        0x686c  // "lh"
#define CM_KEY_INDEX_ROOT       0x6972  // "ri"
#define CM_KEY_NODE_SIGNATURE   0x6b6e  // "nk"
#define CM_KEY_VALUE_SIGNATURE  0x6b76  // "vk"

#define HSYS_MAJOR 1
#define HSYS_MINOR 3
#define HFILE_TYPE_PRIMARY 0
#define HBASE_FORMAT_MEMORY 1

#define HIVE_FILENAME_MAXLEN 31

#pragma pack(push,1)

typedef struct {
    uint32_t Signature;
    uint32_t Sequence1;
    uint32_t Sequence2;
    uint64_t TimeStamp;
    uint32_t Major;
    uint32_t Minor;
    uint32_t Type;
    uint32_t Format;
    uint32_t RootCell;
    uint32_t Length;
    uint32_t Cluster;
    WCHAR FileName[HIVE_FILENAME_MAXLEN + 1];
    uint32_t Reserved1[99];
    uint32_t CheckSum;
    uint32_t Reserved2[0x37E];
    uint32_t BootType;
    uint32_t BootRecover;
} HBASE_BLOCK;

typedef struct {
    uint16_t Signature;
    uint16_t Flags;
    uint64_t LastWriteTime;
    uint32_t Spare;
    uint32_t Parent;
    uint32_t SubKeyCount;
    uint32_t VolatileSubKeyCount;
    uint32_t SubKeyList;
    uint32_t VolatileSubKeyList;
    uint32_t ValuesCount;
    uint32_t Values;
    uint32_t Security;
    uint32_t Class;
    uint32_t MaxNameLen;
    uint32_t MaxClassLen;
    uint32_t MaxValueNameLen;
    uint32_t MaxValueDataLen;
    uint32_t WorkVar;
    uint16_t NameLength;
    uint16_t ClassLength;
    WCHAR Name[1];
} CM_KEY_NODE;

typedef struct {
    uint32_t Cell;
    uint32_t HashKey;
} CM_INDEX;

typedef struct {
    uint16_t Signature;
    uint16_t Count;
    CM_INDEX List[1];
} CM_KEY_FAST_INDEX;

typedef struct {
    uint16_t Signature;
    uint16_t NameLength;
    uint32_t DataLength;
    uint32_t Data;
    uint32_t Type;
    uint16_t Flags;
    uint16_t Spare;
    WCHAR Name[1];
} CM_KEY_VALUE;

typedef struct {
    uint16_t Signature;
    uint16_t Count;
    uint32_t List[1];
} CM_KEY_INDEX;

static void* system_hive = NULL;
static size_t system_hive_size;

static bool hive_is_valid(void* hive, size_t hive_size) {
    HBASE_BLOCK* base_block = (HBASE_BLOCK*)hive;
    unsigned int i;
    uint32_t csum;

    if (hive_size < sizeof(HBASE_BLOCK)) {
        printk(KERN_ALERT "muwine: hive was too short\n");
        return false;
    }

    if (base_block->Signature != HV_HBLOCK_SIGNATURE) {
        printk(KERN_ALERT "muwine: hive had invalid signature\n");
        return false;
    }

    if (base_block->Major != HSYS_MAJOR) {
        printk(KERN_ALERT "muwine: hive had invalid major value %x.\n", base_block->Major);
        return false;
    }

    if (base_block->Minor < HSYS_MINOR) {
        printk(KERN_ALERT "muwine: hive had invalid minor value %x.\n", base_block->Minor);
        return false;
    }

    if (base_block->Type != HFILE_TYPE_PRIMARY) {
        printk(KERN_ALERT "muwine: hive type was not HFILE_TYPE_PRIMARY.\n");
        return false;
    }

    if (base_block->Format != HBASE_FORMAT_MEMORY) {
        printk(KERN_ALERT "muwine: hive format was not HBASE_FORMAT_MEMORY.\n");
        return false;
    }

    if (base_block->Cluster != 1) {
        printk(KERN_ALERT "muwine: hive cluster was not 1.\n");
        return false;
    }

    if (base_block->Sequence1 != base_block->Sequence2) {
        printk(KERN_ALERT "muwine: hive Sequence1 did not match Sequence2.\n");
        return false;
    }

    // check checksum

    csum = 0;

    for (i = 0; i < 127; i++) {
        csum ^= ((uint32_t*)hive)[i];
    }

    if (csum == 0xffffffff)
        csum = 0xfffffffe;
    else if (csum == 0)
        csum = 1;

    if (csum != base_block->CheckSum) {
        printk(KERN_ALERT "muwine: hive checksum was %08x, expected %08x.\n", csum, base_block->CheckSum);
        return false;
    }

    return true;
}

static void clear_volatile(void* hive, uint32_t key) {
    int32_t size;
    CM_KEY_NODE* nk;
    uint16_t sig;
    unsigned int i;

    // FIXME - make sure we don't exceed the bounds of the allocation

    size = -*(int32_t*)((uint8_t*)hive + key);

    if (size < 0)
        return;

    if ((uint32_t)size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return;

    nk = (CM_KEY_NODE*)((uint8_t*)hive + key + sizeof(int32_t));

    if (nk->Signature != CM_KEY_NODE_SIGNATURE)
        return;

    nk->VolatileSubKeyList = 0xbaadf00d;
    nk->VolatileSubKeyCount = 0;

    if (nk->SubKeyCount == 0 || nk->SubKeyList == 0xffffffff)
        return;

    size = -*(int32_t*)((uint8_t*)hive + 0x1000 + nk->SubKeyList);

    sig = *(uint16_t*)((uint8_t*)hive + 0x1000 + nk->SubKeyList + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)hive + 0x1000 + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < lh->Count; i++) {
            clear_volatile(hive, 0x1000 + lh->List[i].Cell);
        }
    } else if (sig == CM_KEY_INDEX_ROOT) {
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)hive + 0x1000 + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < ri->Count; i++) {
            clear_volatile(hive, 0x1000 + ri->List[i]);
        }
    } else
        printk(KERN_INFO "muwine: unhandled registry signature %x\n", sig);
}

NTSTATUS muwine_init_registry(const char* user_system_hive_path) {
    char system_hive_path[255];
    struct file* f;
    loff_t pos;

    // FIXME - make sure uid is root

    if (system_hive) // make sure not already loaded
        return STATUS_INVALID_PARAMETER;

    if (!user_system_hive_path)
        return STATUS_INVALID_PARAMETER;

    if (!read_user_string(user_system_hive_path, system_hive_path, sizeof(system_hive_path)))
        return STATUS_INVALID_PARAMETER;

    printk(KERN_INFO "muwine_init_registry(%s)\n", system_hive_path);

    if (system_hive_path[0] == 0)
        return STATUS_INVALID_PARAMETER;

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
            vfree(system_hive);
            system_hive = NULL;
            return muwine_error_to_ntstatus(read);
        }
    }

    filp_close(f, NULL);

    if (!hive_is_valid(system_hive, system_hive_size)) {
        vfree(system_hive);
        system_hive = NULL;
        return STATUS_REGISTRY_CORRUPT;
    }

    printk(KERN_INFO "muwine_init_registry: loaded system hive at %s.\n", system_hive_path);

    clear_volatile(system_hive, 0x1000 + ((HBASE_BLOCK*)system_hive)->RootCell);

    return STATUS_SUCCESS;
}

void muwine_free_reg(void) {
    if (system_hive)
        vfree(system_hive);
}

NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    printk(KERN_INFO "NtOpenKey(%p, %x, %p): stub\n", KeyHandle, DesiredAccess, ObjectAttributes);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtClose(HANDLE Handle) {
    printk(KERN_INFO "NtClose(%p): stub\n", Handle);

    return STATUS_NOT_IMPLEMENTED;
}
