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

typedef struct {
    void* data;
    size_t size;
} hive;

typedef struct {
    object_header header;
    hive* h;
    size_t offset;
} key_object;

static void key_object_close(object_header* obj);

static hive system_hive;

static bool hive_is_valid(hive* h) {
    HBASE_BLOCK* base_block = (HBASE_BLOCK*)h->data;
    unsigned int i;
    uint32_t csum;

    if (h->size < sizeof(HBASE_BLOCK)) {
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
        csum ^= ((uint32_t*)h->data)[i];
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

static void clear_volatile(hive* h, uint32_t key) {
    int32_t size;
    CM_KEY_NODE* nk;
    uint16_t sig;
    unsigned int i;

    // FIXME - make sure we don't exceed the bounds of the allocation

    size = -*(int32_t*)((uint8_t*)h->data + key);

    if (size < 0)
        return;

    if ((uint32_t)size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return;

    nk = (CM_KEY_NODE*)((uint8_t*)h->data + key + sizeof(int32_t));

    if (nk->Signature != CM_KEY_NODE_SIGNATURE)
        return;

    nk->VolatileSubKeyList = 0xbaadf00d;
    nk->VolatileSubKeyCount = 0;

    if (nk->SubKeyCount == 0 || nk->SubKeyList == 0xffffffff)
        return;

    size = -*(int32_t*)((uint8_t*)h->data + 0x1000 + nk->SubKeyList);

    sig = *(uint16_t*)((uint8_t*)h->data + 0x1000 + nk->SubKeyList + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->data + 0x1000 + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < lh->Count; i++) {
            clear_volatile(h, 0x1000 + lh->List[i].Cell);
        }
    } else if (sig == CM_KEY_INDEX_ROOT) {
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)h->data + 0x1000 + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < ri->Count; i++) {
            clear_volatile(h, 0x1000 + ri->List[i]);
        }
    } else
        printk(KERN_INFO "muwine: unhandled registry signature %x\n", sig);
}

NTSTATUS muwine_init_registry(const char* user_system_hive_path) {
    char system_hive_path[255];
    struct file* f;
    loff_t pos;

    // FIXME - make sure uid is root

    if (system_hive.data) // make sure not already loaded
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

    system_hive.size = f->f_inode->i_size;

    if (system_hive.size == 0) {
        filp_close(f, NULL);
        return STATUS_REGISTRY_CORRUPT;
    }

    system_hive.data = vmalloc(system_hive.size);
    if (!system_hive.data) {
        filp_close(f, NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pos = 0;

    while (pos < system_hive.size) {
        ssize_t read = kernel_read(f, (uint8_t*)system_hive.data + pos, system_hive.size - pos, &pos);

        if (read < 0) {
            printk(KERN_INFO "muwine_init_registry: read returned %ld\n", read);
            filp_close(f, NULL);
            vfree(system_hive.data);
            system_hive.data = NULL;
            return muwine_error_to_ntstatus(read);
        }
    }

    filp_close(f, NULL);

    if (!hive_is_valid(&system_hive)) {
        vfree(system_hive.data);
        system_hive.data = NULL;
        return STATUS_REGISTRY_CORRUPT;
    }

    printk(KERN_INFO "muwine_init_registry: loaded system hive at %s.\n", system_hive_path);

    clear_volatile(&system_hive, 0x1000 + ((HBASE_BLOCK*)system_hive.data)->RootCell);

    return STATUS_SUCCESS;
}

void muwine_free_reg(void) {
    if (system_hive.data)
        vfree(system_hive.data);
}

static NTSTATUS open_key_in_hive(hive* h, UNICODE_STRING* us, PHANDLE KeyHandle, ACCESS_MASK DesiredAccess) {
    NTSTATUS Status;
    size_t offset;
    key_object* k;

    // FIXME - get hive mutex

    // FIXME - loop through parts and locate

//     while (us->Length >= sizeof(WCHAR) && *us->Buffer == '\\') {
//         us->Length += sizeof(WCHAR);
//         us->Buffer++;
//     }

    // FIXME - create key object and return handle

    offset = 0x1000 + ((HBASE_BLOCK*)h->data)->RootCell; // FIXME

    k = kmalloc(sizeof(key_object), GFP_KERNEL);
    if (!k)
        return STATUS_INSUFFICIENT_RESOURCES;

    k->header.refcount = 1;
    k->header.close = key_object_close;
    k->h = h; // FIXME - increase hive refcount
    k->offset = offset;

    Status = muwine_add_handle(&k->header, KeyHandle);

    if (!NT_SUCCESS(Status))
        kfree(k);

    return Status;
}

static NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    UNICODE_STRING us;

    static const WCHAR prefix[] = L"\\Registry\\";
    static const WCHAR machine[] = L"Machine";

    printk(KERN_INFO "NtOpenKey(%p, %x, %p): stub\n", KeyHandle, DesiredAccess, ObjectAttributes);

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES))
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        printk(KERN_ALERT "NtOpenKey: FIXME - support RootDirectory\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    if (!ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    // fail if ObjectAttributes->ObjectName doesn't begin with "\\Registry\\";

    us.Length = ObjectAttributes->ObjectName->Length;
    us.Buffer = ObjectAttributes->ObjectName->Buffer;

    if (us.Length < sizeof(prefix) - sizeof(WCHAR) ||
        wcsnicmp(us.Buffer, prefix, (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR))) {
        return STATUS_OBJECT_PATH_INVALID;
    }

    us.Buffer += (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR);
    us.Length -= sizeof(prefix) - sizeof(WCHAR);

    if (us.Length >= sizeof(machine) - sizeof(WCHAR) && !wcsnicmp(us.Buffer, machine, (sizeof(machine) - sizeof(WCHAR)) / sizeof(WCHAR))) {
        us.Buffer += (sizeof(machine) - sizeof(WCHAR)) / sizeof(WCHAR);
        us.Length -= sizeof(machine) - sizeof(WCHAR);

        if (us.Length >= sizeof(WCHAR) && us.Buffer[0] != '\\')
            return STATUS_OBJECT_PATH_INVALID;

        if (!system_hive.data) // HKLM not loaded
            return STATUS_OBJECT_PATH_INVALID;

        return open_key_in_hive(&system_hive, &us, KeyHandle, DesiredAccess);
    } else
        return STATUS_OBJECT_PATH_INVALID;

    // FIXME - also look in \\Registry\\User
}

NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;

    if (!ObjectAttributes || !KeyHandle)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_INVALID_PARAMETER;

    Status = NtOpenKey(&h, DesiredAccess, &oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (put_user(h, KeyHandle) < 0) {
        if (NT_SUCCESS(Status))
            NtClose(h);

        return STATUS_INVALID_PARAMETER;
    }

    return Status;
}

static void key_object_close(object_header* obj) {
    printk(KERN_ALERT "FIXME - key_object_close\n"); // FIXME

    // FIXME
}
