#include <linux/vmalloc.h>
#include "muwine.h"
#include "reg.h"

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

    size = -*(int32_t*)((uint8_t*)h->bins + key);

    if (size < 0)
        return;

    if ((uint32_t)size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return;

    nk = (CM_KEY_NODE*)((uint8_t*)h->bins + key + sizeof(int32_t));

    if (nk->Signature != CM_KEY_NODE_SIGNATURE)
        return;

    nk->VolatileSubKeyList = 0xbaadf00d;
    nk->VolatileSubKeyCount = 0;

    if (nk->SubKeyCount == 0 || nk->SubKeyList == 0xffffffff)
        return;

    size = -*(int32_t*)((uint8_t*)h->bins + nk->SubKeyList);

    sig = *(uint16_t*)((uint8_t*)h->bins + nk->SubKeyList + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < lh->Count; i++) {
            clear_volatile(h, lh->List[i].Cell);
        }
    } else if (sig == CM_KEY_INDEX_ROOT) {
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)h->bins + nk->SubKeyList + sizeof(int32_t));

        for (i = 0; i < ri->Count; i++) {
            clear_volatile(h, ri->List[i]);
        }
    } else
        printk(KERN_INFO "muwine: unhandled registry signature %x\n", sig);
}

static NTSTATUS find_bin_holes(hive* h, void** off) {
    HBIN* bin = *(HBIN**)off;
    int32_t* len;

    if (bin->Signature != HV_HBIN_SIGNATURE) {
        printk(KERN_ALERT "hbin signature not found\n");
        return STATUS_REGISTRY_CORRUPT;
    }

    if (bin->Size < sizeof(HBIN)) {
        printk(KERN_ALERT "hbin size was %x, expected at least %lx\n", bin->Size, sizeof(HBIN));
        return STATUS_REGISTRY_CORRUPT;
    }

    len = (int32_t*)((uint8_t*)bin + sizeof(HBIN));

    while (len < (int32_t*)((uint8_t*)bin + bin->Size)) {
        if (*len > 0) { // free
            hive_hole* hh = kmalloc(sizeof(hive_hole), GFP_KERNEL);
            if (!hh)
                return STATUS_INSUFFICIENT_RESOURCES; // FIXME - free list entries already done

            hh->offset = (uint8_t*)len - (uint8_t*)h->bins;
            hh->size = *len;

            // FIXME - append to previous if follows on from it

            list_add_tail(&hh->list, &h->holes);
            len = (int32_t*)((uint8_t*)len + *len);
        } else // filled
            len = (int32_t*)((uint8_t*)len + -*len);
    }

    *off = (uint8_t*)bin + bin->Size;

    return STATUS_SUCCESS;
}

static NTSTATUS init_hive(hive* h) {
    NTSTATUS Status;
    void* off;

    h->bins = (uint8_t*)h->data + BIN_SIZE;
    h->refcount = 0;

    clear_volatile(h, ((HBASE_BLOCK*)h->data)->RootCell);

    INIT_LIST_HEAD(&h->holes);
    rwlock_init(&h->lock);
    h->dirty = false;

    off = h->bins;
    while (off < h->bins + ((HBASE_BLOCK*)h->data)->Length) {
        Status = find_bin_holes(h, &off);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS muwine_init_registry(const char* user_system_hive_path) {
    NTSTATUS Status;
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

    Status = init_hive(&system_hive);
    if (!NT_SUCCESS(Status)) {
        vfree(system_hive.data);
        system_hive.data = NULL;
        return Status;
    }

    printk(KERN_INFO "muwine_init_registry: loaded system hive at %s.\n", system_hive_path);

    return STATUS_SUCCESS;
}

static void free_hive(hive* h) {
    // FIXME - flush if dirty

    while (!list_empty(&h->holes)) {
        hive_hole* hh = list_entry(h->holes.next, hive_hole, list);

        list_del(&hh->list);

        kfree(hh);
    }
}

void muwine_free_reg(void) {
    // FIXME - iterate through hive list

    if (system_hive.data)
        free_hive(&system_hive);
}

static uint32_t calc_subkey_hash(UNICODE_STRING* us) {
    uint32_t h = 0;
    unsigned int i;

    for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
        WCHAR c;

        if (us->Buffer[i] == 0 || us->Buffer[i] == '\\')
            break;

        if (us->Buffer[i] >= 'a' && us->Buffer[i] <= 'z')
            c = us->Buffer[i] - 'a' + 'A';
        else
            c = us->Buffer[i];

        h *= 37;
        h += c;
    }

    return h;
}

static NTSTATUS search_lh(hive* h, CM_KEY_FAST_INDEX* lh, uint32_t hash, UNICODE_STRING* us, uint32_t* offset_out) {
    unsigned int i, uslen;

    uslen = 0;
    for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
        if (us->Buffer[i] == 0 || us->Buffer[i] == '\\')
            break;

        uslen++;
    }

    for (i = 0; i < lh->Count; i++) {
        if (lh->List[i].HashKey == hash) {
            CM_KEY_NODE* kn2;
            int32_t size;
            bool found = false;

            // FIXME - check not out of bounds

            size = -*(int32_t*)((uint8_t*)h->bins + lh->List[i].Cell);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
                return STATUS_REGISTRY_CORRUPT;

            kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + lh->List[i].Cell + sizeof(int32_t));

            if (kn2->Signature != CM_KEY_NODE_SIGNATURE)
                return STATUS_REGISTRY_CORRUPT;

            if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength)
                return STATUS_REGISTRY_CORRUPT;

            if (kn2->Flags & KEY_COMP_NAME) {
                if (kn2->NameLength == uslen) {
                    unsigned int j;

                    found = true;

                    for (j = 0; j < uslen; j++) {
                        WCHAR c1 = ((char*)kn2->Name)[j];
                        WCHAR c2 = us->Buffer[j];

                        if (c1 >= 'a' && c1 <= 'z')
                            c1 = c1 - 'a' + 'A';

                        if (c2 >= 'a' && c2 <= 'z')
                            c2 = c2 - 'a' + 'A';

                        if (c1 != c2) {
                            found = false;
                            break;
                        }
                    }


                }
            } else {
                if (kn2->NameLength == uslen * sizeof(WCHAR)) {
                    unsigned int j;

                    found = true;

                    for (j = 0; j < uslen; j++) {
                        WCHAR c1 = kn2->Name[j];
                        WCHAR c2 = us->Buffer[j];

                        if (c1 >= 'a' && c1 <= 'z')
                            c1 = c1 - 'a' + 'A';

                        if (c2 >= 'a' && c2 <= 'z')
                            c2 = c2 - 'a' + 'A';

                        if (c1 != c2) {
                            found = false;
                            break;
                        }
                    }
                }
            }

            if (found) {
                *offset_out = lh->List[i].Cell;
                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_OBJECT_PATH_NOT_FOUND;
}

static NTSTATUS find_subkey(hive* h, uint32_t offset, UNICODE_STRING* us, uint32_t* offset_out) {
    uint32_t hash = calc_subkey_hash(us);
    int32_t size;
    uint16_t sig;
    CM_KEY_NODE* kn;

    size = -*(int32_t*)((uint8_t*)h->bins + offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return STATUS_REGISTRY_CORRUPT;

    kn = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE)
        return STATUS_REGISTRY_CORRUPT;

    // FIXME - work with volatile keys

    if (kn->SubKeyCount == 0)
        return STATUS_OBJECT_PATH_NOT_FOUND;

    // FIXME - check not out of bounds

    sig = *(uint16_t*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));
    size = -*(int32_t*)((uint8_t*)h->bins + kn->SubKeyList);

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
            return STATUS_REGISTRY_CORRUPT;

        return search_lh(h, lh, hash, us, offset_out);
    } else if (sig == CM_KEY_INDEX_ROOT) {
        unsigned int i;
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_INDEX, List[0]) + (ri->Count * sizeof(uint32_t)))
            return STATUS_REGISTRY_CORRUPT;

        for (i = 0; i < ri->Count; i++) {
            NTSTATUS Status;
            CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + ri->List[i] + sizeof(int32_t));

            size = -*(int32_t*)((uint8_t*)h->bins + ri->List[i]);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
                return STATUS_REGISTRY_CORRUPT;

            Status = search_lh(h, lh, hash, us, offset_out);
            if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
                return Status;
        }

        return STATUS_OBJECT_PATH_NOT_FOUND;
    } else
        return STATUS_REGISTRY_CORRUPT;
}

static NTSTATUS open_key_in_hive(hive* h, UNICODE_STRING* us, uint32_t* ret_offset, bool parent) {
    NTSTATUS Status;
    uint32_t offset;

    // loop through parts and locate

    offset = ((HBASE_BLOCK*)h->data)->RootCell;

    do {
        while (us->Length >= sizeof(WCHAR) && *us->Buffer == '\\') {
            us->Length -= sizeof(WCHAR);
            us->Buffer++;
        }

        if (us->Length == 0)
            break;

        if (parent) {
            bool last_one = true;
            unsigned int i;

            for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
                if (us->Buffer[i] == '\\') {
                    last_one = false;
                    break;
                }
            }

            if (last_one)
                break;
        }

        // FIXME - should this be checking for KEY_ENUMERATE_SUB_KEYS against all keys in path?

        Status = find_subkey(h, offset, us, &offset);
        if (!NT_SUCCESS(Status))
            return Status;

        while (us->Length >= sizeof(WCHAR) && *us->Buffer != '\\') {
            us->Length -= sizeof(WCHAR);
            us->Buffer++;
        }
    } while (true);

    *ret_offset = offset;

    return STATUS_SUCCESS;
}

static NTSTATUS NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    NTSTATUS Status;
    UNICODE_STRING us;
    uint32_t offset;

    static const WCHAR prefix[] = L"\\Registry\\";
    static const WCHAR machine[] = L"Machine";

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
        key_object* k;

        us.Buffer += (sizeof(machine) - sizeof(WCHAR)) / sizeof(WCHAR);
        us.Length -= sizeof(machine) - sizeof(WCHAR);

        if (us.Length >= sizeof(WCHAR) && us.Buffer[0] != '\\')
            return STATUS_OBJECT_PATH_INVALID;

        if (!system_hive.data) // HKLM not loaded
            return STATUS_OBJECT_PATH_INVALID;

        read_lock(&system_hive.lock);

        Status = open_key_in_hive(&system_hive, &us, &offset, false);
        if (!NT_SUCCESS(Status)) {
            read_unlock(&system_hive.lock);
            return Status;
        }

        read_unlock(&system_hive.lock);

        // FIXME - do SeAccessCheck
        // FIXME - store access mask in handle

        // create key object and return handle

        k = kmalloc(sizeof(key_object), GFP_KERNEL);
        if (!k)
            return STATUS_INSUFFICIENT_RESOURCES;

        k->header.refcount = 1;
        k->header.type = muwine_object_key;
        k->header.close = key_object_close;
        k->h = &system_hive;
        __sync_add_and_fetch(&system_hive.refcount, 1);
        k->offset = offset;

        Status = muwine_add_handle(&k->header, KeyHandle);

        if (!NT_SUCCESS(Status))
            kfree(k);

        return Status;
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
    key_object* key = (key_object*)obj;

    __sync_sub_and_fetch(&key->h->refcount, 1);

    kfree(key);
}

static NTSTATUS get_key_item_by_index(hive* h, size_t offset, unsigned int index, size_t* cell_offset) {
    int32_t size;
    uint16_t sig;

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)h->bins + offset);
    sig = *(uint16_t*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
            return STATUS_REGISTRY_CORRUPT;

        if (index >= lh->Count)
            return STATUS_REGISTRY_CORRUPT;

        *cell_offset = lh->List[index].Cell;

        return STATUS_SUCCESS;
    } else if (sig == CM_KEY_INDEX_ROOT) {
        unsigned int i;
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)h->bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_INDEX, List[0]) + (ri->Count * sizeof(uint32_t)))
            return STATUS_REGISTRY_CORRUPT;

        for (i = 0; i < ri->Count; i++) {
            CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + ri->List[i] + sizeof(int32_t));

            size = -*(int32_t*)((uint8_t*)h->bins + ri->List[i]);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
                return STATUS_REGISTRY_CORRUPT;

            if (index < lh->Count) {
                *cell_offset = lh->List[index].Cell;

                return STATUS_SUCCESS;
            } else
                index -= lh->Count;
        }

        return STATUS_REGISTRY_CORRUPT;
    } else
        return STATUS_REGISTRY_CORRUPT;
}

static NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                               PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    size_t cell_offset;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_ENUMERATE_SUB_KEYS

    read_lock(&key->h->lock);

    size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    // FIXME - work with volatile keys

    if (Index >= kn->SubKeyCount) {
        read_unlock(&key->h->lock);
        return STATUS_NO_MORE_ENTRIES;
    }

    Status = get_key_item_by_index(key->h, kn->SubKeyList, Index, &cell_offset);
    if (!NT_SUCCESS(Status)) {
        read_unlock(&key->h->lock);
        return Status;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + cell_offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->bins + cell_offset + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    switch (KeyInformationClass) {
        case KeyBasicInformation: {
            KEY_BASIC_INFORMATION* kbi = KeyInformation;
            ULONG reqlen = offsetof(KEY_BASIC_INFORMATION, Name[0]);

            if (kn2->Flags & KEY_COMP_NAME)
                reqlen += kn2->NameLength * sizeof(WCHAR);
            else
                reqlen += kn2->NameLength;

            if (Length < reqlen) { // FIXME - should we be writing partial data, and returning STATUS_BUFFER_OVERFLOW?
                *ResultLength = reqlen;
                read_unlock(&key->h->lock);
                return STATUS_BUFFER_TOO_SMALL;
            }

            kbi->LastWriteTime.QuadPart = kn2->LastWriteTime;
            kbi->TitleIndex = 0;

            if (kn2->Flags & KEY_COMP_NAME) {
                unsigned int i;

                kbi->NameLength = kn2->NameLength * sizeof(WCHAR);

                for (i = 0; i < kn2->NameLength; i++) {
                    kbi->Name[i] = *((char*)kn2->Name + i);
                }
            } else {
                kbi->NameLength = kn2->NameLength;
                memcpy(kbi->Name, kn2->Name, kn2->NameLength);
            }

            *ResultLength = reqlen;

            break;
        }

        // FIXME - KeyFullInformation
        // FIXME - KeyNodeInformation

        default:
            read_unlock(&key->h->lock);
            return STATUS_INVALID_PARAMETER;
    }

    read_unlock(&key->h->lock);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                             PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ULONG reslen = 0;
    void* buf;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtEnumerateKey(KeyHandle, Index, KeyInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status)) {
        if (buf) {
            if (copy_to_user(KeyInformation, buf, reslen) != 0)
                Status = STATUS_INVALID_PARAMETER;
        }

        if (ResultLength) {
            if (put_user(reslen, ResultLength) < 0)
                Status = STATUS_INVALID_PARAMETER;
        }
    }

    if (buf)
        kfree(buf);

    return Status;
}

static NTSTATUS query_key_value(hive* h, CM_KEY_VALUE* vk, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {

    switch (KeyValueInformationClass) {
        case KeyValueBasicInformation: {
            KEY_VALUE_BASIC_INFORMATION* kvbi = KeyValueInformation;
            ULONG reqlen = offsetof(KEY_VALUE_BASIC_INFORMATION, Name[0]);

            if (vk->Flags & VALUE_COMP_NAME)
                reqlen += vk->NameLength * sizeof(WCHAR);
            else
                reqlen += vk->NameLength;

            if (Length < reqlen) { // FIXME - should we be writing partial data, and returning STATUS_BUFFER_OVERFLOW?
                *ResultLength = reqlen;
                return STATUS_BUFFER_TOO_SMALL;
            }

            kvbi->TitleIndex = 0;
            kvbi->Type = vk->Type;

            if (vk->Flags & VALUE_COMP_NAME) {
                unsigned int i;

                kvbi->NameLength = vk->NameLength * sizeof(WCHAR);

                for (i = 0; i < vk->NameLength; i++) {
                    kvbi->Name[i] = *((char*)vk->Name + i);
                }
            } else {
                kvbi->NameLength = vk->NameLength;
                memcpy(kvbi->Name, vk->Name, vk->NameLength);
            }

            *ResultLength = reqlen;

            return STATUS_SUCCESS;
        }

        case KeyValueFullInformation: {
            KEY_VALUE_FULL_INFORMATION* kvfi = KeyValueInformation;
            ULONG datalen = vk->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;
            ULONG reqlen = offsetof(KEY_VALUE_FULL_INFORMATION, Name[0]) + datalen;
            uint8_t* data;

            if (vk->Flags & VALUE_COMP_NAME)
                reqlen += vk->NameLength * sizeof(WCHAR);
            else
                reqlen += vk->NameLength;

            if (Length < reqlen) { // FIXME - should we be writing partial data, and returning STATUS_BUFFER_OVERFLOW?
                *ResultLength = reqlen;
                return STATUS_BUFFER_TOO_SMALL;
            }

            kvfi->TitleIndex = 0;
            kvfi->Type = vk->Type;

            if (vk->Flags & VALUE_COMP_NAME)
                kvfi->NameLength = vk->NameLength * sizeof(WCHAR);
            else
                kvfi->NameLength = vk->NameLength;

            kvfi->DataOffset = offsetof(KEY_VALUE_FULL_INFORMATION, Name[0]) + kvfi->NameLength;
            kvfi->DataLength = datalen;

            if (vk->Flags & VALUE_COMP_NAME) {
                unsigned int i;

                for (i = 0; i < vk->NameLength; i++) {
                    kvfi->Name[i] = *((char*)vk->Name + i);
                }
            } else
                memcpy(kvfi->Name, vk->Name, vk->NameLength);

            data = (uint8_t*)kvfi + kvfi->DataOffset;

            if (vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) // stored in cell
                // FIXME - make sure not more than 4 bytes

                memcpy(data, &vk->Data, datalen);
            else {
                // FIXME - check not out of bounds

                int32_t size = -*(int32_t*)((uint8_t*)h->bins + vk->Data);

                if (size < datalen + sizeof(int32_t))
                    return STATUS_REGISTRY_CORRUPT;

                memcpy(data, h->bins + vk->Data + sizeof(int32_t), datalen);
            }

            *ResultLength = reqlen;

            return STATUS_SUCCESS;
        }

        case KeyValuePartialInformation: {
            KEY_VALUE_PARTIAL_INFORMATION* kvpi = KeyValueInformation;
            ULONG len = vk->DataLength & 0x7fffffff;
            ULONG reqlen = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data[0]) + len;

            if (Length < reqlen) { // FIXME - should we be writing partial data, and returning STATUS_BUFFER_OVERFLOW?
                *ResultLength = reqlen;
                return STATUS_BUFFER_TOO_SMALL;
            }

            kvpi->TitleIndex = 0;
            kvpi->Type = vk->Type;
            kvpi->DataLength = len;

            if (vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) // stored in cell
                // FIXME - make sure not more than 4 bytes

                memcpy(kvpi->Data, &vk->Data, len);
            else {
                // FIXME - check not out of bounds

                int32_t size = -*(int32_t*)((uint8_t*)h->bins + vk->Data);

                if (size < len + sizeof(int32_t))
                    return STATUS_REGISTRY_CORRUPT;

                memcpy(kvpi->Data, h->bins + vk->Data + sizeof(int32_t), len);
            }

            *ResultLength = reqlen;

            return STATUS_SUCCESS;
        }

        // FIXME - KeyValueFullInformationAlign64
        // FIXME - KeyValuePartialInformationAlign64
        // FIXME - KeyValueLayerInformation

        default:
            return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    uint32_t* values_list;
    CM_KEY_VALUE* vk;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_QUERY_VALUE

    read_lock(&key->h->lock);

    size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    // FIXME - work with volatile keys

    if (Index >= kn->ValuesCount) {
        read_unlock(&key->h->lock);
        return STATUS_NO_MORE_ENTRIES;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[Index]);
    vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[Index] + sizeof(int32_t));

    if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    read_unlock(&key->h->lock);

    return Status;
}

NTSTATUS user_NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                  PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ULONG reslen = 0;
    void* buf;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status)) {
        if (buf) {
            if (copy_to_user(KeyValueInformation, buf, reslen) != 0)
                Status = STATUS_INVALID_PARAMETER;
        }

        if (ResultLength) {
            if (put_user(reslen, ResultLength) < 0)
                Status = STATUS_INVALID_PARAMETER;
        }
    }

    if (buf)
        kfree(buf);

    return Status;
}

static NTSTATUS NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    uint32_t* values_list;
    unsigned int i;

    if (!ValueName)
        return STATUS_INVALID_PARAMETER;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_QUERY_VALUE

    read_lock(&key->h->lock);

    size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    // FIXME - work with volatile keys

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        read_unlock(&key->h->lock);
        return STATUS_REGISTRY_CORRUPT;
    }

    values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

    for (i = 0; i < kn->ValuesCount; i++) {
        CM_KEY_VALUE* vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[i] + sizeof(int32_t));

        // FIXME - check not out of bounds

        size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[i]);

        if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
            read_unlock(&key->h->lock);
            return STATUS_REGISTRY_CORRUPT;
        }

        if (vk->Flags & VALUE_COMP_NAME) {
            if (vk->NameLength == ValueName->Length / sizeof(WCHAR)) {
                unsigned int j;
                char* s = (char*)vk->Name;
                bool found = true;

                for (j = 0; j < vk->NameLength; j++) {
                    WCHAR c1 = s[j];
                    WCHAR c2 = ValueName->Buffer[j];

                    if (c1 >= 'a' && c1 <= 'z')
                        c1 = c1 - 'a' + 'A';

                    if (c2 >= 'a' && c2 <= 'z')
                        c2 = c2 - 'a' + 'A';

                    if (c1 != c2) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
                    read_unlock(&key->h->lock);
                    return Status;
                }
            }
        } else {
            if (vk->NameLength == ValueName->Length) {
                unsigned int j;
                bool found = true;

                for (j = 0; j < vk->NameLength / sizeof(WCHAR); j++) {
                    WCHAR c1 = vk->Name[j];
                    WCHAR c2 = ValueName->Buffer[j];

                    if (c1 >= 'a' && c1 <= 'z')
                        c1 = c1 - 'a' + 'A';

                    if (c2 >= 'a' && c2 <= 'z')
                        c2 = c2 - 'a' + 'A';

                    if (c1 != c2) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
                    read_unlock(&key->h->lock);
                    return Status;
                }
            }
        }
    }

    read_unlock(&key->h->lock);

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS user_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                              PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    UNICODE_STRING us;
    ULONG reslen = 0;
    void* buf;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    if (ValueName) {
        if (!get_user_unicode_string(&us, ValueName)) {
            if (buf)
                kfree(buf);

            return STATUS_INVALID_PARAMETER;
        }
    } else {
        us.Length = us.MaximumLength = 0;
        us.Buffer = NULL;
    }

    Status = NtQueryValueKey(KeyHandle, &us, KeyValueInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status)) {
        if (buf) {
            if (copy_to_user(KeyValueInformation, buf, reslen) != 0)
                Status = STATUS_INVALID_PARAMETER;
        }

        if (ResultLength) {
            if (put_user(reslen, ResultLength) < 0)
                Status = STATUS_INVALID_PARAMETER;
        }
    }

    if (buf)
        kfree(buf);

    if (us.Buffer)
        kfree(us.Buffer);

    return Status;
}

static NTSTATUS allocate_cell(hive* h, uint32_t size, uint32_t* offset) {
    struct list_head* le;
    hive_hole* found_hh;

    size += sizeof(int32_t);

    if (size & 7)
        size += 8 - (size & 7);

    // FIXME - work with very large cells

    if (size > BIN_SIZE - sizeof(HBIN))
        return STATUS_INVALID_PARAMETER;

    // search in hive holes for exact match

    le = h->holes.next;

    while (le != &h->holes) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        if (hh->size == size) {
            *(int32_t*)(h->bins + hh->offset) = -size;

            list_del(&hh->list);

            *offset = hh->offset;

            kfree(hh);

            return STATUS_SUCCESS;
        }

        le = le->next;
    }

    // if exact match not found, choose next largest

    found_hh = NULL;
    le = h->holes.next;

    while (le != &h->holes) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        if (hh->size > size && (!found_hh || hh->size < found_hh->size))
            found_hh = hh;

        le = le->next;
    }

    if (found_hh) {
        *(int32_t*)(h->bins + found_hh->offset) = -size;

        *offset = found_hh->offset;

        found_hh->offset += size;
        found_hh->size -= size;

        return STATUS_SUCCESS;
    }

    // FIXME - if can't find anything, add new bin and extend file

    return STATUS_INTERNAL_ERROR;
}

static void free_cell(hive* h, uint32_t offset) {
    struct list_head* le;
    bool added = false;

    // add entry to hive holes

    le = h->holes.next;

    while (le != &h->holes) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        // FIXME - if follows on from previous, merge entries
        // FIXME - if follows on to next, merge entries

        if (hh->offset > offset) {
            hive_hole* hh2 = kmalloc(sizeof(hive_hole), GFP_KERNEL);

            // FIXME - handle malloc failure

            hh2->offset = offset;
            hh2->size = -*(int32_t*)(h->bins + offset);

            list_add(&hh2->list, hh->list.prev); // add before this one
            added = true;

            break;
        }

        le = le->next;
    }

    // add to end if not added already

    if (!added) {
        hive_hole* hh2 = kmalloc(sizeof(hive_hole), GFP_KERNEL);

        // FIXME - handle malloc failure

        hh2->offset = offset;
        hh2->size = -*(int32_t*)(h->bins + offset);

        list_add_tail(&hh2->list, &h->holes);
    }

    // change sign of cell size, to indicate now free

    *(int32_t*)(h->bins + offset) = -*(int32_t*)(h->bins + offset);
}

static NTSTATUS NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                              ULONG Type, PVOID Data, ULONG DataSize) {
    NTSTATUS Status;
    key_object* key;
    CM_KEY_NODE* kn;
    int32_t size;
    uint32_t vk_offset, values_list_offset;
    CM_KEY_VALUE* vk;
    uint32_t* values_list;

    // FIXME - should we be rejecting short REG_DWORDs etc. here?

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check for KEY_SET_VALUE in access mask

    write_lock(&key->h->lock);

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    // FIXME - work with volatile keys

    if (kn->ValuesCount > 0) {
        unsigned int i;

        size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

        if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
        }

        values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

        for (i = 0; i < kn->ValuesCount; i++) {
            bool found = false;

            vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[i] + sizeof(int32_t));

            // FIXME - check not out of bounds

            size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[i]);

            if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
                Status = STATUS_REGISTRY_CORRUPT;
                goto end;
            }

            if (!ValueName || ValueName->Length == 0)
                found = vk->NameLength == 0;
            else {
                if (vk->Flags & VALUE_COMP_NAME) {
                    if (vk->NameLength == ValueName->Length / sizeof(WCHAR)) {
                        unsigned int j;
                        char* s = (char*)vk->Name;

                        found = true;

                        for (j = 0; j < vk->NameLength; j++) {
                            WCHAR c1 = s[j];
                            WCHAR c2 = ValueName->Buffer[j];

                            if (c1 >= 'a' && c1 <= 'z')
                                c1 = c1 - 'a' + 'A';

                            if (c2 >= 'a' && c2 <= 'z')
                                c2 = c2 - 'a' + 'A';

                            if (c1 != c2) {
                                found = false;
                                break;
                            }
                        }
                    }
                } else {
                    if (vk->NameLength == ValueName->Length) {
                        unsigned int j;

                        found = true;

                        for (j = 0; j < vk->NameLength / sizeof(WCHAR); j++) {
                            WCHAR c1 = vk->Name[j];
                            WCHAR c2 = ValueName->Buffer[j];

                            if (c1 >= 'a' && c1 <= 'z')
                                c1 = c1 - 'a' + 'A';

                            if (c2 >= 'a' && c2 <= 'z')
                                c2 = c2 - 'a' + 'A';

                            if (c1 != c2) {
                                found = false;
                                break;
                            }
                        }
                    }
                }
            }

            if (found) {
                if (vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE || vk->DataLength == 0) {
                    if (DataSize <= sizeof(uint32_t)) { // if was resident and still would be resident, write into vk
                        memcpy(&vk->Data, Data, DataSize);
                        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
                        vk->Type = Type;
                    } else { // if was resident and won't be, allocate cell for new data and write
                        uint32_t cell;

                        Status = allocate_cell(key->h, DataSize, &cell);
                        if (!NT_SUCCESS(Status))
                            goto end;

                        memcpy(key->h->bins + cell + sizeof(int32_t), Data, DataSize);

                        vk->Data = cell;
                        vk->DataLength = DataSize;
                        vk->Type = Type;
                    }
                } else {
                    if (DataSize <= sizeof(uint32_t)) { // if wasn't resident but will be, free data cell and write into vk
                        free_cell(key->h, vk->Data);

                        memcpy(&vk->Data, Data, DataSize);
                        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
                        vk->Type = Type;
                    } else {
                        int32_t old_cell_size = -*(int32_t*)((uint8_t*)key->h->bins + vk->Data);
                        int32_t new_cell_size;

                        new_cell_size = sizeof(int32_t) + DataSize;

                        if (new_cell_size & 7)
                            new_cell_size += 8 - (new_cell_size & 7);

                        if (old_cell_size == new_cell_size) { // if wasn't resident, still won't be, and cell similar size, write over existing data
                            memcpy(key->h->bins + vk->Data + sizeof(int32_t), Data, DataSize);
                            vk->DataLength = DataSize;
                            vk->Type = Type;
                        } else { // if wasn't resident, still won't be, and cell different size, free data cell and allocate new one
                            uint32_t cell;

                            Status = allocate_cell(key->h, DataSize, &cell);
                            if (!NT_SUCCESS(Status))
                                goto end;

                            free_cell(key->h, vk->Data);

                            vk->Data = cell;
                            vk->DataLength = DataSize;
                            vk->Type = Type;

                            memcpy(key->h->bins + vk->Data + sizeof(int32_t), Data, DataSize);
                        }
                    }
                }

                Status = STATUS_SUCCESS;
                goto end;
            }
        }
    }

    // new entry

    // allocate cell for vk

    Status = allocate_cell(key->h, offsetof(CM_KEY_VALUE, Name[0]) + (ValueName ? ValueName->Length : 0), &vk_offset);
    if (!NT_SUCCESS(Status))
        goto end;

    vk = (CM_KEY_VALUE*)(key->h->bins + vk_offset + sizeof(int32_t));
    vk->Signature = CM_KEY_VALUE_SIGNATURE;
    vk->NameLength = ValueName ? ValueName->Length : 0;
    vk->Type = Type;
    vk->Flags = 0;
    vk->Spare = 0;

    if (vk->NameLength > 0)
        memcpy(vk->Name, ValueName->Buffer, vk->NameLength);

    if (DataSize > sizeof(uint32_t)) {
        vk->DataLength = DataSize;

        Status = allocate_cell(key->h, DataSize, &vk->Data);
        if (!NT_SUCCESS(Status)) {
            free_cell(key->h, vk_offset);
            goto end;
        }

        memcpy(key->h->bins + vk->Data + sizeof(int32_t), Data, DataSize);
    } else {
        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
        memcpy(&vk->Data, Data, DataSize);
    }

    if (kn->ValuesCount > 0) {
        int32_t old_size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);
        int32_t new_size = ((kn->ValuesCount + 1) * sizeof(uint32_t)) + sizeof(int32_t);

        if (new_size & 7)
            new_size += 8 - (new_size & 7);

        if (old_size == new_size) { // if enough space in values list, add to the end
            values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

            values_list[kn->ValuesCount] = vk_offset;
            kn->ValuesCount++;

            Status = STATUS_SUCCESS;

            goto end;
        }
    }

    Status = allocate_cell(key->h, sizeof(uint32_t) * (kn->ValuesCount + 1), &values_list_offset);
    if (!NT_SUCCESS(Status)) {
        if (!(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) && vk->DataLength != 0)
            free_cell(key->h, vk->Data);

        free_cell(key->h, vk_offset);
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)key->h->bins + values_list_offset + sizeof(int32_t));

    if (kn->ValuesCount > 0) {
        uint32_t* old_values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

        memcpy(values_list, old_values_list, kn->ValuesCount * sizeof(uint32_t));

        free_cell(key->h, kn->Values);
    }

    values_list[kn->ValuesCount] = vk_offset;

    kn->Values = values_list_offset;
    kn->ValuesCount++;

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status))
        key->h->dirty = true;

    write_unlock(&key->h->lock);

    return Status;
}

NTSTATUS user_NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                            ULONG Type, PVOID Data, ULONG DataSize) {
    NTSTATUS Status;
    UNICODE_STRING us;
    void* buf;

    if (ValueName) {
        if (!get_user_unicode_string(&us, ValueName))
            return STATUS_INVALID_PARAMETER;
    } else {
        us.Length = us.MaximumLength = 0;
        us.Buffer = NULL;
    }

    if (DataSize > 0) {
        buf = kmalloc(DataSize, GFP_KERNEL);
        if (!buf) {
            if (us.Buffer)
                kfree(us.Buffer);

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (copy_from_user(buf, Data, DataSize) != 0) {
            if (us.Buffer)
                kfree(us.Buffer);

            kfree(buf);

            return STATUS_INVALID_PARAMETER;
        }
    } else
        buf = NULL;

    Status = NtSetValueKey(KeyHandle, &us, TitleIndex, Type, buf, DataSize);

    if (us.Buffer)
        kfree(us.Buffer);

    if (buf)
        kfree(buf);

    return Status;
}

static NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    NTSTATUS Status;
    key_object* key;
    CM_KEY_NODE* kn;
    int32_t size;
    unsigned int i;
    uint32_t* values_list;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check for KEY_SET_VALUE in access mask

    write_lock(&key->h->lock);

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (kn->ValuesCount == 0) {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto end;
    }

    size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

    for (i = 0; i < kn->ValuesCount; i++) {
        bool found = false;
        CM_KEY_VALUE* vk;

        vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[i] + sizeof(int32_t));

        // FIXME - check not out of bounds

        size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[i]);

        if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
        }

        if (!ValueName || ValueName->Length == 0)
            found = vk->NameLength == 0;
        else {
            if (vk->Flags & VALUE_COMP_NAME) {
                if (vk->NameLength == ValueName->Length / sizeof(WCHAR)) {
                    unsigned int j;
                    char* s = (char*)vk->Name;

                    found = true;

                    for (j = 0; j < vk->NameLength; j++) {
                        WCHAR c1 = s[j];
                        WCHAR c2 = ValueName->Buffer[j];

                        if (c1 >= 'a' && c1 <= 'z')
                            c1 = c1 - 'a' + 'A';

                        if (c2 >= 'a' && c2 <= 'z')
                            c2 = c2 - 'a' + 'A';

                        if (c1 != c2) {
                            found = false;
                            break;
                        }
                    }
                }
            } else {
                if (vk->NameLength == ValueName->Length) {
                    unsigned int j;

                    found = true;

                    for (j = 0; j < vk->NameLength / sizeof(WCHAR); j++) {
                        WCHAR c1 = vk->Name[j];
                        WCHAR c2 = ValueName->Buffer[j];

                        if (c1 >= 'a' && c1 <= 'z')
                            c1 = c1 - 'a' + 'A';

                        if (c2 >= 'a' && c2 <= 'z')
                            c2 = c2 - 'a' + 'A';

                        if (c1 != c2) {
                            found = false;
                            break;
                        }
                    }
                }
            }
        }

        if (found) {
            uint32_t vk_offset = values_list[i];

            if (kn->ValuesCount == 1) {
                free_cell(key->h, kn->Values);
                kn->Values = 0;
            } else {
                int32_t old_size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);
                int32_t new_size = ((kn->ValuesCount - 1) * sizeof(uint32_t)) + sizeof(int32_t);

                if (new_size & 7)
                    new_size += 8 - (new_size & 7);

                if (old_size == new_size) // if values list right size, update
                    memcpy(&values_list[i], &values_list[i+1], (kn->ValuesCount - i - 1) * sizeof(uint32_t));
                else {
                    uint32_t values_list_offset;
                    uint32_t* new_values_list;

                    Status = allocate_cell(key->h, sizeof(uint32_t) * (kn->ValuesCount - 1), &values_list_offset);
                    if (!NT_SUCCESS(Status))
                        goto end;

                    new_values_list = (uint32_t*)((uint8_t*)key->h->bins + values_list_offset + sizeof(int32_t));

                    memcpy(new_values_list, values_list, i * sizeof(uint32_t));
                    memcpy(&new_values_list[i], &values_list[i+1], (kn->ValuesCount - i - 1) * sizeof(uint32_t));

                    kn->Values = values_list_offset;
                }
            }

            if (vk->DataLength != 0 && !(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE)) // free data cell, if not resident
                free_cell(key->h, vk->Data);

            free_cell(key->h, vk_offset);

            kn->ValuesCount--;

            Status = STATUS_SUCCESS;
            goto end;
        }
    }

    Status = STATUS_OBJECT_NAME_NOT_FOUND;

end:
    if (NT_SUCCESS(Status))
        key->h->dirty = true;

    write_unlock(&key->h->lock);

    return Status;
}

NTSTATUS user_NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    NTSTATUS Status;
    UNICODE_STRING us;

    if (ValueName) {
        if (!get_user_unicode_string(&us, ValueName))
            return STATUS_INVALID_PARAMETER;
    } else {
        us.Length = us.MaximumLength = 0;
        us.Buffer = NULL;
    }

    Status = NtDeleteValueKey(KeyHandle, &us);

    if (us.Buffer)
        kfree(us.Buffer);

    return Status;
}

static NTSTATUS lh_copy_and_add(hive* h, CM_KEY_FAST_INDEX* old_lh, uint32_t* offset, uint32_t cell, uint32_t hash,
                                UNICODE_STRING* us) {
    NTSTATUS Status;
    CM_KEY_FAST_INDEX* lh;
    unsigned int i;
    uint32_t pos;
    bool found = false;

    for (i = 0; i < old_lh->Count; i++) {
        int32_t size = -*(int32_t*)(h->bins + old_lh->List[i].Cell);
        uint16_t sig;
        CM_KEY_NODE* kn;

        // FIXME - check not out of bounds

        if (size < sizeof(int32_t) + sizeof(uint16_t))
            return STATUS_REGISTRY_CORRUPT;

        sig = *(uint16_t*)(h->bins + old_lh->List[i].Cell + sizeof(int32_t));

        if (sig != CM_KEY_NODE_SIGNATURE)
            return STATUS_REGISTRY_CORRUPT;

        kn = (CM_KEY_NODE*)(h->bins + old_lh->List[i].Cell + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn->NameLength)
            return STATUS_REGISTRY_CORRUPT;

        if (kn->Flags & KEY_COMP_NAME) {
            bool stop = false;
            unsigned int j;
            unsigned int len = kn->NameLength;

            if (len > us->Length / sizeof(WCHAR))
                len = us->Length / sizeof(WCHAR);

            for (j = 0; j < len; j++) {
                WCHAR c1 = ((char*)kn->Name)[j];
                WCHAR c2 = us->Buffer[j];

                if (c1 >= 'a' && c1 <= 'z')
                    c1 = c1 - 'a' + 'A';

                if (c2 >= 'a' && c2 <= 'z')
                    c2 = c2 - 'a' + 'A';

                if (c1 < c2) {
                    stop = true;
                    break;
                }

                if (c1 > c2) {
                    found = true;
                    pos = i;
                    break;
                }
            }

            if (found)
                break;

            if (!stop && kn->NameLength > us->Length / sizeof(WCHAR)) {
                pos = i;
                found = true;
                break;
            }
        } else {
            bool stop = false;
            unsigned int j;
            unsigned int len = kn->NameLength / sizeof(WCHAR);

            if (len > us->Length / sizeof(WCHAR))
                len = us->Length / sizeof(WCHAR);

            for (j = 0; j < len; j++) {
                WCHAR c1 = kn->Name[j];
                WCHAR c2 = us->Buffer[j];

                if (c1 >= 'a' && c1 <= 'z')
                    c1 = c1 - 'a' + 'A';

                if (c2 >= 'a' && c2 <= 'z')
                    c2 = c2 - 'a' + 'A';

                if (c1 < c2) {
                    stop = true;
                    break;
                }

                if (c1 > c2) {
                    found = true;
                    pos = i;
                    break;
                }
            }

            if (found)
                break;

            if (!stop && kn->NameLength > us->Length) {
                pos = i;
                found = true;
                break;
            }
        }
    }

    if (!found)
        pos = old_lh->Count - 1;

    Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * (old_lh->Count + 1)), offset);
    if (!NT_SUCCESS(Status))
        return Status;

    lh = (CM_KEY_FAST_INDEX*)(h->bins + *offset + sizeof(int32_t));

    lh->Signature = CM_KEY_HASH_LEAF;
    lh->Count = old_lh->Count + 1;

    memcpy(lh->List, old_lh->List, pos * sizeof(CM_INDEX));

    lh->List[pos].Cell = cell;
    lh->List[pos].HashKey = hash;

    memcpy(&lh->List[pos+1], &old_lh->List[pos], old_lh->Count - pos);

    return STATUS_SUCCESS;
}

static NTSTATUS NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                            PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    NTSTATUS Status;
    UNICODE_STRING us;
    uint32_t offset, subkey_offset;
    key_object* k;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint32_t hash;

    static const WCHAR prefix[] = L"\\Registry\\";
    static const WCHAR machine[] = L"Machine";

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES))
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        printk(KERN_ALERT "NtCreateKey: FIXME - support RootDirectory\n"); // FIXME
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

    if (us.Length < sizeof(machine) - sizeof(WCHAR) || wcsnicmp(us.Buffer, machine, (sizeof(machine) - sizeof(WCHAR)) / sizeof(WCHAR)))
        return STATUS_OBJECT_PATH_INVALID;

    us.Buffer += (sizeof(machine) - sizeof(WCHAR)) / sizeof(WCHAR);
    us.Length -= sizeof(machine) - sizeof(WCHAR);

    if (us.Length >= sizeof(WCHAR) && us.Buffer[0] != '\\')
        return STATUS_OBJECT_PATH_INVALID;

    if (!system_hive.data) // HKLM not loaded
        return STATUS_OBJECT_PATH_INVALID;

    write_lock(&system_hive.lock);

    // get offset for kn of parent

    Status = open_key_in_hive(&system_hive, &us, &offset, true);
    if (!NT_SUCCESS(Status))
        goto end;

    if (us.Length < sizeof(WCHAR)) {
        Status = STATUS_OBJECT_NAME_INVALID;
        goto end;
    }

    // FIXME - make sure SD allows us to create subkeys

    // if already exists, set Disposition to REG_OPENED_EXISTING_KEY, create handle, and return

    Status = find_subkey(&system_hive, offset, &us, &subkey_offset);
    if (NT_SUCCESS(Status)) {
        k = kmalloc(sizeof(key_object), GFP_KERNEL);
        if (!k) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        k->header.refcount = 1;
        k->header.type = muwine_object_key;
        k->header.close = key_object_close;
        k->h = &system_hive;
        __sync_add_and_fetch(&system_hive.refcount, 1);
        k->offset = offset;

        Status = muwine_add_handle(&k->header, KeyHandle);

        if (!NT_SUCCESS(Status))
            kfree(k);

        if (Disposition)
            *Disposition = REG_OPENED_EXISTING_KEY;

        goto end;
    } else if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
        goto end;

    if (CreateOptions & REG_OPTION_VOLATILE) {
        // FIXME - creating volatile keys
        printk(KERN_ALERT "NtCreateKey: FIXME - support creating volatile keys\n"); // FIXME
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    // FIXME - don't allow non-volatile keys to be created under volatile parent

    // allocate space for new kn

    Status = allocate_cell(&system_hive, offsetof(CM_KEY_NODE, Name) + us.Length, &subkey_offset);
    if (!NT_SUCCESS(Status))
        goto end;

    // FIXME - compute SD and allocate or find cell for it

    kn2 = (CM_KEY_NODE*)((uint8_t*)system_hive.bins + subkey_offset + sizeof(int32_t));

    kn2->Signature = CM_KEY_NODE_SIGNATURE;
    kn2->Flags = 0;
    kn2->LastWriteTime = 0; // FIXME
    kn2->Spare = 0;
    kn2->Parent = offset;
    kn2->SubKeyCount = 0;
    kn2->VolatileSubKeyCount = 0;
    kn2->SubKeyList = 0;
    kn2->VolatileSubKeyList = 0;
    kn2->ValuesCount = 0;
    kn2->Values = 0;
    kn2->Security = 0; // FIXME
    kn2->Class = 0; // FIXME
    kn2->MaxNameLen = 0;
    kn2->MaxClassLen = 0;
    kn2->MaxValueNameLen = 0;
    kn2->MaxValueDataLen = 0;
    kn2->WorkVar = 0;
    kn2->NameLength = us.Length;
    kn2->ClassLength = 0; // FIXME
    memcpy(kn2->Name, us.Buffer, us.Length);

    // open kn of parent (checking already done in open_key_in_hive)

    kn = (CM_KEY_NODE*)((uint8_t*)system_hive.bins + offset + sizeof(int32_t));

    hash = calc_subkey_hash(&us);

    // add handle here, to make things easier if we fail later on

    k = kmalloc(sizeof(key_object), GFP_KERNEL);
    if (!k) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    k->header.refcount = 1;
    k->header.type = muwine_object_key;
    k->header.close = key_object_close;
    k->h = &system_hive;
    __sync_add_and_fetch(&system_hive.refcount, 1);

    Status = muwine_add_handle(&k->header, KeyHandle);

    if (!NT_SUCCESS(Status)) {
        kfree(k);
        goto end;
    }

    if (kn->SubKeyCount == 0) {
        CM_KEY_FAST_INDEX* lh;
        uint32_t lh_offset;

        Status = allocate_cell(&system_hive, offsetof(CM_KEY_FAST_INDEX, List[0]) + sizeof(CM_INDEX), &lh_offset);
        if (!NT_SUCCESS(Status)) {
            free_cell(&system_hive, subkey_offset);
            NtClose(*KeyHandle);
            goto end;
        }

        lh = (CM_KEY_FAST_INDEX*)(system_hive.bins + lh_offset + sizeof(int32_t));

        lh->Signature = CM_KEY_HASH_LEAF;
        lh->Count = 1;
        lh->List[0].Cell = subkey_offset;
        lh->List[0].HashKey = hash;

        kn->MaxNameLen = us.Length;
        kn->SubKeyCount = 1;
        kn->SubKeyList = lh_offset;

        k->offset = subkey_offset;
    } else {
        uint16_t sig;
        int32_t size;

        size = -*(int32_t*)(system_hive.bins + kn->SubKeyList);

        if (size < sizeof(int32_t) + sizeof(uint16_t)) {
            free_cell(&system_hive, subkey_offset);
            NtClose(*KeyHandle);
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
        }

        sig = *(uint16_t*)(system_hive.bins + kn->SubKeyList + sizeof(int32_t));

        // FIXME - dealing with existing ri rather than lh
        // FIXME - creating new ri if lh gets too large

        if (sig == CM_KEY_HASH_LEAF) {
            CM_KEY_FAST_INDEX* old_lh;
            uint32_t lh_offset;

            old_lh = (CM_KEY_FAST_INDEX*)(system_hive.bins + kn->SubKeyList + sizeof(int32_t));

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * old_lh->Count)) {
                free_cell(&system_hive, subkey_offset);
                NtClose(*KeyHandle);
                Status = STATUS_REGISTRY_CORRUPT;
                goto end;
            }

            Status = lh_copy_and_add(&system_hive, old_lh, &lh_offset, subkey_offset, hash, &us);
            if (!NT_SUCCESS(Status)) {
                free_cell(&system_hive, subkey_offset);
                NtClose(*KeyHandle);
                goto end;
            }

            free_cell(&system_hive, kn->SubKeyList);

            kn->SubKeyCount++;
            kn->SubKeyList = lh_offset;

            if (us.Length > kn->MaxNameLen)
                kn->MaxNameLen = us.Length;
        } else {
            printk(KERN_ALERT "NtCreateKey: unhandled list type %x\n", sig);
            Status = STATUS_NOT_IMPLEMENTED;
            NtClose(*KeyHandle);
            goto end;
        }
    }

    if (Disposition)
        *Disposition = REG_CREATED_NEW_KEY;

    k->h->dirty = true;

    Status = STATUS_SUCCESS;

end:
    write_unlock(&system_hive.lock);

    return Status;
}

NTSTATUS user_NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                          PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    ULONG dispos;
    UNICODE_STRING us;

    if (!ObjectAttributes || !KeyHandle)
        return STATUS_INVALID_PARAMETER;

    if (Class) {
        if (!get_user_unicode_string(&us, Class))
            return STATUS_INVALID_PARAMETER;
    } else {
        us.Length = us.MaximumLength = 0;
        us.Buffer = NULL;
    }

    if (!get_user_object_attributes(&oa, ObjectAttributes)) {
        if (us.Buffer)
            kfree(us.Buffer);

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateKey(&h, DesiredAccess, &oa, TitleIndex, Class ? &us : NULL, CreateOptions, &dispos);

    if (us.Buffer)
        kfree(us.Buffer);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (NT_SUCCESS(Status)) {
        if (put_user(h, KeyHandle) != 0)
            return STATUS_INVALID_PARAMETER;

        if (Disposition) {
            if (put_user(dispos, Disposition) != 0)
                return STATUS_INVALID_PARAMETER;
        }
    }

    return Status;
}
