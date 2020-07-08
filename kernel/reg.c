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

    system_hive.bins = (uint8_t*)system_hive.data + 0x1000; // FIXME
    system_hive.refcount = 0;

    clear_volatile(&system_hive, ((HBASE_BLOCK*)system_hive.data)->RootCell);

    return STATUS_SUCCESS;
}

void muwine_free_reg(void) {
    if (system_hive.data)
        vfree(system_hive.data);
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

static NTSTATUS search_lh(hive* h, CM_KEY_FAST_INDEX* lh, uint32_t hash, UNICODE_STRING* us, size_t* offset_out) {
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

static NTSTATUS find_subkey(hive* h, size_t offset, UNICODE_STRING* us, size_t* offset_out) {
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
        return STATUS_OBJECT_PATH_INVALID;

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

static NTSTATUS open_key_in_hive(hive* h, UNICODE_STRING* us, PHANDLE KeyHandle, ACCESS_MASK DesiredAccess) {
    NTSTATUS Status;
    size_t offset;
    key_object* k;

    // FIXME - get hive mutex

    // loop through parts and locate

    offset = ((HBASE_BLOCK*)h->data)->RootCell;

    do {
        while (us->Length >= sizeof(WCHAR) && *us->Buffer == '\\') {
            us->Length -= sizeof(WCHAR);
            us->Buffer++;
        }

        if (us->Length == 0)
            break;

        // FIXME - should this be checking for KEY_ENUMERATE_SUB_KEYS against all keys in path?

        Status = find_subkey(h, offset, us, &offset);
        if (!NT_SUCCESS(Status))
            return Status;

        while (us->Length >= sizeof(WCHAR) && *us->Buffer != '\\') {
            us->Length -= sizeof(WCHAR);
            us->Buffer++;
        }
    } while (true);

    // FIXME - do SeAccessCheck
    // FIXME - store access mask in handle

    // create key object and return handle

    k = kmalloc(sizeof(key_object), GFP_KERNEL);
    if (!k)
        return STATUS_INSUFFICIENT_RESOURCES;

    k->header.refcount = 1;
    k->header.type = muwine_object_key;
    k->header.close = key_object_close;
    k->h = h;
    __sync_add_and_fetch(&h->refcount, 1);
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

    size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return STATUS_REGISTRY_CORRUPT;

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE)
        return STATUS_REGISTRY_CORRUPT;

    // FIXME - work with volatile keys

    if (Index >= kn->SubKeyCount)
        return STATUS_NO_MORE_ENTRIES;

    Status = get_key_item_by_index(key->h, kn->SubKeyList, Index, &cell_offset);
    if (!NT_SUCCESS(Status))
        return Status;

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + cell_offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return STATUS_REGISTRY_CORRUPT;

    kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->bins + cell_offset + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE)
        return STATUS_REGISTRY_CORRUPT;

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength)
        return STATUS_REGISTRY_CORRUPT;

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
            return STATUS_INVALID_PARAMETER;
    }

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

static NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    uint32_t* values_list;
    CM_KEY_VALUE* vk;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_QUERY_VALUE

    size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return STATUS_REGISTRY_CORRUPT;

    kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE)
        return STATUS_REGISTRY_CORRUPT;

    // FIXME - work with volatile keys

    if (Index >= kn->ValuesCount)
        return STATUS_NO_MORE_ENTRIES;

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t)))
        return STATUS_REGISTRY_CORRUPT;

    values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[Index]);
    vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[Index] + sizeof(int32_t));

    if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength)
        return STATUS_REGISTRY_CORRUPT;

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

            break;
        }

        // FIXME - KeyValueFullInformation
        // FIXME - KeyValuePartialInformation
        // FIXME - KeyValueFullInformationAlign64
        // FIXME - KeyValuePartialInformationAlign64
        // FIXME - KeyValueLayerInformation

        default:
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
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
