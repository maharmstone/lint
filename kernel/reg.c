#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <linux/namei.h>
#include "muwine.h"
#include "reg.h"

#define REG_FLUSH_INTERVAL 30 // seconds

static void key_object_close(object_header* obj);
static void reg_flush_timer_handler(struct timer_list* timer);
static NTSTATUS flush_hive(hive* h);
static int reboot_callback(struct notifier_block* self, unsigned long val, void* data);

static const WCHAR symlinkval[] = L"SymbolicLinkValue";

LIST_HEAD(hive_list);
DECLARE_RWSEM(hive_list_sem);
LIST_HEAD(symlink_list);
DEFINE_RWLOCK(symlink_lock);
DEFINE_TIMER(reg_flush_timer, reg_flush_timer_handler);

static struct task_struct* reg_flush_thread = NULL;
static bool reg_thread_running = true;

static struct notifier_block reboot_notifier = {
    .notifier_call = reboot_callback,
};

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

    if (base_block->Minor < HSYS_MAX_MINOR) {
        printk(KERN_ALERT "muwine: hive had unsupported minor value %x.\n", base_block->Minor);
        return false;
    }

    if (base_block->Minor > HSYS_MAX_MINOR) {
        printk(KERN_ALERT "muwine: hive had unsupported minor value %x.\n", base_block->Minor);
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

    nk->Flags &= ~KEY_HIVE_EXIT;
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
            unsigned int j;

            CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + ri->List[i] + sizeof(int32_t));

            for (j = 0; j < lh->Count; j++) {
                clear_volatile(h, lh->List[j].Cell);
            }
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
    CM_KEY_NODE* root_cell;

    h->refcount = 0;

    h->bins = (uint8_t*)h->data + BIN_SIZE;
    clear_volatile(h, ((HBASE_BLOCK*)h->data)->RootCell);

    // FIXME - check size, is in bounds, and signature
    root_cell = (CM_KEY_NODE*)((uint8_t*)h->bins + ((HBASE_BLOCK*)h->data)->RootCell + sizeof(int32_t));
    root_cell->Flags |= KEY_HIVE_ENTRY;

    INIT_LIST_HEAD(&h->holes);
    INIT_LIST_HEAD(&h->volatile_holes);
    init_rwsem(&h->sem);

    h->dirty = false;
    h->volatile_bins = NULL;
    h->volatile_size = 0;
    h->size = ((HBASE_BLOCK*)h->data)->Length + BIN_SIZE;

    off = h->bins;
    while (off < h->bins + ((HBASE_BLOCK*)h->data)->Length) {
        Status = find_bin_holes(h, &off);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    return STATUS_SUCCESS;
}

static void free_hive(hive* h) {
    while (!list_empty(&h->holes)) {
        hive_hole* hh = list_entry(h->holes.next, hive_hole, list);

        list_del(&hh->list);

        kfree(hh);
    }

    if (h->data)
        vfree(h->data);
    else if (h->bins)
        vfree(h->bins);

    if (h->path.Buffer)
        kfree(h->path.Buffer);

    if (h->fs_path)
        kfree(h->fs_path);

    list_del(&h->list);

    kfree(h);
}

void muwine_free_reg(void) {
    if (reg_flush_thread) {
        reg_thread_running = false;
        wake_up_process(reg_flush_thread);
    }

    down_write(&hive_list_sem);

    while (!list_empty(&hive_list)) {
        hive* h = list_entry(hive_list.next, hive, list);

        flush_hive(h);

        free_hive(h);
    }

    up_write(&hive_list_sem);

    write_lock(&symlink_lock);

    while (!list_empty(&symlink_list)) {
        symlink* s = list_entry(symlink_list.next, symlink, list);

        kfree(s->source);
        kfree(s->destination);

        list_del(&s->list);

        kfree(s);
    }

    write_unlock(&symlink_lock);

    unregister_reboot_notifier(&reboot_notifier);
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

static NTSTATUS search_lh(hive* h, CM_KEY_FAST_INDEX* lh, uint32_t hash, UNICODE_STRING* us, bool is_volatile, uint32_t* offset_out) {
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

            if (is_volatile)
                size = -*(int32_t*)((uint8_t*)h->volatile_bins + lh->List[i].Cell);
            else
                size = -*(int32_t*)((uint8_t*)h->bins + lh->List[i].Cell);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
                return STATUS_REGISTRY_CORRUPT;

            if (is_volatile)
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + lh->List[i].Cell + sizeof(int32_t));
            else
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

static NTSTATUS search_index(hive* h, uint32_t offset, UNICODE_STRING* us, uint32_t hash, bool is_volatile, uint32_t* offset_out) {
    uint16_t sig;
    int32_t size;
    void* bins = is_volatile ? h->volatile_bins : h->bins;

    // FIXME - check not out of bounds

    sig = *(uint16_t*)((uint8_t*)bins + offset + sizeof(int32_t));
    size = -*(int32_t*)((uint8_t*)bins + offset);

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
            return STATUS_REGISTRY_CORRUPT;

        return search_lh(h, lh, hash, us, is_volatile, offset_out);
    } else if (sig == CM_KEY_INDEX_ROOT) {
        unsigned int i;
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)((uint8_t*)bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_INDEX, List[0]) + (ri->Count * sizeof(uint32_t)))
            return STATUS_REGISTRY_CORRUPT;

        for (i = 0; i < ri->Count; i++) {
            NTSTATUS Status;
            CM_KEY_FAST_INDEX* lh = (CM_KEY_FAST_INDEX*)((uint8_t*)bins + ri->List[i] + sizeof(int32_t));

            size = -*(int32_t*)((uint8_t*)bins + ri->List[i]);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
                return STATUS_REGISTRY_CORRUPT;

            Status = search_lh(h, lh, hash, us, is_volatile, offset_out);
            if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
                return Status;
        }

        return STATUS_OBJECT_PATH_NOT_FOUND;
    } else
        return STATUS_REGISTRY_CORRUPT;
}

static NTSTATUS find_subkey(hive* h, uint32_t offset, UNICODE_STRING* us, uint32_t* offset_out, bool* is_volatile) {
    NTSTATUS Status;
    uint32_t hash = calc_subkey_hash(us);
    int32_t size;
    CM_KEY_NODE* kn;

    if (*is_volatile)
        size = -*(int32_t*)((uint8_t*)h->volatile_bins + offset);
    else
        size = -*(int32_t*)((uint8_t*)h->bins + offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]))
        return STATUS_REGISTRY_CORRUPT;

    if (*is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE)
        return STATUS_REGISTRY_CORRUPT;

    if (kn->SubKeyCount > 0) {
        Status = search_index(h, kn->SubKeyList, us, hash, false, offset_out);
        if (NT_SUCCESS(Status)) {
            *is_volatile = false;
            return Status;
        } else if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
            return Status;
    }

    if (kn->VolatileSubKeyCount > 0) {
        Status = search_index(h, kn->VolatileSubKeyList, us, hash, true, offset_out);
        if (NT_SUCCESS(Status)) {
            *is_volatile = true;
            return Status;
        } else if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
            return Status;
    }

    return STATUS_OBJECT_PATH_NOT_FOUND;
}

static NTSTATUS open_key_in_hive(hive* h, UNICODE_STRING* us, uint32_t* ret_offset, bool parent,
                                 bool* is_volatile, bool* parent_is_volatile) {
    NTSTATUS Status;
    uint32_t offset;
    bool vol, parent_vol;

    // loop through parts and locate

    if (h->depth == 0) { // volatile root
        offset = h->volatile_root_cell;
        vol = true;
    } else {
        offset = ((HBASE_BLOCK*)h->data)->RootCell;
        vol = false;
    }

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

        parent_vol = vol;

        Status = find_subkey(h, offset, us, &offset, &vol);
        if (!NT_SUCCESS(Status))
            return Status;

        while (us->Length >= sizeof(WCHAR) && *us->Buffer != '\\') {
            us->Length -= sizeof(WCHAR);
            us->Buffer++;
        }
    } while (true);

    *ret_offset = offset;
    *is_volatile = vol;

    if (parent_is_volatile)
        *parent_is_volatile = parent_vol;

    return STATUS_SUCCESS;
}

static NTSTATUS resolve_symlinks(UNICODE_STRING* us, bool* done_alloc) {
    UNICODE_STRING us2;
    bool alloc = false;
    struct list_head* le;
    unsigned int count = 0;

    us2.Buffer = us->Buffer;
    us2.Length = us->Length;

    read_lock(&symlink_lock);

    while (true) {
        bool found = false;

        le = symlink_list.next;
        while (le != &symlink_list) {
            symlink* s = list_entry(le, symlink, list);

            if ((us2.Length <= s->source_len || us2.Buffer[s->source_len / sizeof(WCHAR)] != '\\') &&
                us2.Length != s->source_len) {
                le = le->next;
                continue;
            }

            if (wcsnicmp(us2.Buffer, s->source, s->source_len / sizeof(WCHAR))) {
                le = le->next;
                continue;
            }

            if (us2.Length == s->source_len) {
                WCHAR* buf = kmalloc(s->destination_len, GFP_KERNEL); // FIXME - handle malloc failure

                memcpy(buf, s->destination, s->destination_len);

                if (alloc)
                    kfree(us2.Buffer);

                us2.Buffer = buf;
                us2.Length = s->destination_len;

                alloc = true;
            } else {
                unsigned int newlen = s->destination_len + us2.Length - s->source_len;
                WCHAR* buf = kmalloc(newlen, GFP_KERNEL); // FIXME - handle malloc failure

                memcpy(buf, s->destination, s->destination_len);
                memcpy(&buf[s->destination_len / sizeof(WCHAR)],
                       &us2.Buffer[s->source_len / sizeof(WCHAR)], us2.Length - s->source_len);

                if (alloc)
                    kfree(us2.Buffer);

                us2.Buffer = buf;
                us2.Length = newlen;

                alloc = true;
            }

            found = true;
            break;
        }

        if (!found)
            break;

        count++;

        if (count == 20) { // don't loop too many times
            read_unlock(&symlink_lock);
            kfree(us2.Buffer);
            *done_alloc = false;
            return STATUS_INVALID_PARAMETER;
        }
    }

    read_unlock(&symlink_lock);

    *done_alloc = alloc;

    if (alloc) {
        us->Buffer = us2.Buffer;
        us->Length = us2.Length;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                            ULONG OpenOptions) {
    NTSTATUS Status;
    UNICODE_STRING us;
    uint32_t offset;
    struct list_head* le;
    bool us_alloc;

    static const WCHAR prefix[] = L"\\Registry\\";

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES))
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        printk(KERN_ALERT "NtOpenKeyEx: FIXME - support RootDirectory\n"); // FIXME
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

    while (us.Length >= sizeof(WCHAR) && us.Buffer[(us.Length / sizeof(WCHAR)) - 1] == '\\') {
        us.Length -= sizeof(WCHAR);
    }

    Status = resolve_symlinks(&us, &us_alloc);
    if (!NT_SUCCESS(Status))
        return Status;

    down_read(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        if (us.Length < h->path.Length) {
            le = le->next;
            continue;
        }

        if (us.Buffer[h->path.Length / sizeof(WCHAR)] != 0 && us.Buffer[h->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        if (!wcsnicmp(us.Buffer, h->path.Buffer, h->path.Length / sizeof(WCHAR))) {
            key_object* k;
            bool is_volatile, parent_is_volatile;

            us.Buffer += h->path.Length / sizeof(WCHAR);
            us.Length -= h->path.Length;

            while (us.Length >= sizeof(WCHAR) && us.Buffer[0] == '\\') {
                us.Buffer++;
                us.Length -= sizeof(WCHAR);
            }

            down_read(&h->sem);

            Status = open_key_in_hive(h, &us, &offset, false, &is_volatile, &parent_is_volatile);
            if (!NT_SUCCESS(Status)) {
                up_read(&h->sem);
                up_read(&hive_list_sem);

                if (us_alloc)
                    kfree(us.Buffer);

                return Status;
            }

            up_read(&h->sem);

            // FIXME - do SeAccessCheck
            // FIXME - store access mask in handle

            // create key object and return handle

            k = kmalloc(sizeof(key_object), GFP_KERNEL);
            if (!k) {
                up_read(&hive_list_sem);

                if (us_alloc)
                    kfree(us.Buffer);

                return STATUS_INSUFFICIENT_RESOURCES;
            }

            k->header.refcount = 1;
            k->header.type = muwine_object_key;
            k->header.close = key_object_close;
            k->h = h;
            __sync_add_and_fetch(&h->refcount, 1);
            k->offset = offset;
            k->is_volatile = is_volatile;
            k->parent_is_volatile = parent_is_volatile;

            up_read(&hive_list_sem);

            Status = muwine_add_handle(&k->header, KeyHandle);

            if (!NT_SUCCESS(Status))
                kfree(k);

            if (us_alloc)
                kfree(us.Buffer);

            return Status;
        }

        le = le->next;
    }

    up_read(&hive_list_sem);

    if (us_alloc)
        kfree(us.Buffer);

    return STATUS_OBJECT_PATH_INVALID;
}

NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;

    if (!ObjectAttributes || !KeyHandle)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_INVALID_PARAMETER;

    Status = NtOpenKeyEx(&h, DesiredAccess, &oa, 0);

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

NTSTATUS user_NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                          ULONG OpenOptions) {
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;

    if (!ObjectAttributes || !KeyHandle)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_INVALID_PARAMETER;

    Status = NtOpenKeyEx(&h, DesiredAccess, &oa, OpenOptions);

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

static NTSTATUS get_key_item_by_index(hive* h, CM_KEY_NODE* kn, unsigned int index, uint32_t* cell_offset, bool is_volatile) {
    int32_t size;
    uint16_t sig;

    // FIXME - check not out of bounds

    if (is_volatile) {
        size = -*(int32_t*)((uint8_t*)h->volatile_bins + kn->VolatileSubKeyList);
        sig = *(uint16_t*)((uint8_t*)h->volatile_bins + kn->VolatileSubKeyList + sizeof(int32_t));
    } else {
        size = -*(int32_t*)((uint8_t*)h->bins + kn->SubKeyList);
        sig = *(uint16_t*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));
    }

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh;

        if (is_volatile)
            lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->volatile_bins + kn->VolatileSubKeyList + sizeof(int32_t));
        else
            lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (lh->Count * sizeof(CM_KEY_INDEX)))
            return STATUS_REGISTRY_CORRUPT;

        if (index >= lh->Count)
            return STATUS_REGISTRY_CORRUPT;

        *cell_offset = lh->List[index].Cell;

        return STATUS_SUCCESS;
    } else if (sig == CM_KEY_INDEX_ROOT) {
        unsigned int i;
        CM_KEY_INDEX* ri;

        if (is_volatile)
            ri = (CM_KEY_INDEX*)((uint8_t*)h->volatile_bins + kn->VolatileSubKeyList + sizeof(int32_t));
        else
            ri = (CM_KEY_INDEX*)((uint8_t*)h->bins + kn->SubKeyList + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_INDEX, List[0]) + (ri->Count * sizeof(uint32_t)))
            return STATUS_REGISTRY_CORRUPT;

        for (i = 0; i < ri->Count; i++) {
            CM_KEY_FAST_INDEX* lh;

            if (is_volatile) {
                lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->volatile_bins + ri->List[i] + sizeof(int32_t));
                size = -*(int32_t*)((uint8_t*)h->volatile_bins + ri->List[i]);
            } else {
                lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + ri->List[i] + sizeof(int32_t));
                size = -*(int32_t*)((uint8_t*)h->bins + ri->List[i]);
            }

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
    uint32_t cell_offset;
    void* bins;
    void* bins2;
    bool is_volatile;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_ENUMERATE_SUB_KEYS

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    if (Index >= kn->SubKeyCount + kn->VolatileSubKeyCount) {
        up_read(&key->h->sem);
        return STATUS_NO_MORE_ENTRIES;
    }

    if (Index >= kn->SubKeyCount) {
        Status = get_key_item_by_index(key->h, kn, Index - kn->SubKeyCount, &cell_offset, true);
        if (!NT_SUCCESS(Status)) {
            printk(KERN_INFO "get_key_item_by_index returned %08x\n", Status);
            up_read(&key->h->sem);
            return Status;
        }

        is_volatile = true;
    } else {
        Status = get_key_item_by_index(key->h, kn, Index, &cell_offset, false);
        if (!NT_SUCCESS(Status)) {
            printk(KERN_INFO "get_key_item_by_index returned %08x\n", Status);
            up_read(&key->h->sem);
            return Status;
        }

        is_volatile = false;
    }

    bins2 = is_volatile ? key->h->volatile_bins : key->h->bins;

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins2 + cell_offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn2 = (CM_KEY_NODE*)((uint8_t*)bins2 + cell_offset + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength) {
        up_read(&key->h->sem);
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
                up_read(&key->h->sem);
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
            up_read(&key->h->sem);
            return STATUS_INVALID_PARAMETER;
    }

    up_read(&key->h->sem);

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
    void* bins;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_QUERY_VALUE

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins: key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    if (Index >= kn->ValuesCount) {
        up_read(&key->h->sem);
        return STATUS_NO_MORE_ENTRIES;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + values_list[Index]);
    vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[Index] + sizeof(int32_t));

    if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    up_read(&key->h->sem);

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
    void* bins;

    if (!ValueName)
        return STATUS_INVALID_PARAMETER;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask of handle for KEY_QUERY_VALUE

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        up_read(&key->h->sem);
        return STATUS_REGISTRY_CORRUPT;
    }

    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

    for (i = 0; i < kn->ValuesCount; i++) {
        CM_KEY_VALUE* vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[i] + sizeof(int32_t));

        // FIXME - check not out of bounds

        size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

        if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
            up_read(&key->h->sem);
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
                    up_read(&key->h->sem);
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
                    up_read(&key->h->sem);
                    return Status;
                }
            }
        }
    }

    up_read(&key->h->sem);

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

static NTSTATUS allocate_cell(hive* h, uint32_t size, uint32_t* offset, bool alloc_volatile) {
    struct list_head* le;
    struct list_head* head;
    hive_hole* found_hh;
    void* new_data;

    size += sizeof(int32_t);

    if (size & 7)
        size += 8 - (size & 7);

    // FIXME - work with very large cells

    if (size > BIN_SIZE - sizeof(HBIN))
        return STATUS_INVALID_PARAMETER;

    // search in hive holes for exact match

    if (alloc_volatile)
        head = &h->volatile_holes;
    else
        head = &h->holes;

    le = head->next;

    while (le != head) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        if (hh->size == size) {
            if (alloc_volatile)
                *(int32_t*)(h->volatile_bins + hh->offset) = -size;
            else
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
    le = head->next;

    while (le != head) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        if (hh->size > size && (!found_hh || hh->size < found_hh->size))
            found_hh = hh;

        le = le->next;
    }

    if (found_hh) {
        if (alloc_volatile)
            *(int32_t*)(h->volatile_bins + found_hh->offset) = -size;
        else
            *(int32_t*)(h->bins + found_hh->offset) = -size;

        *offset = found_hh->offset;

        found_hh->offset += size;
        found_hh->size -= size;

        if (alloc_volatile)
            *(int32_t*)(h->volatile_bins + found_hh->offset) = found_hh->size;
        else
            *(int32_t*)(h->bins + found_hh->offset) = found_hh->size;

        return STATUS_SUCCESS;
    }

    // if can't find anything, add new bin and extend file

    if (alloc_volatile)
        new_data = vmalloc(h->volatile_size + BIN_SIZE);
    else
        new_data = vmalloc(h->size + BIN_SIZE);

    if (!new_data)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (!alloc_volatile) { // non-volatile
        HBIN* hbin;

        memcpy(new_data, h->data, h->size);
        vfree(h->data);
        h->data = new_data;
        h->bins = (uint8_t*)h->data + BIN_SIZE;

        hbin = (HBIN*)((uint8_t*)h->bins + h->size);
        hbin->Signature = HV_HBIN_SIGNATURE;
        hbin->FileOffset = (uint8_t*)hbin - (uint8_t*)h->bins;
        hbin->Size = BIN_SIZE;
        hbin->Reserved[0] = 0;
        hbin->Reserved[1] = 0;
        hbin->TimeStamp.QuadPart = 0; // FIXME
        hbin->Spare = 0;

        *offset = h->size + sizeof(HBIN);
        h->size += BIN_SIZE;

        if (size < BIN_SIZE - sizeof(HBIN)) { // add hole entry for rest
            hive_hole* hh2 = kmalloc(sizeof(hive_hole), GFP_KERNEL);

            // FIXME - handle malloc failure

            hh2->offset = *offset + size;
            hh2->size = BIN_SIZE - sizeof(HBIN) - size;

            *(int32_t*)(h->bins + hh2->offset) = hh2->size;

            list_add_tail(&hh2->list, &h->holes);
        }

        *(int32_t*)(h->bins + *offset) = -size;
    } else {
        if (h->volatile_bins) {
            memcpy(new_data, h->volatile_bins, h->volatile_size);
            vfree(h->volatile_bins);
        }

        h->volatile_bins = new_data;

        *offset = h->volatile_size;
        h->volatile_size += BIN_SIZE;

        if (size < BIN_SIZE) { // add hole entry for rest
            hive_hole* hh2 = kmalloc(sizeof(hive_hole), GFP_KERNEL);

            // FIXME - handle malloc failure

            hh2->offset = *offset + size;
            hh2->size = BIN_SIZE - size;

            *(int32_t*)(h->volatile_bins + hh2->offset) = hh2->size;

            list_add_tail(&hh2->list, &h->volatile_holes);
        }

        *(int32_t*)(h->volatile_bins + *offset) = -size;
    }

    return STATUS_SUCCESS;
}

static void free_cell(hive* h, uint32_t offset, bool is_volatile) {
    struct list_head* le;
    struct list_head* head = is_volatile ? &h->volatile_holes : &h->holes;
    bool added = false;

    // add entry to hive holes

    le = head->next;

    while (le != head) {
        hive_hole* hh = list_entry(le, hive_hole, list);

        // FIXME - if follows on from previous, merge entries
        // FIXME - if follows on to next, merge entries

        if (hh->offset > offset) {
            hive_hole* hh2 = kmalloc(sizeof(hive_hole), GFP_KERNEL);

            // FIXME - handle malloc failure

            hh2->offset = offset;

            if (is_volatile)
                hh2->size = -*(int32_t*)(h->volatile_bins + offset);
            else
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

        if (is_volatile)
            hh2->size = -*(int32_t*)(h->volatile_bins + offset);
        else
            hh2->size = -*(int32_t*)(h->bins + offset);

        list_add_tail(&hh2->list, head);
    }

    // change sign of cell size, to indicate now free

    if (is_volatile)
        *(int32_t*)(h->volatile_bins + offset) = -*(int32_t*)(h->volatile_bins + offset);
    else
        *(int32_t*)(h->bins + offset) = -*(int32_t*)(h->bins + offset);
}

static void update_symlink_cache(hive* h, uint32_t offset, bool is_volatile, WCHAR* value, ULONG value_length) {
    CM_KEY_NODE* kn;
    hive* h2;
    unsigned int len = 0, depth = 0, level;
    WCHAR* name;
    WCHAR* ptr;
    struct list_head* le;
    symlink* s;

    if (value_length != 0) {
        static const WCHAR prefix[] = L"\\Registry\\";

        if (value_length >= sizeof(prefix) - sizeof(WCHAR) && !wcsnicmp(value, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1)) {
            value += (sizeof(prefix) / sizeof(WCHAR)) - 1;
            value_length -= sizeof(prefix) - sizeof(WCHAR);
        } else {
            value = NULL;
            value_length = 0;
        }
    }

    // construct path to key
    h2 = h;

    if (is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h2->volatile_bins + offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h2->bins + offset + sizeof(int32_t));

    do {
        if (kn->Flags & KEY_HIVE_ENTRY) {
            if (h2->depth == 0)
                break;

            if (h2->parent_key_volatile)
                kn = (CM_KEY_NODE*)((uint8_t*)h2->parent_hive->volatile_bins + h2->parent_key_offset + sizeof(int32_t));
            else
                kn = (CM_KEY_NODE*)((uint8_t*)h2->parent_hive->bins + h2->parent_key_offset + sizeof(int32_t));

            h2 = h2->parent_hive;
        }

        if (kn->Flags & KEY_COMP_NAME)
            len += kn->NameLength * sizeof(WCHAR);
        else
            len += kn->NameLength;

        len += sizeof(WCHAR);
        depth++;

        if (kn->Parent & 0x80000000)
            kn = (CM_KEY_NODE*)((uint8_t*)h2->volatile_bins + (kn->Parent & 0x7fffffff) + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h2->bins + kn->Parent + sizeof(int32_t));
    } while (true);

    if (len == 0)
        return;

    len -= sizeof(WCHAR); // rm initial backslash

    name = kmalloc(len, GFP_KERNEL);
    // FIXME - check for malloc failure

    ptr = &name[len / sizeof(WCHAR)];

    h2 = h;

    if (is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h2->volatile_bins + offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h2->bins + offset + sizeof(int32_t));

    level = 0;

    do {
        if (kn->Flags & KEY_HIVE_ENTRY) {
            if (h2->depth == 0)
                break;

            if (h2->parent_key_volatile)
                kn = (CM_KEY_NODE*)((uint8_t*)h2->parent_hive->volatile_bins + h2->parent_key_offset + sizeof(int32_t));
            else
                kn = (CM_KEY_NODE*)((uint8_t*)h2->parent_hive->bins + h2->parent_key_offset + sizeof(int32_t));

            h2 = h2->parent_hive;
        }

        if (kn->Flags & KEY_COMP_NAME) {
            unsigned int i;

            ptr -= kn->NameLength;

            for (i = 0; i < kn->NameLength; i++) {
                ptr[i] = ((char*)kn->Name)[i];
            }
        } else {
            ptr -= kn->NameLength / sizeof(WCHAR);
            memcpy(ptr, kn->Name, kn->NameLength);
        }

        if (level != depth - 1){
            ptr--;
            *ptr = '\\';
        }

        if (kn->Parent & 0x80000000)
            kn = (CM_KEY_NODE*)((uint8_t*)h2->volatile_bins + (kn->Parent & 0x7fffffff) + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h2->bins + kn->Parent + sizeof(int32_t));

        level++;
    } while (true);

    // check if already exists

    write_lock(&symlink_lock);

    le = symlink_list.next;
    while (le != &symlink_list) {
        symlink* s = list_entry(le, symlink, list);

        if (s->depth == depth && s->source_len == len && !wcsnicmp(s->source, name, len / sizeof(WCHAR))) {
            kfree(name);

            if (value_length == 0) {
                list_del(&s->list);
                write_unlock(&symlink_lock);
                return;
            }

            kfree(s->destination);

            s->destination = kmalloc(value_length, GFP_KERNEL);
            // FIXME - handle malloc failure

            memcpy(s->destination, value, value_length);

            s->destination_len = value_length;
            write_unlock(&symlink_lock);

            return;
        } else if (s->depth < depth)
            break;

        le = le->next;
    }

    if (value_length == 0) {
        write_unlock(&symlink_lock);
        kfree(name);
        return;
    }

    // otherwise, add new

    s = kmalloc(sizeof(symlink), GFP_KERNEL); // FIXME - handle malloc failure

    s->source = name;
    s->source_len = len;

    s->destination = kmalloc(value_length, GFP_KERNEL); // FIXME - handle malloc failure
    memcpy(s->destination, value, value_length);
    s->destination_len = value_length;
    s->depth = depth;

    // insert into symlink list, reverse-ordered by depth

    le = symlink_list.next;
    while (le != &symlink_list) {
        symlink* s2 = list_entry(le, symlink, list);

        if (s2->depth < s->depth) {
            list_add(&s->list, le->prev);
            write_unlock(&symlink_lock);
            return;
        }

        le = le->next;
    }

    list_add_tail(&s->list, &symlink_list);

    write_unlock(&symlink_lock);
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
    void* bins;

    // FIXME - should we be rejecting short REG_DWORDs etc. here?

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check for KEY_SET_VALUE in access mask

    down_write(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (kn->ValuesCount > 0) {
        unsigned int i;

        size = -*(int32_t*)((uint8_t*)bins + kn->Values);

        if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
        }

        values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

        for (i = 0; i < kn->ValuesCount; i++) {
            bool found = false;

            vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[i] + sizeof(int32_t));

            // FIXME - check not out of bounds

            size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

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

                        Status = allocate_cell(key->h, DataSize, &cell, key->is_volatile);
                        if (!NT_SUCCESS(Status))
                            goto end;

                        memcpy(bins + cell + sizeof(int32_t), Data, DataSize);

                        vk->Data = cell;
                        vk->DataLength = DataSize;
                        vk->Type = Type;
                    }
                } else {
                    if (DataSize <= sizeof(uint32_t)) { // if wasn't resident but will be, free data cell and write into vk
                        free_cell(key->h, vk->Data, key->is_volatile);

                        memcpy(&vk->Data, Data, DataSize);
                        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
                        vk->Type = Type;
                    } else {
                        int32_t old_cell_size = -*(int32_t*)((uint8_t*)bins + vk->Data);
                        int32_t new_cell_size;

                        new_cell_size = sizeof(int32_t) + DataSize;

                        if (new_cell_size & 7)
                            new_cell_size += 8 - (new_cell_size & 7);

                        if (old_cell_size == new_cell_size) { // if wasn't resident, still won't be, and cell similar size, write over existing data
                            memcpy(bins + vk->Data + sizeof(int32_t), Data, DataSize);
                            vk->DataLength = DataSize;
                            vk->Type = Type;
                        } else { // if wasn't resident, still won't be, and cell different size, free data cell and allocate new one
                            uint32_t cell;

                            Status = allocate_cell(key->h, DataSize, &cell, key->is_volatile);
                            if (!NT_SUCCESS(Status))
                                goto end;

                            free_cell(key->h, vk->Data, key->is_volatile);

                            vk->Data = cell;
                            vk->DataLength = DataSize;
                            vk->Type = Type;

                            memcpy(bins + vk->Data + sizeof(int32_t), Data, DataSize);
                        }
                    }
                }

                if (kn->Flags & KEY_SYM_LINK && ValueName->Length == sizeof(symlinkval) - sizeof(WCHAR) &&
                    !wcsnicmp(ValueName->Buffer, symlinkval, (sizeof(symlinkval) / sizeof(WCHAR)) - 1)) {
                    if (Type == REG_LINK)
                        update_symlink_cache(key->h, key->offset, key->is_volatile, Data, DataSize);
                    else
                        update_symlink_cache(key->h, key->offset, key->is_volatile, NULL, 0);
                }

                Status = STATUS_SUCCESS;
                goto end;
            }
        }
    }

    // new entry

    // allocate cell for vk

    Status = allocate_cell(key->h, offsetof(CM_KEY_VALUE, Name[0]) + (ValueName ? ValueName->Length : 0), &vk_offset, key->is_volatile);
    if (!NT_SUCCESS(Status))
        goto end;

    vk = (CM_KEY_VALUE*)(bins + vk_offset + sizeof(int32_t));
    vk->Signature = CM_KEY_VALUE_SIGNATURE;
    vk->NameLength = ValueName ? ValueName->Length : 0;
    vk->Type = Type;
    vk->Flags = 0;
    vk->Spare = 0;

    if (vk->NameLength > 0)
        memcpy(vk->Name, ValueName->Buffer, vk->NameLength);

    if (DataSize > sizeof(uint32_t)) {
        vk->DataLength = DataSize;

        Status = allocate_cell(key->h, DataSize, &vk->Data, key->is_volatile);
        if (!NT_SUCCESS(Status)) {
            free_cell(key->h, vk_offset, key->is_volatile);
            goto end;
        }

        memcpy(bins + vk->Data + sizeof(int32_t), Data, DataSize);
    } else {
        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
        memcpy(&vk->Data, Data, DataSize);
    }

    if (kn->Flags & KEY_SYM_LINK && ValueName->Length == sizeof(symlinkval) - sizeof(WCHAR) &&
        !wcsnicmp(ValueName->Buffer, symlinkval, (sizeof(symlinkval) / sizeof(WCHAR)) - 1)) {
        if (Type == REG_LINK)
            update_symlink_cache(key->h, key->offset, key->is_volatile, Data, DataSize);
        else
            update_symlink_cache(key->h, key->offset, key->is_volatile, NULL, 0);
    }

    if (kn->ValuesCount > 0) {
        int32_t old_size = -*(int32_t*)((uint8_t*)bins + kn->Values);
        int32_t new_size = ((kn->ValuesCount + 1) * sizeof(uint32_t)) + sizeof(int32_t);

        if (new_size & 7)
            new_size += 8 - (new_size & 7);

        if (old_size == new_size) { // if enough space in values list, add to the end
            values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

            values_list[kn->ValuesCount] = vk_offset;
            kn->ValuesCount++;

            Status = STATUS_SUCCESS;

            goto end;
        }
    }

    Status = allocate_cell(key->h, sizeof(uint32_t) * (kn->ValuesCount + 1), &values_list_offset, key->is_volatile);
    if (!NT_SUCCESS(Status)) {
        if (!(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) && vk->DataLength != 0)
            free_cell(key->h, vk->Data, key->is_volatile);

        free_cell(key->h, vk_offset, key->is_volatile);
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)bins + values_list_offset + sizeof(int32_t));

    if (kn->ValuesCount > 0) {
        uint32_t* old_values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

        memcpy(values_list, old_values_list, kn->ValuesCount * sizeof(uint32_t));

        free_cell(key->h, kn->Values, key->is_volatile);
    }

    values_list[kn->ValuesCount] = vk_offset;

    kn->Values = values_list_offset;
    kn->ValuesCount++;

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status) && !key->is_volatile)
        key->h->dirty = true;

    up_write(&key->h->sem);

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
    void* bins;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check for KEY_SET_VALUE in access mask

    down_write(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (kn->ValuesCount == 0) {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto end;
    }

    size = -*(int32_t*)((uint8_t*)bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

    for (i = 0; i < kn->ValuesCount; i++) {
        bool found = false;
        CM_KEY_VALUE* vk;

        vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[i] + sizeof(int32_t));

        // FIXME - check not out of bounds

        size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

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
                free_cell(key->h, kn->Values, key->is_volatile);
                kn->Values = 0;
            } else {
                int32_t old_size = -*(int32_t*)((uint8_t*)bins + kn->Values);
                int32_t new_size = ((kn->ValuesCount - 1) * sizeof(uint32_t)) + sizeof(int32_t);

                if (new_size & 7)
                    new_size += 8 - (new_size & 7);

                if (old_size == new_size) // if values list right size, update
                    memcpy(&values_list[i], &values_list[i+1], (kn->ValuesCount - i - 1) * sizeof(uint32_t));
                else {
                    uint32_t values_list_offset;
                    uint32_t* new_values_list;

                    Status = allocate_cell(key->h, sizeof(uint32_t) * (kn->ValuesCount - 1), &values_list_offset, key->is_volatile);
                    if (!NT_SUCCESS(Status))
                        goto end;

                    new_values_list = (uint32_t*)((uint8_t*)bins + values_list_offset + sizeof(int32_t));

                    memcpy(new_values_list, values_list, i * sizeof(uint32_t));
                    memcpy(&new_values_list[i], &values_list[i+1], (kn->ValuesCount - i - 1) * sizeof(uint32_t));

                    kn->Values = values_list_offset;
                }
            }

            if (vk->DataLength != 0 && !(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE)) // free data cell, if not resident
                free_cell(key->h, vk->Data, key->is_volatile);

            if (kn->Flags & KEY_SYM_LINK && vk->Type == REG_LINK && ValueName->Length == sizeof(symlinkval) - sizeof(WCHAR) &&
                !wcsnicmp(ValueName->Buffer, symlinkval, (sizeof(symlinkval) / sizeof(WCHAR)) - 1)) {
                update_symlink_cache(key->h, key->offset, key->is_volatile, NULL, 0);
            }

            free_cell(key->h, vk_offset, key->is_volatile);

            kn->ValuesCount--;

            Status = STATUS_SUCCESS;
            goto end;
        }
    }

    Status = STATUS_OBJECT_NAME_NOT_FOUND;

end:
    if (NT_SUCCESS(Status) && !key->is_volatile)
        key->h->dirty = true;

    up_write(&key->h->sem);

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
                                UNICODE_STRING* us, bool is_volatile) {
    NTSTATUS Status;
    CM_KEY_FAST_INDEX* lh;
    unsigned int i;
    uint32_t pos;
    bool found = false;
    void* bins = is_volatile ? h->volatile_bins : h->bins;

    for (i = 0; i < old_lh->Count; i++) {
        int32_t size = -*(int32_t*)(bins + old_lh->List[i].Cell);
        uint16_t sig;
        CM_KEY_NODE* kn;

        // FIXME - check not out of bounds

        if (size < sizeof(int32_t) + sizeof(uint16_t))
            return STATUS_REGISTRY_CORRUPT;

        sig = *(uint16_t*)(bins + old_lh->List[i].Cell + sizeof(int32_t));

        if (sig != CM_KEY_NODE_SIGNATURE)
            return STATUS_REGISTRY_CORRUPT;

        kn = (CM_KEY_NODE*)(bins + old_lh->List[i].Cell + sizeof(int32_t));

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

    Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * (old_lh->Count + 1)),
                           offset, is_volatile);
    if (!NT_SUCCESS(Status))
        return Status;

    lh = (CM_KEY_FAST_INDEX*)(bins + *offset + sizeof(int32_t));

    lh->Signature = CM_KEY_HASH_LEAF;
    lh->Count = old_lh->Count + 1;

    memcpy(lh->List, old_lh->List, pos * sizeof(CM_INDEX));

    lh->List[pos].Cell = cell;
    lh->List[pos].HashKey = hash;

    memcpy(&lh->List[pos+1], &old_lh->List[pos], (old_lh->Count - pos) * sizeof(CM_INDEX));

    return STATUS_SUCCESS;
}

static NTSTATUS create_key_in_hive(hive* h, UNICODE_STRING* us, PHANDLE KeyHandle, ULONG CreateOptions, PULONG Disposition) {
    NTSTATUS Status;
    key_object* k;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint32_t hash;
    bool is_volatile = false;
    uint32_t offset, subkey_offset;
    bool parent_is_volatile;
    uint32_t* subkey_count;
    uint32_t* subkey_list;

    // get offset for kn of parent

    Status = open_key_in_hive(h, us, &offset, true, &parent_is_volatile, NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    if (us->Length < sizeof(WCHAR))
        return STATUS_OBJECT_NAME_INVALID;

    is_volatile = parent_is_volatile;

    // FIXME - make sure SD allows us to create subkeys

    // if already exists, set Disposition to REG_OPENED_EXISTING_KEY, create handle, and return

    Status = find_subkey(h, offset, us, &subkey_offset, &is_volatile);
    if (NT_SUCCESS(Status)) {
        k = kmalloc(sizeof(key_object), GFP_KERNEL);
        if (!k)
            return STATUS_INSUFFICIENT_RESOURCES;

        k->header.refcount = 1;
        k->header.type = muwine_object_key;
        k->header.close = key_object_close;
        k->h = h;
        __sync_add_and_fetch(&h->refcount, 1);
        k->offset = subkey_offset;
        k->is_volatile = is_volatile;
        k->parent_is_volatile = parent_is_volatile;

        Status = muwine_add_handle(&k->header, KeyHandle);

        if (!NT_SUCCESS(Status))
            kfree(k);

        if (Disposition)
            *Disposition = REG_OPENED_EXISTING_KEY;

        return Status;
    } else if (Status != STATUS_OBJECT_PATH_NOT_FOUND)
        return Status;

    if (CreateOptions & REG_OPTION_VOLATILE)
        is_volatile = true;

    // don't allow non-volatile keys to be created under volatile parent

    if (!is_volatile && parent_is_volatile)
        return STATUS_INVALID_PARAMETER;

    // allocate space for new kn

    Status = allocate_cell(h, offsetof(CM_KEY_NODE, Name) + us->Length, &subkey_offset, is_volatile);
    if (!NT_SUCCESS(Status))
        return Status;

    // FIXME - compute SD and allocate or find cell for it

    if (is_volatile)
        kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + subkey_offset + sizeof(int32_t));
    else
        kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + subkey_offset + sizeof(int32_t));

    kn2->Signature = CM_KEY_NODE_SIGNATURE;
    kn2->Flags = 0;
    kn2->LastWriteTime = 0; // FIXME
    kn2->Spare = 0;
    kn2->Parent = offset;

    if (parent_is_volatile)
        kn2->Parent |= 0x80000000;

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
    kn2->NameLength = us->Length;
    kn2->ClassLength = 0; // FIXME
    memcpy(kn2->Name, us->Buffer, us->Length);

    if (CreateOptions & REG_OPTION_CREATE_LINK)
        kn2->Flags |= KEY_SYM_LINK;

    // open kn of parent (checking already done in open_key_in_hive)

    if (parent_is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    hash = calc_subkey_hash(us);

    // add handle here, to make things easier if we fail later on

    k = kmalloc(sizeof(key_object), GFP_KERNEL);
    if (!k)
        return STATUS_INSUFFICIENT_RESOURCES;

    k->header.refcount = 1;
    k->header.type = muwine_object_key;
    k->header.close = key_object_close;
    k->h = h;
    __sync_add_and_fetch(&h->refcount, 1);
    k->is_volatile = is_volatile;
    k->parent_is_volatile = parent_is_volatile;

    Status = muwine_add_handle(&k->header, KeyHandle);

    if (!NT_SUCCESS(Status)) {
        kfree(k);
        return Status;
    }

    if (is_volatile) {
        subkey_count = &kn->VolatileSubKeyCount;
        subkey_list = &kn->VolatileSubKeyList;
    } else {
        subkey_count = &kn->SubKeyCount;
        subkey_list = &kn->SubKeyList;
    }

    if (*subkey_count == 0) {
        CM_KEY_FAST_INDEX* lh;
        uint32_t lh_offset;

        Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + sizeof(CM_INDEX), &lh_offset, is_volatile);
        if (!NT_SUCCESS(Status)) {
            free_cell(h, subkey_offset, is_volatile);
            NtClose(*KeyHandle);
            return Status;
        }

        if (is_volatile)
            lh = (CM_KEY_FAST_INDEX*)(h->volatile_bins + lh_offset + sizeof(int32_t));
        else
            lh = (CM_KEY_FAST_INDEX*)(h->bins + lh_offset + sizeof(int32_t));

        lh->Signature = CM_KEY_HASH_LEAF;
        lh->Count = 1;
        lh->List[0].Cell = subkey_offset;
        lh->List[0].HashKey = hash;

        if (us->Length > kn->MaxNameLen)
            kn->MaxNameLen = us->Length;

        *subkey_count = 1;
        *subkey_list = lh_offset;

        k->offset = subkey_offset;
    } else {
        uint16_t sig;
        int32_t size;

        if (is_volatile)
            size = -*(int32_t*)(h->volatile_bins + *subkey_list);
        else
            size = -*(int32_t*)(h->bins + *subkey_list);

        if (size < sizeof(int32_t) + sizeof(uint16_t)) {
            free_cell(h, subkey_offset, is_volatile);
            NtClose(*KeyHandle);
            return STATUS_REGISTRY_CORRUPT;
        }

        if (is_volatile)
            sig = *(uint16_t*)(h->volatile_bins + *subkey_list + sizeof(int32_t));
        else
            sig = *(uint16_t*)(h->bins + *subkey_list + sizeof(int32_t));

        // FIXME - dealing with existing ri rather than lh
        // FIXME - creating new ri if lh gets too large

        k->offset = subkey_offset;

        if (sig == CM_KEY_HASH_LEAF) {
            CM_KEY_FAST_INDEX* old_lh;
            uint32_t lh_offset;

            if (is_volatile)
                old_lh = (CM_KEY_FAST_INDEX*)(h->volatile_bins + *subkey_list + sizeof(int32_t));
            else
                old_lh = (CM_KEY_FAST_INDEX*)(h->bins + *subkey_list + sizeof(int32_t));

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * old_lh->Count)) {
                free_cell(h, subkey_offset, is_volatile);
                NtClose(*KeyHandle);
                return STATUS_REGISTRY_CORRUPT;
            }

            Status = lh_copy_and_add(h, old_lh, &lh_offset, subkey_offset, hash, us, is_volatile);
            if (!NT_SUCCESS(Status)) {
                free_cell(h, subkey_offset, is_volatile);
                NtClose(*KeyHandle);
                return Status;
            }

            free_cell(h, *subkey_list, is_volatile);

            (*subkey_count)++;
            *subkey_list = lh_offset;

            if (us->Length > kn->MaxNameLen)
                kn->MaxNameLen = us->Length;
        } else {
            printk(KERN_ALERT "NtCreateKey: unhandled list type %x\n", sig);
            NtClose(*KeyHandle);
            return STATUS_NOT_IMPLEMENTED;
        }
    }

    if (Disposition)
        *Disposition = REG_CREATED_NEW_KEY;

    if (!is_volatile)
        k->h->dirty = true;

    return STATUS_SUCCESS;
}

static NTSTATUS NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                            PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    NTSTATUS Status;
    UNICODE_STRING us;
    bool us_alloc;
    struct list_head* le;

    static const WCHAR prefix[] = L"\\Registry\\";

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

    while (us.Length >= sizeof(WCHAR) && us.Buffer[(us.Length / sizeof(WCHAR)) - 1] == '\\') {
        us.Length -= sizeof(WCHAR);
    }

    Status = resolve_symlinks(&us, &us_alloc);
    if (!NT_SUCCESS(Status))
        return Status;

    down_read(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        if (us.Length <= h->path.Length) {
            le = le->next;
            continue;
        }

        if (h->depth != 0 && us.Buffer[h->path.Length / sizeof(WCHAR)] != 0 && us.Buffer[h->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        if (h->depth == 0 || !wcsnicmp(us.Buffer, h->path.Buffer, h->path.Length / sizeof(WCHAR))) {
            us.Buffer += h->path.Length / sizeof(WCHAR);
            us.Length -= h->path.Length;

            while (us.Length >= sizeof(WCHAR) && us.Buffer[0] == '\\') {
                us.Buffer++;
                us.Length -= sizeof(WCHAR);
            }

            down_write(&h->sem);

            Status = create_key_in_hive(h, &us, KeyHandle, CreateOptions, Disposition);

            up_write(&h->sem);
            up_read(&hive_list_sem);

            if (us_alloc)
                kfree(us.Buffer);

            return Status;
        }

        le = le->next;
    }

    up_read(&hive_list_sem);

    if (us_alloc)
        kfree(us.Buffer);

    return STATUS_OBJECT_PATH_NOT_FOUND;
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

static NTSTATUS lh_remove(hive* h, CM_KEY_FAST_INDEX* old_lh, uint32_t key, bool is_volatile, uint32_t* addr) {
    NTSTATUS Status;
    uint32_t offset;
    CM_KEY_FAST_INDEX* lh;
    unsigned int i;

    Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * (old_lh->Count - 1)),
                           &offset, is_volatile);
    if (!NT_SUCCESS(Status))
        return Status;

    if (is_volatile)
        lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
    else
        lh = (CM_KEY_FAST_INDEX*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    lh->Signature = CM_KEY_HASH_LEAF;
    lh->Count = old_lh->Count - 1;

    for (i = 0; i < old_lh->Count; i++) {
        if (old_lh->List[i].Cell == key) {
            memcpy(lh->List, old_lh->List, i * sizeof(CM_INDEX));
            memcpy(&lh->List[i], &old_lh->List[i + 1], old_lh->Count - i - 1);

            *addr = offset;
            return STATUS_SUCCESS;
        }
    }

    // key not found in list

    free_cell(h, offset, is_volatile);

    return STATUS_REGISTRY_CORRUPT;
}

NTSTATUS NtDeleteKey(HANDLE KeyHandle) {
    NTSTATUS Status;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint16_t sig;
    uint32_t* subkey_count;
    uint32_t* subkey_list;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    // FIXME - check access mask has DELETE permission

    down_write(&key->h->sem);

    if (key->is_volatile)
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + key->offset);
    else
        size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (key->is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + key->offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn->NameLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (kn->Flags & (KEY_HIVE_EXIT | KEY_HIVE_ENTRY | KEY_NO_DELETE)) {
        printk("kn->Flags = %x\n", kn->Flags);
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    if (kn->SubKeyCount != 0 || kn->VolatileSubKeyCount != 0) {
        printk("kn->SubKeyCount = %x, kn->VolatileSubKeyCount = %x\n", kn->SubKeyCount, kn->VolatileSubKeyCount);
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    // get parent kn

    if (key->parent_is_volatile)
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + (kn->Parent & 0x7fffffff));
    else
        size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Parent);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (key->parent_is_volatile)
        kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + (kn->Parent & 0x7fffffff) + sizeof(int32_t));
    else
        kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->bins + kn->Parent + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    // FIXME - get parent's subkey list (volatile or non-volatile)

    if (key->is_volatile) {
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + kn2->VolatileSubKeyList);
        subkey_count = &kn2->VolatileSubKeyCount;
        subkey_list = &kn2->VolatileSubKeyList;
    } else {
        size = -*(int32_t*)((uint8_t*)key->h->bins + kn2->SubKeyList);
        subkey_count = &kn2->SubKeyCount;
        subkey_list = &kn2->SubKeyList;
    }

    if (size < sizeof(int32_t) + sizeof(uint16_t)) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (key->is_volatile)
        sig = *(uint16_t*)((uint8_t*)key->h->volatile_bins + kn2->VolatileSubKeyList + sizeof(int32_t));
    else
        sig = *(uint16_t*)((uint8_t*)key->h->bins + kn2->SubKeyList + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* old_lh;

        if (key->is_volatile)
            old_lh = (CM_KEY_FAST_INDEX*)(key->h->volatile_bins + kn2->VolatileSubKeyList + sizeof(int32_t));
        else
            old_lh = (CM_KEY_FAST_INDEX*)(key->h->bins + kn2->SubKeyList + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) ||
            size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * old_lh->Count)) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        if (*subkey_count == 1) {
            free_cell(key->h, *subkey_list, key->is_volatile);

            *subkey_count = 0;
            *subkey_list = 0xffffffff;
        } else {
            uint32_t new_list;

            Status = lh_remove(key->h, old_lh, key->offset, key->is_volatile, &new_list);
            if (!NT_SUCCESS(Status))
                goto end;

            free_cell(key->h, *subkey_list, key->is_volatile);

            (*subkey_count)--;
            *subkey_list = new_list;
        }
    } else {
        // FIXME - handle ri
        printk(KERN_ALERT "NtDeleteKey: unhandled list type %x\n", sig);
        Status = STATUS_NOT_IMPLEMENTED;
        goto end;
    }

    if (kn->ValuesCount != 0) {
        // FIXME - check not out of bounds

        if (key->is_volatile)
            size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + kn->Values);
        else
            size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Values);

        if (size >= sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
            unsigned int i;
            uint32_t* values_list;

            if (key->is_volatile)
                values_list = (uint32_t*)((uint8_t*)key->h->volatile_bins + kn->Values + sizeof(int32_t));
            else
                values_list = (uint32_t*)((uint8_t*)key->h->bins + kn->Values + sizeof(int32_t));

            for (i = 0; i < kn->ValuesCount; i++) {
                CM_KEY_VALUE* vk;

                // FIXME - check not out of bounds

                if (key->is_volatile) {
                    size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + values_list[i]);
                    vk = (CM_KEY_VALUE*)((uint8_t*)key->h->volatile_bins + values_list[i] + sizeof(int32_t));
                } else {
                    size = -*(int32_t*)((uint8_t*)key->h->bins + values_list[i]);
                    vk = (CM_KEY_VALUE*)((uint8_t*)key->h->bins + values_list[i] + sizeof(int32_t));
                }

                if (vk->Signature == CM_KEY_VALUE_SIGNATURE && size >= sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) &&
                    sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
                    if (vk->DataLength != 0 && !(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE)) // free non-resident data cell
                        free_cell(key->h, vk->Data, key->is_volatile);

                    free_cell(key->h, values_list[i], key->is_volatile);
                }
            }

            free_cell(key->h, kn->Values, key->is_volatile);
        }
    }

    if (kn->Flags & KEY_SYM_LINK)
        update_symlink_cache(key->h, key->offset, key->is_volatile, NULL, 0);

    free_cell(key->h, key->offset, key->is_volatile);

    // FIXME - update MaxNameLen in parent if necessary

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status))
        key->h->dirty = true;

    up_write(&key->h->sem);

    return Status;
}

static NTSTATUS translate_path(UNICODE_STRING* us, char** path) {
    UNICODE_STRING us2;
    unsigned int i;
    char* s;

    static const WCHAR prefix[] = L"\\Device\\UnixRoot";

    // FIXME - translate symlinks (DosDevices etc.)

    if (us->Length <= sizeof(prefix) - sizeof(WCHAR))
        return STATUS_OBJECT_PATH_INVALID;

    if (wcsnicmp(us->Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1))
        return STATUS_OBJECT_PATH_INVALID;

    us2.Length = us2.MaximumLength = us->Length - sizeof(prefix) + sizeof(WCHAR);
    us2.Buffer = us->Buffer + (sizeof(prefix) / sizeof(WCHAR)) - 1;

    // FIXME - convert UTF-16 to UTF-8 properly here

    *path = s = kmalloc((us2.Length / sizeof(WCHAR)) + 1, GFP_KERNEL);

    for (i = 0; i < us2.Length / sizeof(WCHAR); i++) {
        if (us2.Buffer[i] == '\\')
            *s = '/';
        else
            *s = us2.Buffer[i];

        s++;
    }

    *s = 0;

    return STATUS_SUCCESS;
}

static unsigned int count_backslashes(UNICODE_STRING* us) {
    unsigned int i;
    unsigned int bs = 0;

    for (i = 0; i < us->Length; i++) {
        if (us->Buffer[i] == '\\')
            bs++;
    }

    return bs;
}

static NTSTATUS NtLoadKey(POBJECT_ATTRIBUTES DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName) {
    NTSTATUS Status;
    char* fs_path;
    struct file* f;
    loff_t pos;
    hive* h;
    UNICODE_STRING us;
    struct list_head* le;

    static const WCHAR prefix[] = L"\\Registry\\";

    // FIXME - make sure user has SE_RESTORE_PRIVILEGE

    if (!DestinationKeyName || !HiveFileName || !DestinationKeyName->ObjectName || !HiveFileName->ObjectName)
        return STATUS_INVALID_PARAMETER;

    // FIXME - support RootDirectory?

    // make sure DestinationKeyName begins with prefix

    if (DestinationKeyName->ObjectName->Length <= sizeof(prefix) - sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    if (wcsnicmp(DestinationKeyName->ObjectName->Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1))
        return STATUS_INVALID_PARAMETER;

    us.Buffer = DestinationKeyName->ObjectName->Buffer + (sizeof(prefix) / sizeof(WCHAR)) - 1;
    us.Length = DestinationKeyName->ObjectName->Length - sizeof(prefix) + sizeof(WCHAR);

    // translate HiveFileName to actual FS path

    Status = translate_path(HiveFileName->ObjectName, &fs_path);
    if (!NT_SUCCESS(Status))
        return Status;

    f = filp_open(fs_path, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_INFO "NtLoadKey: could not open %s\n", fs_path);
        kfree(fs_path);
        return muwine_error_to_ntstatus((int)(uintptr_t)f);
    }

    if (!f->f_inode) {
        printk(KERN_INFO "NtLoadKey: file did not have an inode\n");
        filp_close(f, NULL);
        kfree(fs_path);
        return STATUS_INTERNAL_ERROR;
    }

    h = kmalloc(sizeof(hive), GFP_KERNEL);
    if (!h) {
        filp_close(f, NULL);
        kfree(h);
        kfree(fs_path);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    h->path.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!h->path.Buffer) {
        filp_close(f, NULL);
        kfree(h);
        kfree(fs_path);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(h->path.Buffer, us.Buffer, us.Length);
    h->path.Length = h->path.MaximumLength = us.Length;

    h->depth = count_backslashes(&us) + 1;

    h->size = f->f_inode->i_size;
    h->file_mode = f->f_inode->i_mode;

    if (h->size == 0) {
        filp_close(f, NULL);
        kfree(h->path.Buffer);
        kfree(h);
        kfree(fs_path);
        return STATUS_REGISTRY_CORRUPT;
    }

    h->data = vmalloc(h->size);
    if (!h->data) {
        filp_close(f, NULL);
        kfree(h->path.Buffer);
        kfree(h);
        kfree(fs_path);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pos = 0;

    while (pos < h->size) {
        ssize_t read = kernel_read(f, (uint8_t*)h->data + pos, h->size - pos, &pos);

        if (read < 0) {
            printk(KERN_INFO "NtLoadKey: read returned %ld\n", read);
            filp_close(f, NULL);
            vfree(h->data);
            kfree(h->path.Buffer);
            kfree(h);
            kfree(fs_path);
            return muwine_error_to_ntstatus(read);
        }
    }

    filp_close(f, NULL);

    if (!hive_is_valid(h)) {
        vfree(h->data);
        kfree(h->path.Buffer);
        kfree(h);
        kfree(fs_path);
        return STATUS_REGISTRY_CORRUPT;
    }

    Status = init_hive(h);
    if (!NT_SUCCESS(Status)) {
        vfree(h->data);
        kfree(h->path.Buffer);
        kfree(h);
        kfree(fs_path);
        return Status;
    }

    down_write(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* parent_hive = list_entry(le, hive, list);

        if (h->path.Length <= parent_hive->path.Length) {
            le = le->next;
            continue;
        }

        if (parent_hive->depth != 0 && h->path.Buffer[parent_hive->path.Length / sizeof(WCHAR)] != 0 &&
            h->path.Buffer[parent_hive->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        if (parent_hive->depth == 0 || !wcsnicmp(h->path.Buffer, parent_hive->path.Buffer, parent_hive->path.Length / sizeof(WCHAR))) {
            bool found = false;
            uint32_t offset;
            bool is_volatile;
            CM_KEY_NODE* kn;

            down_read(&parent_hive->sem);

            Status = open_key_in_hive(parent_hive, &us, &offset, false, &is_volatile, NULL);
            if (!NT_SUCCESS(Status)) {
                up_read(&parent_hive->sem);
                up_write(&hive_list_sem);

                vfree(h->data);
                kfree(h->path.Buffer);
                kfree(h);
                kfree(fs_path);

                return Status;
            }

            if (is_volatile)
                kn = (CM_KEY_NODE*)((uint8_t*)parent_hive->volatile_bins + offset + sizeof(int32_t));
            else
                kn = (CM_KEY_NODE*)((uint8_t*)parent_hive->bins + offset + sizeof(int32_t));

            if (kn->Flags & KEY_HIVE_EXIT) { // something already mounted here
                up_read(&parent_hive->sem);
                up_write(&hive_list_sem);

                vfree(h->data);
                kfree(h->path.Buffer);
                kfree(h);
                kfree(fs_path);

                return STATUS_INVALID_PARAMETER;
            }

            kn->Flags |= KEY_HIVE_EXIT;

            h->parent_hive = parent_hive;
            h->parent_key_offset = offset;
            h->parent_key_volatile = is_volatile;

            parent_hive->refcount++;

            // store hives in reverse order by depth

            up_read(&parent_hive->sem);

            le = hive_list.next;
            while (le != &hive_list) {
                hive* h2 = list_entry(le, hive, list);

                if (h2->depth <= h->depth) {
                    list_add(&h->list, le->prev);
                    found = true;
                    break;
                }

                le = le->next;
            }

            if (!found)
                list_add_tail(&h->list, &hive_list);

            h->fs_path = fs_path;

            up_write(&hive_list_sem);

            printk(KERN_INFO "NtLoadKey: loaded hive at %s\n", fs_path);

            return STATUS_SUCCESS;
        }

        le = le->next;
    }

    up_write(&hive_list_sem);

    return STATUS_INTERNAL_ERROR;
}

NTSTATUS user_NtLoadKey(POBJECT_ATTRIBUTES DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa1, oa2;

    if (!DestinationKeyName || !HiveFileName)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa1, DestinationKeyName))
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa2, HiveFileName)) {
        if (oa1.ObjectName) {
            if (oa1.ObjectName->Buffer)
                kfree(oa1.ObjectName->Buffer);

            kfree(oa1.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtLoadKey(&oa1, &oa2);

    if (oa1.ObjectName) {
        if (oa1.ObjectName->Buffer)
            kfree(oa1.ObjectName->Buffer);

        kfree(oa1.ObjectName);
    }

    if (oa2.ObjectName) {
        if (oa2.ObjectName->Buffer)
            kfree(oa2.ObjectName->Buffer);

        kfree(oa2.ObjectName);
    }

    return Status;
}

static NTSTATUS NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    UNICODE_STRING us;
    struct list_head* le;

    static const WCHAR prefix[] = L"\\Registry\\";

    // FIXME - make sure user has SE_RESTORE_PRIVILEGE

    if (!DestinationKeyName || !DestinationKeyName->ObjectName)
        return STATUS_INVALID_PARAMETER;

    // FIXME - support RootDirectory?

    // make sure DestinationKeyName begins with prefix

    if (DestinationKeyName->ObjectName->Length <= sizeof(prefix) - sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    if (wcsnicmp(DestinationKeyName->ObjectName->Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1))
        return STATUS_INVALID_PARAMETER;

    us.Buffer = DestinationKeyName->ObjectName->Buffer + (sizeof(prefix) / sizeof(WCHAR)) - 1;
    us.Length = DestinationKeyName->ObjectName->Length - sizeof(prefix) + sizeof(WCHAR);

    down_write(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        if (us.Length != h->path.Length) {
            le = le->next;
            continue;
        }

        if (!wcsnicmp(us.Buffer, h->path.Buffer, h->path.Length / sizeof(WCHAR))) {
            CM_KEY_NODE* kn;

            if (h->refcount != 0) {
                up_write(&hive_list_sem);
                return STATUS_INVALID_PARAMETER;
            }

            if (!h->parent_hive) {
                up_write(&hive_list_sem);
                return STATUS_INVALID_PARAMETER;
            }

            if (h->parent_key_volatile)
                kn = (CM_KEY_NODE*)(h->parent_hive->volatile_bins + h->parent_key_offset + sizeof(int32_t));
            else
                kn = (CM_KEY_NODE*)(h->parent_hive->bins + h->parent_key_offset + sizeof(int32_t));

            if (!(kn->Flags & KEY_HIVE_EXIT)) {
                up_write(&hive_list_sem);
                return STATUS_INVALID_PARAMETER;
            }

            kn->Flags &= ~KEY_HIVE_EXIT;

            flush_hive(h);
            h->parent_hive->refcount--;

            printk(KERN_INFO "NtUnloadKey: unloaded hive at %s\n", h->fs_path);

            free_hive(h);

            up_write(&hive_list_sem);

            return STATUS_SUCCESS;
        }

        le = le->next;
    }

    up_write(&hive_list_sem);

    return STATUS_INTERNAL_ERROR;
}

NTSTATUS user_NtUnloadKey(POBJECT_ATTRIBUTES DestinationKeyName) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;

    if (!DestinationKeyName)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, DestinationKeyName))
        return STATUS_INVALID_PARAMETER;

    Status = NtUnloadKey(&oa);

    if (oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    return Status;
}

static int reg_flush_thread_func(void* data) {
    while (reg_thread_running) {
        struct list_head* le;
        set_current_state(TASK_INTERRUPTIBLE);

        schedule(); // yield

        down_read(&hive_list_sem);

        le = hive_list.next;
        while (le != &hive_list) {
            hive* h = list_entry(le, hive, list);

            flush_hive(h);

            le = le->next;
        }

        up_read(&hive_list_sem);

        if (reg_thread_running)
            mod_timer(&reg_flush_timer, jiffies + msecs_to_jiffies(1000 * REG_FLUSH_INTERVAL));
    }

    del_timer(&reg_flush_timer);

    set_current_state(TASK_RUNNING);

    do_exit(0);
}

static void reg_flush_timer_handler(struct timer_list* timer) {
    if (reg_flush_thread)
        wake_up_process(reg_flush_thread);
}

static NTSTATUS init_flush_thread(void) {
    reg_flush_thread = kthread_run(reg_flush_thread_func, NULL, "muwine_reg_flush");

    if (!reg_flush_thread) {
        printk(KERN_ALERT "muwine failed to create registry flush thread\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mod_timer(&reg_flush_timer, jiffies + msecs_to_jiffies(1000 * REG_FLUSH_INTERVAL));

    return STATUS_SUCCESS;
}

NTSTATUS muwine_init_registry(void) {
    NTSTATUS Status;
    hive* h;
    uint32_t offset;
    CM_KEY_NODE* kn;

    h = kmalloc(sizeof(hive), GFP_KERNEL);
    if (!h)
        return STATUS_INSUFFICIENT_RESOURCES;

    h->path.Buffer = NULL;
    h->path.Length = h->path.MaximumLength = 0;
    h->depth = 0;
    h->data = NULL;
    h->bins = NULL;
    h->size = 0;
    h->refcount = 0;
    INIT_LIST_HEAD(&h->holes);
    init_rwsem(&h->sem);
    h->dirty = false;
    h->volatile_bins = NULL;
    h->volatile_size = 0;
    INIT_LIST_HEAD(&h->volatile_holes);
    h->fs_path = NULL;
    h->parent_hive = NULL;

    Status = allocate_cell(h, sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]), &offset, true);
    if (!NT_SUCCESS(Status)) {
        kfree(h);
        return Status;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));

    kn->Signature = CM_KEY_NODE_SIGNATURE;
    kn->Flags = KEY_HIVE_ENTRY;
    kn->LastWriteTime = 0;;
    kn->Spare = 0;
    kn->Parent = 0;
    kn->SubKeyCount = 0;
    kn->VolatileSubKeyCount = 0;
    kn->SubKeyList = 0;
    kn->VolatileSubKeyList = 0;
    kn->ValuesCount = 0;
    kn->Values = 0;
    kn->Security = 0; // FIXME
    kn->Class = 0;
    kn->MaxNameLen = 0;
    kn->MaxClassLen = 0;
    kn->MaxValueNameLen = 0;
    kn->MaxValueDataLen = 0;
    kn->WorkVar = 0;
    kn->NameLength = 0;
    kn->ClassLength = 0;

    h->volatile_root_cell = offset;

    down_write(&hive_list_sem);

    list_add_tail(&h->list, &hive_list);

    up_write(&hive_list_sem);

    Status = init_flush_thread();
    if (!NT_SUCCESS(Status))
        return Status;

    register_reboot_notifier(&reboot_notifier);

    return STATUS_SUCCESS;
}

static void get_temp_hive_path(hive* h, char** out) {
    size_t len = strlen(h->fs_path);

    static const char suffix[] = ".tmp";

    // FIXME - also prepend dot, so that file is hidden

    *out = kmalloc(len + sizeof(suffix), GFP_KERNEL);
    if (!*out)
        return;

    memcpy(*out, h->fs_path, len);
    memcpy(&(*out)[len], suffix, sizeof(suffix));
}

static void init_qstr_from_path(struct qstr* q, const char* path) {
    unsigned int i, start = 0;

    i = 0;
    while (path[i] != 0) {
        if (path[i] == '/')
            start = i + 1;

        i++;
    }

    q->name = &path[start];
    q->len = i - start;
}

static NTSTATUS flush_hive(hive* h) {
    struct file* f;
    loff_t pos;
    HBASE_BLOCK* base_block;
    unsigned int i;
    uint32_t csum;
    char* temp_fn;
    int ret;
    struct qstr q;
    struct dentry* new_dentry;

    // FIXME - if called from periodic thread, give up if can't acquire lock immediately? (Might need to put a limit on how often this happens.)

    if (h->depth == 0) // volatile root
        return STATUS_SUCCESS;

    down_read(&h->sem);

    if (!h->dirty) {
        up_read(&h->sem);
        return STATUS_SUCCESS;
    }

    // FIXME - do reflink copy from old file to new, and only write changed sectors?

    base_block = (HBASE_BLOCK*)h->data;
    base_block->Sequence1++;
    base_block->Sequence2++;
    // FIXME - update timestamp in header
    base_block->Minor = HSYS_MAX_MINOR;
    base_block->Length = h->size - BIN_SIZE;

    // recalculate checksum in header

    csum = 0;

    for (i = 0; i < 127; i++) {
        csum ^= ((uint32_t*)h->data)[i];
    }

    if (csum == 0xffffffff)
        csum = 0xfffffffe;
    else if (csum == 0)
        csum = 1;

    base_block->CheckSum = csum;

    get_temp_hive_path(h, &temp_fn);
    if (!temp_fn) {
        printk(KERN_ALERT "flush_hive: unable to get temporary filename for hive\n");
        up_read(&h->sem);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // FIXME - O_TMPFILE?
    f = filp_open(temp_fn, O_CREAT | O_WRONLY, h->file_mode);
    if (IS_ERR(f)) {
        printk(KERN_ALERT "flush_hive: could not open %s for writing\n", temp_fn);
        up_read(&h->sem);
        kfree(temp_fn);
        return muwine_error_to_ntstatus((int)(uintptr_t)f);
    }

    // FIXME - preallocate file (vfs_fallocate?)

    // dump contents of h->data

    pos = 0;

    while (pos < h->size) {
        ssize_t written = kernel_write(f, (uint8_t*)h->data + pos, h->size - pos, &pos);

        if (written < 0) {
            printk(KERN_INFO "flush_hive: write returned %ld\n", written);
            filp_close(f, NULL);
            up_read(&h->sem);
            kfree(temp_fn);
            return muwine_error_to_ntstatus(written);
        }
    }

    // copy new file over old

    init_qstr_from_path(&q, h->fs_path);

    new_dentry = d_alloc(file_dentry(f)->d_parent, &q);

    lock_rename(file_dentry(f)->d_parent, file_dentry(f)->d_parent);

    ret = vfs_rename(file_dentry(f)->d_parent->d_inode, file_dentry(f), file_dentry(f)->d_parent->d_inode,
                     new_dentry, NULL, 0);
    if (ret < 0)
        printk(KERN_WARNING "flush_hive: vfs_rename returned %d\n", ret);

    unlock_rename(file_dentry(f)->d_parent, file_dentry(f)->d_parent);

    d_invalidate(new_dentry);

    // FIXME - preserve uid, gid, and extended attributes

    filp_close(f, NULL);

    h->dirty = false;

    up_read(&h->sem);

    kfree(temp_fn);

    return STATUS_SUCCESS;
}

NTSTATUS NtFlushKey(HANDLE KeyHandle) {
    key_object* key;

    key = (key_object*)get_object_from_handle(KeyHandle);
    if (!key || key->header.type != muwine_object_key)
        return STATUS_INVALID_HANDLE;

    return flush_hive(key->h);
}

static int reboot_callback(struct notifier_block* self, unsigned long val, void* data) {
    struct list_head* le;

    printk(KERN_INFO "reboot_callback(%p, %lx, %p)\n", self, val, data);

    down_read(&hive_list_sem);

    le = hive_list.next;
    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        flush_hive(h);

        le = le->next;
    }

    up_read(&hive_list_sem);

    return NOTIFY_DONE;
}
