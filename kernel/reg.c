#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <linux/namei.h>
#include "muwine.h"
#include "reg.h"
#include "sec.h"
#include "proc.h"
#include "file.h"

#define REG_FLUSH_INTERVAL 30 // seconds

static void key_object_close(object_header* obj);
static void reg_flush_timer_handler(struct timer_list* timer);
static NTSTATUS flush_hive(hive* h);
static int reboot_callback(struct notifier_block* self, unsigned long val, void* data);

static const WCHAR symlinkval[] = L"SymbolicLinkValue";

static LIST_HEAD(hive_list);
static DECLARE_RWSEM(hive_list_sem);
static LIST_HEAD(symlink_list);
static DEFINE_RWLOCK(symlink_lock);
static DEFINE_TIMER(reg_flush_timer, reg_flush_timer_handler);

static struct task_struct* reg_flush_thread = NULL;
static bool reg_thread_running = true;

type_object* key_type = NULL;

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
    h->volatile_sk = 0xffffffff;

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

    if (h->fs_path.Buffer)
        kfree(h->fs_path.Buffer);

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

static uint32_t calc_subkey_hash(const UNICODE_STRING* us) {
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

static NTSTATUS search_lh(hive* h, CM_KEY_FAST_INDEX* lh, uint32_t hash, const UNICODE_STRING* us,
                          bool is_volatile, uint32_t* offset_out) {
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

static NTSTATUS search_index(hive* h, uint32_t offset, const UNICODE_STRING* us, uint32_t hash, bool is_volatile,
                             uint32_t* offset_out) {
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

static NTSTATUS find_subkey(hive* h, uint32_t offset, const UNICODE_STRING* us, uint32_t* offset_out, bool* is_volatile) {
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

static NTSTATUS resolve_reg_symlinks(UNICODE_STRING* us, bool* done_alloc) {
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

static NTSTATUS open_key(PHANDLE KeyHandle, UNICODE_STRING* us, hive* h,
                         POBJECT_ATTRIBUTES ObjectAttributes, const UNICODE_STRING* orig_us,
                         ACCESS_MASK DesiredAccess) {
    NTSTATUS Status;
    key_object* k;
    bool is_volatile, parent_is_volatile;
    CM_KEY_NODE* nk;
    SECURITY_DESCRIPTOR_RELATIVE* sd = NULL;
    uint32_t offset;
    ACCESS_MASK access;

    static const WCHAR prefix[] = L"\\Registry\\";

    us->Buffer += h->path.Length / sizeof(WCHAR);
    us->Length -= h->path.Length;

    while (us->Length >= sizeof(WCHAR) && us->Buffer[0] == '\\') {
        us->Buffer++;
        us->Length -= sizeof(WCHAR);
    }

    down_read(&h->sem);

    Status = open_key_in_hive(h, us, &offset, false, &is_volatile, &parent_is_volatile);
    if (!NT_SUCCESS(Status)) {
        up_read(&h->sem);
        return Status;
    }

    if (is_volatile)
        nk = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
    else
        nk = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    if (nk->Security != 0) {
        CM_KEY_SECURITY* sk;

        if (is_volatile)
            sk = (CM_KEY_SECURITY*)((uint8_t*)h->volatile_bins + nk->Security + sizeof(int32_t));
        else
            sk = (CM_KEY_SECURITY*)((uint8_t*)h->bins + nk->Security + sizeof(int32_t));

        if (sk->Signature != CM_KEY_SECURITY_SIGNATURE)
            Status = STATUS_REGISTRY_CORRUPT;
        else
            Status = check_sd((SECURITY_DESCRIPTOR_RELATIVE*)sk->Descriptor, sk->DescriptorLength);

        if (!NT_SUCCESS(Status)) {
            up_read(&h->sem);
            return Status;
        }

        sd = kmalloc(sk->DescriptorLength, GFP_KERNEL);
        if (!sd) {
            up_read(&h->sem);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(sd, sk->Descriptor, sk->DescriptorLength);
    }

    up_read(&h->sem);

    // create key object and return handle

    k = (key_object*)muwine_alloc_object(sizeof(key_object), key_type, sd);
    if (!k)
        return STATUS_INSUFFICIENT_RESOURCES;

    k->header.path.Length = k->header.path.MaximumLength = orig_us->Length + sizeof(prefix) - sizeof(WCHAR);
    k->header.path.Buffer = kmalloc(k->header.path.Length, GFP_KERNEL);

    if (!k->header.path.Buffer) {
        dec_obj_refcount(&k->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(k->header.path.Buffer, prefix, sizeof(prefix) - sizeof(WCHAR));
    memcpy(&k->header.path.Buffer[(sizeof(prefix) / sizeof(WCHAR)) - 1], orig_us->Buffer, orig_us->Length);

    k->h = h;
    __sync_add_and_fetch(&h->refcount, 1);
    k->offset = offset;
    k->is_volatile = is_volatile;
    k->parent_is_volatile = parent_is_volatile;

    Status = access_check_object(&k->header, DesiredAccess, &access);
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&k->header);
        return Status;
    }

    Status = muwine_add_handle(&k->header, KeyHandle, ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&k->header);

    return Status;
}

static NTSTATUS NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
                            ULONG OpenOptions) {
    NTSTATUS Status;
    UNICODE_STRING us;
    struct list_head* le;
    bool us_alloc = false;
    UNICODE_STRING orig_us;
    WCHAR* oa_us_alloc = NULL;

    static const WCHAR prefix[] = L"\\Registry\\";

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        key_object* key = (key_object*)get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!key)
            return STATUS_INVALID_HANDLE;

        if (key->header.type != key_type) {
            dec_obj_refcount(&key->header);
            return STATUS_INVALID_HANDLE;
        }

        spin_lock(&key->header.header_lock);

        us.Length = key->header.path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&key->header.header_lock);
            dec_obj_refcount(&key->header);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, key->header.path.Buffer, key->header.path.Length);
        us.Buffer[key->header.path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(key->header.path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&key->header.header_lock);

        dec_obj_refcount(&key->header);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    // fail if ObjectAttributes->ObjectName doesn't begin with "\\Registry\\";

    if (us.Length < sizeof(prefix) - sizeof(WCHAR) ||
        wcsnicmp(us.Buffer, prefix, (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR))) {
        return STATUS_OBJECT_PATH_INVALID;
    }

    us.Buffer += (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR);
    us.Length -= sizeof(prefix) - sizeof(WCHAR);

    while (us.Length >= sizeof(WCHAR) && us.Buffer[(us.Length / sizeof(WCHAR)) - 1] == '\\') {
        us.Length -= sizeof(WCHAR);
    }

    // FIXME - is this right? What if we're opening a symlink, but there's another symlink in the path?
    if (!(OpenOptions & REG_OPTION_OPEN_LINK)) {
        Status = resolve_reg_symlinks(&us, &us_alloc);
        if (!NT_SUCCESS(Status)) {
            if (oa_us_alloc)
                kfree(oa_us_alloc);

            return Status;
        }
    }

    orig_us = us;

    down_read(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        if (us.Length < h->path.Length) {
            le = le->next;
            continue;
        }

        if (h->depth != 0 && us.Length > h->path.Length && us.Buffer[h->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        if (h->depth == 0 || !wcsnicmp(us.Buffer, h->path.Buffer, h->path.Length / sizeof(WCHAR))) {
            Status = open_key(KeyHandle, &us, h, ObjectAttributes, &orig_us, DesiredAccess);
            goto end;
        }

        le = le->next;
    }

    Status = STATUS_OBJECT_PATH_INVALID;

end:
    up_read(&hive_list_sem);

    if (us_alloc)
        kfree(orig_us.Buffer);

    if (oa_us_alloc)
        kfree(oa_us_alloc);

    return Status;
}

NTSTATUS user_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;

    if (!ObjectAttributes || !KeyHandle)
        return STATUS_INVALID_PARAMETER;

    if (!get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_INVALID_PARAMETER;

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenKeyEx(&h, DesiredAccess, &oa, 0);

    free_object_attributes(&oa);

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

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtOpenKeyEx(&h, DesiredAccess, &oa, OpenOptions);

    free_object_attributes(&oa);

    if (put_user(h, KeyHandle) < 0) {
        if (NT_SUCCESS(Status))
            NtClose(h);

        return STATUS_INVALID_PARAMETER;
    }

    return Status;
}

static void key_object_close(object_header* obj) {
    key_object* key = (key_object*)obj;

    if (key->h)
        __sync_sub_and_fetch(&key->h->refcount, 1);
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

static NTSTATUS query_key_info(KEY_INFORMATION_CLASS KeyInformationClass, void* KeyInformation, CM_KEY_NODE* kn,
                               ULONG Length, PULONG ResultLength) {
    switch (KeyInformationClass) {
        case KeyBasicInformation: {
            KEY_BASIC_INFORMATION kbi;
            ULONG reqlen = offsetof(KEY_BASIC_INFORMATION, Name);
            ULONG left;
            WCHAR* name;

            if (kn->Flags & KEY_COMP_NAME)
                reqlen += kn->NameLength * sizeof(WCHAR);
            else
                reqlen += kn->NameLength;

            *ResultLength = reqlen;

            memset(&kbi, 0, offsetof(KEY_BASIC_INFORMATION, Name));

            kbi.LastWriteTime.QuadPart = kn->LastWriteTime;

            if (kn->Flags & KEY_COMP_NAME)
                kbi.NameLength = kn->NameLength * sizeof(WCHAR);
            else
                kbi.NameLength = kn->NameLength;

            if (Length < offsetof(KEY_BASIC_INFORMATION, Name)) {
                memcpy(KeyInformation, &kbi, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyInformation, &kbi, offsetof(KEY_BASIC_INFORMATION, Name));
            left = Length - offsetof(KEY_BASIC_INFORMATION, Name);

            name = (WCHAR*)((uint8_t*)KeyInformation + offsetof(KEY_BASIC_INFORMATION, Name));

            if (kn->Flags & KEY_COMP_NAME) {
                unsigned int i;
                ULONG namelen = kn->NameLength * sizeof(WCHAR);

                if (namelen > left)
                    namelen = left;

                for (i = 0; i < namelen / sizeof(WCHAR); i++) {
                    name[i] = *((char*)kn->Name + i);
                }

                if (kn->NameLength * sizeof(WCHAR) > left)
                    return STATUS_BUFFER_OVERFLOW;
            } else {
                if (left < kn->NameLength) {
                    memcpy(name, kn->Name, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(name, kn->Name, kn->NameLength);
            }

            break;
        }

        case KeyNodeInformation: {
            KEY_NODE_INFORMATION kni;
            ULONG reqlen = offsetof(KEY_NODE_INFORMATION, Name);
            ULONG left;
            WCHAR* name;

            if (kn->Flags & KEY_COMP_NAME)
                reqlen += kn->NameLength * sizeof(WCHAR);
            else
                reqlen += kn->NameLength;

            *ResultLength = reqlen;

            memset(&kni, 0, offsetof(KEY_NODE_INFORMATION, Name));

            kni.LastWriteTime.QuadPart = kn->LastWriteTime;
            // FIXME - ClassOffset and ClassLength

            if (kn->Flags & KEY_COMP_NAME)
                kni.NameLength = kn->NameLength * sizeof(WCHAR);
            else
                kni.NameLength = kn->NameLength;

            if (Length < offsetof(KEY_NODE_INFORMATION, Name)) {
                memcpy(KeyInformation, &kni, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyInformation, &kni, offsetof(KEY_NODE_INFORMATION, Name));
            left = Length - offsetof(KEY_NODE_INFORMATION, Name);

            name = (WCHAR*)((uint8_t*)KeyInformation + offsetof(KEY_NODE_INFORMATION, Name));

            if (kn->Flags & KEY_COMP_NAME) {
                unsigned int i;
                ULONG namelen = kn->NameLength * sizeof(WCHAR);

                if (namelen > left)
                    namelen = left;

                for (i = 0; i < namelen / sizeof(WCHAR); i++) {
                    name[i] = *((char*)kn->Name + i);
                }

                if (kn->NameLength * sizeof(WCHAR) > left)
                    return STATUS_BUFFER_OVERFLOW;
            } else {
                if (left < kn->NameLength) {
                    memcpy(name, kn->Name, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(name, kn->Name, kn->NameLength);
            }

            break;
        }

        case KeyFullInformation: {
            KEY_FULL_INFORMATION kfi;
            ULONG reqlen = offsetof(KEY_FULL_INFORMATION, Class);

            *ResultLength = reqlen;

            kfi.LastWriteTime.QuadPart = kn->LastWriteTime;
            kfi.TitleIndex = 0;
            kfi.ClassOffset = 0; // FIXME?
            kfi.ClassLength = 0; // FIXME?
            kfi.SubKeys = kn->SubKeyCount + kn->VolatileSubKeyCount;
            kfi.MaxNameLen = kn->MaxNameLen;
            kfi.MaxClassLen = kn->MaxClassLen;
            kfi.Values = kn->ValuesCount;
            kfi.MaxValueNameLen = kn->MaxValueNameLen;
            kfi.MaxValueDataLen = kn->MaxValueDataLen;

            if (Length < offsetof(KEY_FULL_INFORMATION, Class)) {
                memcpy(KeyInformation, &kfi, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyInformation, &kfi, offsetof(KEY_FULL_INFORMATION, Class));

            break;
        }

        case KeyNameInformation: {
            printk(KERN_INFO "query_key_info: unhandled class KeyNameInformation\n");
            // FIXME
            return STATUS_INVALID_PARAMETER;
        }

        case KeyCachedInformation: {
            printk(KERN_INFO "query_key_info: unhandled class KeyCachedInformation\n");
            // FIXME
            return STATUS_INVALID_PARAMETER;
        }

        // FIXME - other classes not in Wine:
        // FIXME - KeyFlagsInformation
        // FIXME - KeyVirtualizationInformation
        // FIXME - KeyHandleTagsInformation
        // FIXME - KeyTrustInformation
        // FIXME - KeyLayerInformation

        default:
            printk(KERN_INFO "query_key_info: unhandled class %x\n", KeyInformationClass);
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                               PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ACCESS_MASK access;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint32_t cell_offset;
    void* bins;
    void* bins2;
    bool is_volatile;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & KEY_ENUMERATE_SUB_KEYS)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (Index >= kn->SubKeyCount + kn->VolatileSubKeyCount) {
        Status = STATUS_NO_MORE_ENTRIES;
        goto end;
    }

    if (Index >= kn->SubKeyCount) {
        Status = get_key_item_by_index(key->h, kn, Index - kn->SubKeyCount, &cell_offset, true);
        if (!NT_SUCCESS(Status)) {
            printk(KERN_INFO "get_key_item_by_index returned %08x\n", Status);
            goto end;
        }

        is_volatile = true;
    } else {
        Status = get_key_item_by_index(key->h, kn, Index, &cell_offset, false);
        if (!NT_SUCCESS(Status)) {
            printk(KERN_INFO "get_key_item_by_index returned %08x\n", Status);
            goto end;
        }

        is_volatile = false;
    }

    bins2 = is_volatile ? key->h->volatile_bins : key->h->bins;

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins2 + cell_offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    kn2 = (CM_KEY_NODE*)((uint8_t*)bins2 + cell_offset + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    Status = query_key_info(KeyInformationClass, KeyInformation, kn2,
                            Length, ResultLength);

end:
    up_read(&key->h->sem);

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
                             PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ULONG reslen = 0;
    void* buf;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtEnumerateKey(KeyHandle, Index, KeyInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
        if (buf) {
            if (copy_to_user(KeyInformation, buf, min(Length, reslen)) != 0)
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
                                PVOID KeyValueInformation, ULONG Length, PULONG ResultLength, bool is_volatile) {
    uint8_t* bins = is_volatile ? h->volatile_bins : h->bins;

    switch (KeyValueInformationClass) {
        case KeyValueBasicInformation: {
            KEY_VALUE_BASIC_INFORMATION kvbi;
            ULONG reqlen = offsetof(KEY_VALUE_BASIC_INFORMATION, Name);
            ULONG left;
            WCHAR* name;

            if (vk->Flags & VALUE_COMP_NAME)
                reqlen += vk->NameLength * sizeof(WCHAR);
            else
                reqlen += vk->NameLength;

            *ResultLength = reqlen;

            memset(&kvbi, 0, offsetof(KEY_VALUE_BASIC_INFORMATION, Name));

            kvbi.TitleIndex = 0;
            kvbi.Type = vk->Type;

            if (vk->Flags & VALUE_COMP_NAME)
                kvbi.NameLength = vk->NameLength * sizeof(WCHAR);
            else
                kvbi.NameLength = vk->NameLength;

            if (Length < offsetof(KEY_VALUE_BASIC_INFORMATION, Name)) {
                memcpy(KeyValueInformation, &kvbi, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyValueInformation, &kvbi, offsetof(KEY_VALUE_BASIC_INFORMATION, Name));
            left = Length - offsetof(KEY_VALUE_BASIC_INFORMATION, Name);

            name = (WCHAR*)((uint8_t*)KeyValueInformation + offsetof(KEY_VALUE_BASIC_INFORMATION, Name));

            if (vk->Flags & VALUE_COMP_NAME) {
                unsigned int i;
                ULONG namelen = vk->NameLength * sizeof(WCHAR);

                if (namelen > left)
                    namelen = left;

                for (i = 0; i < namelen / sizeof(WCHAR); i++) {
                    name[i] = *((char*)vk->Name + i);
                }

                if (vk->NameLength * sizeof(WCHAR) > left)
                    return STATUS_BUFFER_OVERFLOW;
            } else {
                if (left < vk->NameLength) {
                    memcpy(name, vk->Name, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(name, vk->Name, vk->NameLength);
            }

            return STATUS_SUCCESS;
        }

        case KeyValueFullInformation: {
            KEY_VALUE_FULL_INFORMATION kvfi;
            ULONG datalen = vk->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;
            ULONG reqlen = offsetof(KEY_VALUE_FULL_INFORMATION, Name[0]) + datalen;
            uint8_t* data;
            WCHAR* name;
            ULONG left;

            memset(&kvfi, 0, offsetof(KEY_VALUE_FULL_INFORMATION, Name));

            if (vk->Flags & VALUE_COMP_NAME)
                reqlen += vk->NameLength * sizeof(WCHAR);
            else
                reqlen += vk->NameLength;

            *ResultLength = reqlen;

            kvfi.TitleIndex = 0;
            kvfi.Type = vk->Type;

            if (vk->Flags & VALUE_COMP_NAME)
                kvfi.NameLength = vk->NameLength * sizeof(WCHAR);
            else
                kvfi.NameLength = vk->NameLength;

            kvfi.DataOffset = offsetof(KEY_VALUE_FULL_INFORMATION, Name[0]) + kvfi.NameLength;
            kvfi.DataLength = datalen;

            if (Length < offsetof(KEY_VALUE_FULL_INFORMATION, Name)) {
                memcpy(KeyValueInformation, &kvfi, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyValueInformation, &kvfi, offsetof(KEY_VALUE_FULL_INFORMATION, Name));

            name = (WCHAR*)((uint8_t*)KeyValueInformation + offsetof(KEY_VALUE_FULL_INFORMATION, Name));
            left = Length - offsetof(KEY_VALUE_FULL_INFORMATION, Name);

            if (vk->Flags & VALUE_COMP_NAME) {
                unsigned int i;
                ULONG namelen = vk->NameLength * sizeof(WCHAR);

                if (namelen > left)
                    namelen = left;

                for (i = 0; i < namelen / sizeof(WCHAR); i++) {
                    name[i] = *((char*)vk->Name + i);
                }

                if (vk->NameLength * sizeof(WCHAR) > left)
                    return STATUS_BUFFER_OVERFLOW;

                left -= vk->NameLength * sizeof(WCHAR);
            } else {
                if (left < vk->NameLength) {
                    memcpy(name, vk->Name, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(name, vk->Name, vk->NameLength);
                left -= vk->NameLength;
            }

            if (kvfi.DataLength == 0)
                return STATUS_SUCCESS;

            data = (uint8_t*)KeyValueInformation + kvfi.DataOffset;

            if (vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) { // stored in cell
                // FIXME - make sure not more than 4 bytes

                if (datalen > left) {
                    memcpy(data, &vk->Data, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(data, &vk->Data, datalen);
            } else {
                // FIXME - check not out of bounds

                int32_t size = -*(int32_t*)((uint8_t*)bins + vk->Data);

                if (size < datalen + sizeof(int32_t))
                    return STATUS_REGISTRY_CORRUPT;

                if (datalen > left) {
                    memcpy(data, bins + vk->Data + sizeof(int32_t), left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(data, bins + vk->Data + sizeof(int32_t), datalen);
            }

            return STATUS_SUCCESS;
        }

        case KeyValuePartialInformation: {
            KEY_VALUE_PARTIAL_INFORMATION kvpi;
            ULONG len = vk->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;
            ULONG reqlen = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data[0]) + len;
            ULONG left;
            uint8_t* data;

            *ResultLength = reqlen;

            memset(&kvpi, 0, offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data));

            kvpi.TitleIndex = 0;
            kvpi.Type = vk->Type;
            kvpi.DataLength = len;

            if (Length < offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data)) {
                memcpy(KeyValueInformation, &kvpi, Length);
                return STATUS_BUFFER_OVERFLOW;
            }

            memcpy(KeyValueInformation, &kvpi, offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data));
            left = Length - offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data);

            data = (uint8_t*)KeyValueInformation + offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data);

            if (vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE) { // stored in cell
                // FIXME - make sure not more than 4 bytes

                if (left < len) {
                    memcpy(data, &vk->Data, left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(data, &vk->Data, len);
            } else {
                // FIXME - check not out of bounds

                int32_t size = -*(int32_t*)((uint8_t*)bins + vk->Data);

                if (size < len + sizeof(int32_t))
                    return STATUS_REGISTRY_CORRUPT;

                if (left < len) {
                    memcpy(data, bins + vk->Data + sizeof(int32_t), left);
                    return STATUS_BUFFER_OVERFLOW;
                }

                memcpy(data, bins + vk->Data + sizeof(int32_t), len);
            }

            return STATUS_SUCCESS;
        }

        // FIXME - KeyValueFullInformationAlign64
        // FIXME - KeyValuePartialInformationAlign64
        // FIXME - KeyValueLayerInformation

        default:
            printk(KERN_INFO "query_key_value: unhandled class %x\n", KeyValueInformationClass);
            return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ACCESS_MASK access;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    uint32_t* values_list;
    CM_KEY_VALUE* vk;
    void* bins;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & KEY_QUERY_VALUE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins: key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (Index >= kn->ValuesCount) {
        Status = STATUS_NO_MORE_ENTRIES;
        goto end;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + values_list[Index]);
    vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[Index] + sizeof(int32_t));

    if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length,
                             ResultLength, key->is_volatile);

end:
    up_read(&key->h->sem);

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                                  PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ULONG reslen = 0;
    void* buf;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
        if (buf) {
            if (copy_to_user(KeyValueInformation, buf, min(Length, reslen)) != 0)
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
    ACCESS_MASK access;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    uint32_t* values_list;
    unsigned int i;
    void* bins;

    if (!ValueName)
        return STATUS_INVALID_PARAMETER;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & KEY_QUERY_VALUE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

    down_read(&key->h->sem);

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;

    size = -*(int32_t*)((uint8_t*)bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (kn->ValuesCount == 0) {
        Status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto end;
    }

    // FIXME - check not out of bounds

    size = -*(int32_t*)((uint8_t*)bins + kn->Values);

    if (size < sizeof(int32_t) + (kn->ValuesCount * sizeof(uint32_t))) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

    for (i = 0; i < kn->ValuesCount; i++) {
        CM_KEY_VALUE* vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[i] + sizeof(int32_t));

        // FIXME - check not out of bounds

        size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

        if (vk->Signature != CM_KEY_VALUE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk->NameLength) {
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
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
                    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length,
                                             ResultLength, key->is_volatile);
                    goto end;
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
                    Status = query_key_value(key->h, vk, KeyValueInformationClass, KeyValueInformation, Length,
                                             ResultLength, key->is_volatile);
                    goto end;
                }
            }
        }
    }

    Status = STATUS_OBJECT_NAME_NOT_FOUND;

end:
    up_read(&key->h->sem);

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                              PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    UNICODE_STRING us;
    ULONG reslen = 0;
    void* buf;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

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

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
        if (buf) {
            if (copy_to_user(KeyValueInformation, buf, min(Length, reslen)) != 0)
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

        hbin = (HBIN*)((uint8_t*)h->data + h->size);
        hbin->Signature = HV_HBIN_SIGNATURE;
        hbin->FileOffset = (uint8_t*)hbin - (uint8_t*)h->bins;
        hbin->Size = BIN_SIZE;
        hbin->Reserved[0] = 0;
        hbin->Reserved[1] = 0;
        hbin->TimeStamp.QuadPart = 0; // FIXME
        hbin->Spare = 0;

        *offset = hbin->FileOffset + sizeof(HBIN);
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

static void update_symlink_cache(const UNICODE_STRING* path, WCHAR* value, ULONG value_length) {
    UNICODE_STRING src, dest;
    struct list_head* le;
    symlink* s;
    unsigned int i, depth;

    static const WCHAR prefix[] = L"\\Registry\\";

    src.Buffer = path->Buffer;
    src.Length = path->Length;

    if (src.Length >= sizeof(prefix) - sizeof(WCHAR) && !wcsnicmp(src.Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1)) {
        src.Buffer += (sizeof(prefix) / sizeof(WCHAR)) - 1;
        src.Length -= sizeof(prefix) - sizeof(WCHAR);
    }

    dest.Buffer = value;
    dest.Length = value_length;

    if (dest.Length >= sizeof(prefix) - sizeof(WCHAR) && !wcsnicmp(dest.Buffer, prefix, (sizeof(prefix) / sizeof(WCHAR)) - 1)) {
        dest.Buffer += (sizeof(prefix) / sizeof(WCHAR)) - 1;
        dest.Length -= sizeof(prefix) - sizeof(WCHAR);
    }

    depth = 1;
    for (i = 0; i < src.Length / sizeof(WCHAR); i++) {
        if (src.Buffer[i] == '\\')
            depth++;
    }

    // check if already exists

    write_lock(&symlink_lock);

    le = symlink_list.next;
    while (le != &symlink_list) {
        symlink* s = list_entry(le, symlink, list);

        if (s->depth == depth && s->source_len == src.Length && !wcsnicmp(s->source, src.Buffer, src.Length / sizeof(WCHAR))) {
            if (dest.Length == 0) {
                list_del(&s->list);
                write_unlock(&symlink_lock);
                return;
            }

            kfree(s->destination);

            s->destination = kmalloc(dest.Length, GFP_KERNEL);
            // FIXME - handle malloc failure

            memcpy(s->destination, dest.Buffer, dest.Length);

            s->destination_len = dest.Length;
            write_unlock(&symlink_lock);

            return;
        } else if (s->depth < depth)
            break;

        le = le->next;
    }

    if (value_length == 0) {
        write_unlock(&symlink_lock);
        return;
    }

    // otherwise, add new

    s = kmalloc(sizeof(symlink), GFP_KERNEL); // FIXME - handle malloc failure

    s->source = kmalloc(src.Length, GFP_KERNEL); // FIXME - handle malloc failure
    memcpy(s->source, src.Buffer, src.Length);
    s->source_len = src.Length;

    s->destination = kmalloc(dest.Length, GFP_KERNEL); // FIXME - handle malloc failure
    memcpy(s->destination, dest.Buffer, dest.Length);
    s->destination_len = dest.Length;
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
    ACCESS_MASK access;
    key_object* key;
    CM_KEY_NODE* kn;
    int32_t size;
    uint32_t vk_offset, values_list_offset;
    CM_KEY_VALUE* vk;
    uint32_t* values_list;
    void* bins;

    // FIXME - should we be rejecting short REG_DWORDs etc. here?

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & KEY_SET_VALUE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

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

            vk_offset = values_list[i];

            vk = (CM_KEY_VALUE*)((uint8_t*)bins + vk_offset + sizeof(int32_t));

            // FIXME - check not out of bounds

            size = -*(int32_t*)((uint8_t*)bins + vk_offset);

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
                ULONG orig_data_len = vk->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;

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

                        bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
                        kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));
                        vk = (CM_KEY_VALUE*)((uint8_t*)bins + vk_offset + sizeof(int32_t));
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

                            bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
                            kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));
                            vk = (CM_KEY_VALUE*)((uint8_t*)bins + vk_offset + sizeof(int32_t));

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
                        update_symlink_cache(&key->header.path, Data, DataSize);
                    else
                        update_symlink_cache(&key->header.path, NULL, 0);
                }

                if (DataSize >= kn->MaxValueDataLen || kn->ValuesCount == 1)
                    kn->MaxValueDataLen = DataSize;
                else if (kn->MaxValueDataLen == orig_data_len) {
                    unsigned int j;

                    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

                    kn->MaxValueDataLen = 0;

                    for (j = 0; j < kn->ValuesCount; j++) {
                        if (j != i) {
                            CM_KEY_VALUE* vk2 = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[j] + sizeof(int32_t));

                            // FIXME - check not out of bounds

                            size = -*(int32_t*)((uint8_t*)bins + values_list[j]);

                            if (vk2->Signature == CM_KEY_VALUE_SIGNATURE && size >= sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk2->NameLength) {
                                uint32_t len = vk2->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;

                                if (len > kn->MaxValueDataLen)
                                    kn->MaxValueDataLen = len;
                            }
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

    Status = allocate_cell(key->h, offsetof(CM_KEY_VALUE, Name[0]) + (ValueName ? ValueName->Length : 0), &vk_offset, key->is_volatile);
    if (!NT_SUCCESS(Status))
        goto end;

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

    vk = (CM_KEY_VALUE*)(bins + vk_offset + sizeof(int32_t));
    vk->Signature = CM_KEY_VALUE_SIGNATURE;
    vk->NameLength = ValueName ? ValueName->Length : 0;
    vk->Type = Type;
    vk->Flags = 0;
    vk->Spare = 0;

    if (vk->NameLength > 0)
        memcpy(vk->Name, ValueName->Buffer, vk->NameLength);

    if (DataSize > sizeof(uint32_t)) {
        uint32_t addr;

        vk->DataLength = DataSize;

        Status = allocate_cell(key->h, DataSize, &addr, key->is_volatile);
        if (!NT_SUCCESS(Status)) {
            free_cell(key->h, vk_offset, key->is_volatile);
            goto end;
        }

        bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
        vk = (CM_KEY_VALUE*)(bins + vk_offset + sizeof(int32_t));
        kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));

        vk->Data = addr;

        memcpy(bins + vk->Data + sizeof(int32_t), Data, DataSize);
    } else {
        vk->DataLength = DataSize == 0 ? 0 : (CM_KEY_VALUE_SPECIAL_SIZE | DataSize);
        memcpy(&vk->Data, Data, DataSize);
    }

    if (kn->Flags & KEY_SYM_LINK && ValueName->Length == sizeof(symlinkval) - sizeof(WCHAR) &&
        !wcsnicmp(ValueName->Buffer, symlinkval, (sizeof(symlinkval) / sizeof(WCHAR)) - 1)) {
        if (Type == REG_LINK)
            update_symlink_cache(&key->header.path, Data, DataSize);
        else
            update_symlink_cache(&key->header.path, NULL, 0);
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

    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));
    values_list = (uint32_t*)((uint8_t*)bins + values_list_offset + sizeof(int32_t));

    if (kn->ValuesCount > 0) {
        uint32_t* old_values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));

        memcpy(values_list, old_values_list, kn->ValuesCount * sizeof(uint32_t));

        free_cell(key->h, kn->Values, key->is_volatile);
    }

    values_list[kn->ValuesCount] = vk_offset;

    kn->Values = values_list_offset;
    kn->ValuesCount++;

    if (ValueName && ValueName->Length > kn->MaxValueNameLen)
        kn->MaxValueNameLen = ValueName->Length;

    if (DataSize > kn->MaxValueDataLen)
        kn->MaxValueDataLen = DataSize;

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status) && !key->is_volatile)
        key->h->dirty = true;

    up_write(&key->h->sem);

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex,
                            ULONG Type, PVOID Data, ULONG DataSize) {
    NTSTATUS Status;
    UNICODE_STRING us;
    void* buf;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

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
    ACCESS_MASK access;
    key_object* key;
    CM_KEY_NODE* kn;
    int32_t size;
    unsigned int i;
    uint32_t* values_list;
    void* bins;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & KEY_SET_VALUE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

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
                kn->MaxValueNameLen = 0;
                kn->MaxValueDataLen = 0;
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

                    bins = key->is_volatile ? key->h->volatile_bins : key->h->bins;
                    kn = (CM_KEY_NODE*)((uint8_t*)bins + key->offset + sizeof(int32_t));
                    values_list = (uint32_t*)((uint8_t*)bins + kn->Values + sizeof(int32_t));
                    vk = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[i] + sizeof(int32_t));

                    new_values_list = (uint32_t*)((uint8_t*)bins + values_list_offset + sizeof(int32_t));

                    memcpy(new_values_list, values_list, i * sizeof(uint32_t));
                    memcpy(&new_values_list[i], &values_list[i+1], (kn->ValuesCount - i - 1) * sizeof(uint32_t));

                    kn->Values = values_list_offset;
                }

                if (kn->MaxValueNameLen  == ValueName->Length) {
                    unsigned int j;

                    kn->MaxValueNameLen = 0;

                    for (j = 0; j < kn->ValuesCount; j++) {
                        if (j != i) {
                            CM_KEY_VALUE* vk2 = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[j] + sizeof(int32_t));

                            // FIXME - check not out of bounds

                            size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

                            if (vk2->Signature == CM_KEY_VALUE_SIGNATURE || size >= sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk2->NameLength) {
                                uint32_t len;

                                if (vk2->Flags & VALUE_COMP_NAME)
                                    len = vk2->NameLength * sizeof(WCHAR);
                                else
                                    len = vk2->NameLength;

                                if (len > kn->MaxValueNameLen)
                                    kn->MaxValueNameLen = len;
                            }
                        }
                    }
                }

                if (kn->MaxValueDataLen == (vk->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE)) {
                    unsigned int j;

                    kn->MaxValueDataLen = 0;

                    for (j = 0; j < kn->ValuesCount; j++) {
                        if (j != i) {
                            CM_KEY_VALUE* vk2 = (CM_KEY_VALUE*)((uint8_t*)bins + values_list[j] + sizeof(int32_t));

                            // FIXME - check not out of bounds

                            size = -*(int32_t*)((uint8_t*)bins + values_list[i]);

                            if (vk2->Signature == CM_KEY_VALUE_SIGNATURE || size >= sizeof(int32_t) + offsetof(CM_KEY_VALUE, Name[0]) + vk2->NameLength) {
                                uint32_t len = vk2->DataLength & ~CM_KEY_VALUE_SPECIAL_SIZE;

                                if (len > kn->MaxValueDataLen)
                                    kn->MaxValueDataLen = len;
                            }
                        }
                    }
                }
            }

            if (vk->DataLength != 0 && !(vk->DataLength & CM_KEY_VALUE_SPECIAL_SIZE)) // free data cell, if not resident
                free_cell(key->h, vk->Data, key->is_volatile);

            if (kn->Flags & KEY_SYM_LINK && vk->Type == REG_LINK && ValueName->Length == sizeof(symlinkval) - sizeof(WCHAR) &&
                !wcsnicmp(ValueName->Buffer, symlinkval, (sizeof(symlinkval) / sizeof(WCHAR)) - 1)) {
                update_symlink_cache(&key->header.path, NULL, 0);
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

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {
    NTSTATUS Status;
    UNICODE_STRING us;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

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

static NTSTATUS allocate_inherited_sk(hive* h, uint32_t parent_off, uint32_t* off, token_object* tok,
                                      bool is_volatile, bool parent_is_volatile,
                                      SECURITY_DESCRIPTOR_RELATIVE* provided_sd,
                                      SECURITY_DESCRIPTOR_RELATIVE** ret_sd) {
    NTSTATUS Status;
    int32_t size;
    CM_KEY_SECURITY* sk;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    size_t sdlen;
    uint32_t skoff, orig_skoff;
    void* parent_bins = parent_is_volatile ? h->volatile_bins : h->bins;
    void* bins = is_volatile ? h->volatile_bins : h->bins;

    size = -*(int32_t*)(parent_bins + parent_off);

    if (size < offsetof(CM_KEY_SECURITY, Descriptor))
        return STATUS_REGISTRY_CORRUPT;

    sk = (CM_KEY_SECURITY*)(parent_bins + parent_off + sizeof(int32_t));

    if (sk->Signature != CM_KEY_SECURITY_SIGNATURE || size < offsetof(CM_KEY_SECURITY, Descriptor) + sk->DescriptorLength)
        return STATUS_REGISTRY_CORRUPT;

    Status = check_sd((SECURITY_DESCRIPTOR_RELATIVE*)sk->Descriptor, sk->DescriptorLength);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = muwine_create_sd2((SECURITY_DESCRIPTOR_RELATIVE*)sk->Descriptor,
                               provided_sd, tok, &key_type->generic_mapping, 0,
                               true, &sd, &sdlen);

    if (!NT_SUCCESS(Status))
        return Status;

    // FIXME - need to remove any ACEs for temporary SIDs (logon SIDs etc.) from SD?

    if (!is_volatile || h->volatile_sk != 0xffffffff) {
        // walk through sk list, and increase refcount if already present

        if ((is_volatile && parent_is_volatile) || (!is_volatile && !parent_is_volatile))
            orig_skoff = parent_off;
        else
            orig_skoff = h->volatile_sk;

        skoff = orig_skoff;

        do {
            size = -*(int32_t*)(bins + skoff);

            if (size < offsetof(CM_KEY_SECURITY, Descriptor))
                break;

            sk = (CM_KEY_SECURITY*)(bins + skoff + sizeof(int32_t));

            if (sk->Signature != CM_KEY_SECURITY_SIGNATURE || size < offsetof(CM_KEY_SECURITY, Descriptor) + sk->DescriptorLength)
                break;

            if (sk->DescriptorLength == sdlen && !memcmp(sk->Descriptor, sd, sdlen)) {
                sk->ReferenceCount++;
                *off = skoff;

                if (ret_sd)
                    *ret_sd = sd;
                else
                    kfree(sd);

                return STATUS_SUCCESS;
            }

            skoff = sk->Flink;
        } while (skoff != orig_skoff);
    }

    // otherwise, allocate new cell and to list

    Status = allocate_cell(h, offsetof(CM_KEY_SECURITY, Descriptor) + sdlen, &skoff, is_volatile);
    if (!NT_SUCCESS(Status))
        return Status;

    bins = is_volatile ? h->volatile_bins : h->bins;
    sk = (CM_KEY_SECURITY*)(bins + skoff + sizeof(int32_t));

    sk->Signature = CM_KEY_SECURITY_SIGNATURE;
    sk->Reserved = 0;

    if ((is_volatile && parent_is_volatile) || (!is_volatile && !parent_is_volatile)) { // parent and child have same volatility
        CM_KEY_SECURITY* parent_sk = (CM_KEY_SECURITY*)(bins + parent_off + sizeof(int32_t));

        if (parent_sk->Flink == parent_off) { // parent SK is only entry
            parent_sk->Flink = parent_sk->Blink = skoff;
            sk->Flink = sk->Blink = parent_off;
        } else {
            CM_KEY_SECURITY* next_sk = (CM_KEY_SECURITY*)(bins + parent_sk->Flink + sizeof(int32_t));

            sk->Flink = parent_sk->Flink;
            next_sk->Blink = skoff;

            sk->Blink = parent_off;
            parent_sk->Flink = skoff;
        }
    } else if (h->volatile_sk != 0xffffffff) { // child is volatile, and volatile_sk already set
        CM_KEY_SECURITY* sk2 = (CM_KEY_SECURITY*)(h->volatile_bins + h->volatile_sk + sizeof(int32_t));

        if (sk2->Flink == h->volatile_sk) { // SK is only entry
            sk2->Flink = sk2->Blink = skoff;
            sk->Flink = sk->Blink = h->volatile_sk;
        } else {
            CM_KEY_SECURITY* sk3 = (CM_KEY_SECURITY*)(h->volatile_bins + sk2->Flink + sizeof(int32_t));

            sk->Flink = sk2->Flink;
            sk3->Blink = skoff;

            sk2->Flink = skoff;
            sk->Blink = h->volatile_sk;
        }
    } else { // first volatile key
        sk->Flink = skoff;
        sk->Blink = skoff;

        h->volatile_sk = skoff;
    }

    sk->ReferenceCount = 1;
    sk->DescriptorLength = sdlen;
    memcpy(sk->Descriptor, sd, sdlen);

    *off = skoff;

    if (ret_sd)
        *ret_sd = sd;
    else
        kfree(sd);

    return STATUS_SUCCESS;
}

static void free_sk(hive* h, uint32_t off, bool is_volatile) {
    int32_t size;
    CM_KEY_SECURITY* sk;
    void* bins;

    if (is_volatile)
        bins = h->volatile_bins;
    else
        bins = h->bins;

    size = -*(int32_t*)(bins + off);

    if (size < offsetof(CM_KEY_SECURITY, Descriptor))
        return;

    sk = (CM_KEY_SECURITY*)(bins + off + sizeof(int32_t));

    if (sk->Signature != CM_KEY_SECURITY_SIGNATURE)
        return;

    if (sk->ReferenceCount > 1) {
        sk->ReferenceCount--;
        return;
    }

    if (is_volatile && off == h->volatile_sk) {
        if (sk->Flink == off)
            h->volatile_sk = 0xffffffff;
        else
            h->volatile_sk = sk->Flink;
    }

    // FIXME - check not out of bounds
    size = -*(int32_t*)(bins + sk->Flink);

    // change sk->Flink->Blink to sk->Blink

    if (size >= offsetof(CM_KEY_SECURITY, Descriptor)) {
        CM_KEY_SECURITY* sk2 = (CM_KEY_SECURITY*)(bins + sk->Flink + sizeof(int32_t));

        sk2->Blink = sk->Flink;
    }

    // FIXME - check not out of bounds
    size = -*(int32_t*)(bins + sk->Blink);

    // change sk->Blink->Flink to sk->Flink

    if (size >= offsetof(CM_KEY_SECURITY, Descriptor)) {
        CM_KEY_SECURITY* sk2 = (CM_KEY_SECURITY*)(bins + sk->Blink + sizeof(int32_t));

        sk2->Flink = sk->Flink;
    }

    free_cell(h, off, is_volatile);
}

static NTSTATUS extract_subkey_list(hive* h, bool is_volatile, uint32_t offset, uint32_t count, CM_INDEX** list) {
    int32_t size;
    uint16_t sig;

    // FIXME - check not out of bounds

    if (is_volatile)
        size = -*(int32_t*)(h->volatile_bins + offset);
    else
        size = -*(int32_t*)(h->bins + offset);

    if (size < sizeof(int32_t) + sizeof(uint16_t))
        return STATUS_REGISTRY_CORRUPT;

    if (is_volatile)
        sig = *(uint16_t*)(h->volatile_bins + offset + sizeof(int32_t));
    else
        sig = *(uint16_t*)(h->bins + offset + sizeof(int32_t));

    if (sig == CM_KEY_HASH_LEAF) {
        CM_KEY_FAST_INDEX* lh;

        if (is_volatile)
            lh = (CM_KEY_FAST_INDEX*)(h->volatile_bins + offset + sizeof(int32_t));
        else
            lh = (CM_KEY_FAST_INDEX*)(h->bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List) + (count * sizeof(CM_INDEX)))
            return STATUS_REGISTRY_CORRUPT;

        if (lh->Count != count)
            return STATUS_REGISTRY_CORRUPT;

        *list = kmalloc(count * sizeof(CM_INDEX), GFP_KERNEL);
        memcpy(*list, lh->List, count * sizeof(CM_INDEX));

        return STATUS_SUCCESS;
    } else if (sig == CM_KEY_INDEX_ROOT) {
        CM_KEY_INDEX* ri;
        CM_INDEX* l;
        unsigned int i;

        if (is_volatile)
            ri = (CM_KEY_INDEX*)(h->volatile_bins + offset + sizeof(int32_t));
        else
            ri = (CM_KEY_INDEX*)(h->bins + offset + sizeof(int32_t));

        if (size < sizeof(int32_t) + offsetof(CM_KEY_INDEX, List) + (ri->Count * sizeof(uint32_t)))
            return STATUS_REGISTRY_CORRUPT;

        *list = l = kmalloc(count * sizeof(CM_INDEX), GFP_KERNEL);

        for (i = 0; i < ri->Count; i++) {
            CM_KEY_FAST_INDEX* lh;

            if (is_volatile)
                size = -*(int32_t*)(h->volatile_bins + ri->List[i]);
            else
                size = -*(int32_t*)(h->bins + ri->List[i]);

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List)) {
                kfree(*list);
                return STATUS_REGISTRY_CORRUPT;
            }

            if (is_volatile)
                lh = (CM_KEY_FAST_INDEX*)(h->volatile_bins + ri->List[i] + sizeof(int32_t));
            else
                lh = (CM_KEY_FAST_INDEX*)(h->bins + ri->List[i] + sizeof(int32_t));

            if (lh->Signature != CM_KEY_HASH_LEAF) {
                kfree(*list);
                return STATUS_REGISTRY_CORRUPT;
            }

            if (size < sizeof(int32_t) + offsetof(CM_KEY_FAST_INDEX, List) + (lh->Count * sizeof(CM_INDEX))) {
                kfree(*list);
                return STATUS_REGISTRY_CORRUPT;
            }

            if (lh->Count > count) {
                kfree(*list);
                return STATUS_REGISTRY_CORRUPT;
            }

            memcpy(l, lh->List, lh->Count * sizeof(CM_INDEX));

            l += lh->Count;
            count -= lh->Count;
        }

        return STATUS_SUCCESS;
    } else {
        printk(KERN_INFO "extract_subkey_list: unexpected list type %04x\n", sig);
        return STATUS_INVALID_PARAMETER;
    }
}

static NTSTATUS add_subkey_entry(hive* h, bool is_volatile, CM_INDEX** list, uint32_t count, uint32_t hash,
                                 uint32_t offset, const UNICODE_STRING* us) {
    uint8_t* bins = is_volatile ? h->volatile_bins : h->bins;
    CM_INDEX* lh = *list;
    CM_INDEX* new_lh;
    bool found = false;
    unsigned int i, pos;

    for (i = 0; i < count; i++) {
        int32_t size = -*(int32_t*)(bins + lh[i].Cell);
        uint16_t sig;
        CM_KEY_NODE* kn;

        // FIXME - check not out of bounds

        if (size < sizeof(int32_t) + sizeof(uint16_t))
            return STATUS_REGISTRY_CORRUPT;

        sig = *(uint16_t*)(bins + lh[i].Cell + sizeof(int32_t));

        if (sig != CM_KEY_NODE_SIGNATURE)
            return STATUS_REGISTRY_CORRUPT;

        kn = (CM_KEY_NODE*)(bins + lh[i].Cell + sizeof(int32_t));

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
        pos = count;

    new_lh = kmalloc(sizeof(CM_INDEX) * (count + 1), GFP_KERNEL);
    if (!new_lh)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(new_lh, lh, pos * sizeof(CM_INDEX));

    new_lh[pos].Cell = offset;
    new_lh[pos].HashKey = hash;

    memcpy(&new_lh[pos + 1], &lh[pos], (count - pos) * sizeof(CM_INDEX));

    kfree(*list);
    *list = new_lh;

    return STATUS_SUCCESS;
}

static NTSTATUS write_subkey_list(hive* h, bool is_volatile, CM_INDEX* subkeys, uint32_t count,
                                  uint32_t* list_offset) {
    NTSTATUS Status;
    uint32_t offset;
    CM_KEY_FAST_INDEX* lh;

    static const unsigned int maxnum = (BIN_SIZE - sizeof(HBIN) - sizeof(int32_t) -
                                        offsetof(CM_KEY_FAST_INDEX, List[0])) / sizeof(CM_INDEX);

    if (count > maxnum) {
        unsigned int num_parts = count / maxnum;
        CM_KEY_INDEX* ri;
        uint32_t lh_off, i;

        if ((count % maxnum) != 0)
            num_parts++;

        Status = allocate_cell(h, offsetof(CM_KEY_INDEX, List) + (sizeof(uint32_t) * num_parts),
                               &offset, is_volatile);
        if (!NT_SUCCESS(Status))
            return Status;

        ri = (CM_KEY_INDEX*)((is_volatile ? h->volatile_bins : h->bins) + offset + sizeof(int32_t));

        ri->Signature = CM_KEY_INDEX_ROOT;
        ri->Count = num_parts;

        for (i = 0; i < num_parts; i++) {
            Status = write_subkey_list(h, is_volatile, subkeys, maxnum < count ? maxnum : count, &lh_off);

            ri = (CM_KEY_INDEX*)((is_volatile ? h->volatile_bins : h->bins) + offset + sizeof(int32_t));

            if (!NT_SUCCESS(Status)) {
                unsigned int j;

                free_cell(h, offset, is_volatile);

                for (j = 0; j < i; j++) {
                    free_cell(h, ri->List[j], is_volatile);
                }

                return Status;
            }

            ri->List[i] = lh_off;

            subkeys += maxnum;
            count -= maxnum;
        }

        *list_offset = offset;

        return STATUS_SUCCESS;
    } else {
        Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + (sizeof(CM_INDEX) * count),
                               &offset, is_volatile);
        if (!NT_SUCCESS(Status))
            return Status;

        lh = (CM_KEY_FAST_INDEX*)((is_volatile ? h->volatile_bins : h->bins) + offset + sizeof(int32_t));

        lh->Signature = CM_KEY_HASH_LEAF;
        lh->Count = count;

        memcpy(lh->List, subkeys, count * sizeof(CM_INDEX));

        *list_offset = offset;

        return STATUS_SUCCESS;
    }
}

static void free_subkey_list(hive* h, bool is_volatile, uint32_t subkey_list) {
    int32_t size;
    uint16_t sig;

    // FIXME - check not out of bounds

    if (is_volatile)
        size = -*(int32_t*)(h->volatile_bins + subkey_list);
    else
        size = -*(int32_t*)(h->bins + subkey_list);

    if (size < sizeof(int32_t) + sizeof(uint16_t))
        return;

    if (is_volatile)
        sig = *(uint16_t*)(h->volatile_bins + subkey_list + sizeof(int32_t));
    else
        sig = *(uint16_t*)(h->bins + subkey_list + sizeof(int32_t));

    if (sig == CM_KEY_INDEX_ROOT) {
        CM_KEY_INDEX* ri = (CM_KEY_INDEX*)(h->volatile_bins + subkey_list + sizeof(int32_t));

        if (size >= sizeof(int32_t) + offsetof(CM_KEY_INDEX, List) &&
            size >= sizeof(int32_t) + offsetof(CM_KEY_INDEX, List) + (ri->Count * sizeof(uint32_t))) {
            unsigned int i;

            for (i = 0; i < ri->Count; i++) {
                free_cell(h, ri->List[i], is_volatile);
            }
        }
    }

    free_cell(h, subkey_list, is_volatile);
}

static NTSTATUS create_sub_key(hive* h, uint32_t parent_offset, bool parent_is_volatile, const UNICODE_STRING* us,
                               uint32_t* subkey_offset, bool* subkey_is_volatile, ULONG CreateOptions,
                               bool* created, SECURITY_DESCRIPTOR_RELATIVE* provided_sd,
                               SECURITY_DESCRIPTOR_RELATIVE** ret_sd) {
    NTSTATUS Status;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint32_t hash;
    uint32_t offset, subkey_list;
    uint32_t subkey_count;
    bool is_volatile;

    if (parent_is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + parent_offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h->bins + parent_offset + sizeof(int32_t));

    // open if already exists, and return

    is_volatile = parent_is_volatile;
    Status = find_subkey(h, parent_offset, us, subkey_offset, &is_volatile);

    if (NT_SUCCESS(Status)) {
        *subkey_is_volatile = is_volatile;
        *created = false;
        return Status;
    }

    // FIXME - check SD of kn, and that we would have permission to create subkey

    is_volatile = CreateOptions & REG_OPTION_VOLATILE;

    // don't allow non-volatile keys to be created under volatile parent

    if (!is_volatile && parent_is_volatile)
        return STATUS_CHILD_MUST_BE_VOLATILE;

    // allocate space for new kn

    Status = allocate_cell(h, offsetof(CM_KEY_NODE, Name) + us->Length, &offset, is_volatile);
    if (!NT_SUCCESS(Status))
        return Status;

    if (is_volatile)
        kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
    else
        kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

    kn2->Signature = CM_KEY_NODE_SIGNATURE;
    kn2->Flags = 0;
    kn2->LastWriteTime = 0; // FIXME
    kn2->Spare = 0;
    kn2->Parent = parent_offset;

    if (parent_is_volatile)
        kn2->Parent |= 0x80000000;

    kn2->SubKeyCount = 0;
    kn2->VolatileSubKeyCount = 0;
    kn2->SubKeyList = 0;
    kn2->VolatileSubKeyList = 0;
    kn2->ValuesCount = 0;
    kn2->Values = 0;
    kn2->Security = 0xffffffff;
    kn2->Class = 0; // FIXME
    kn2->MaxNameLen = 0;
    kn2->MaxClassLen = 0;
    kn2->MaxValueNameLen = 0;
    kn2->MaxValueDataLen = 0;
    kn2->WorkVar = 0;
    kn2->NameLength = us->Length;
    kn2->ClassLength = 0; // FIXME
    memcpy(kn2->Name, us->Buffer, us->Length);

    // open kn of parent (checking already done in open_key_in_hive)

    if (parent_is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + parent_offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)h->bins + parent_offset + sizeof(int32_t));

    hash = calc_subkey_hash(us);

    if (kn->Security != 0xffffffff) {
        token_object* tok = muwine_get_current_token();

        Status = allocate_inherited_sk(h, kn->Security, &kn2->Security, tok,
                                       is_volatile, parent_is_volatile, provided_sd,
                                       ret_sd);

        dec_obj_refcount(&tok->header);

        if (!NT_SUCCESS(Status))
            return Status;

        if (parent_is_volatile)
            kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + parent_offset + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h->bins + parent_offset + sizeof(int32_t));
    }

    if (is_volatile) {
        subkey_count = kn->VolatileSubKeyCount;
        subkey_list = kn->VolatileSubKeyList;
    } else {
        subkey_count = kn->SubKeyCount;
        subkey_list = kn->SubKeyList;
    }

    if (subkey_count == 0) {
        CM_KEY_FAST_INDEX* lh;
        uint32_t lh_offset;

        Status = allocate_cell(h, offsetof(CM_KEY_FAST_INDEX, List[0]) + sizeof(CM_INDEX), &lh_offset, is_volatile);
        if (!NT_SUCCESS(Status)) {
            if (kn2->Security != 0xffffffff)
                free_sk(h, kn2->Security, is_volatile);

            free_cell(h, offset, is_volatile);

            return Status;
        }

        if (parent_is_volatile)
            kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + parent_offset + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h->bins + parent_offset + sizeof(int32_t));

        if (is_volatile)
            lh = (CM_KEY_FAST_INDEX*)(h->volatile_bins + lh_offset + sizeof(int32_t));
        else
            lh = (CM_KEY_FAST_INDEX*)(h->bins + lh_offset + sizeof(int32_t));

        lh->Signature = CM_KEY_HASH_LEAF;
        lh->Count = 1;
        lh->List[0].Cell = offset;
        lh->List[0].HashKey = hash;

        if (us->Length > kn->MaxNameLen)
            kn->MaxNameLen = us->Length;

        if (is_volatile) {
            kn->VolatileSubKeyCount = 1;
            kn->VolatileSubKeyList = lh_offset;
        } else {
            kn->SubKeyCount = 1;
            kn->SubKeyList = lh_offset;
        }
    } else {
        int32_t size;
        CM_INDEX* subkeys;
        uint32_t list_offset;

        if (is_volatile)
            size = -*(int32_t*)(h->volatile_bins + subkey_list);
        else
            size = -*(int32_t*)(h->bins + subkey_list);

        if (size < sizeof(int32_t) + sizeof(uint16_t)) {
            if (is_volatile)
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
            else
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

            if (kn2->Security != 0xffffffff)
                free_sk(h, kn2->Security, is_volatile);

            free_cell(h, offset, is_volatile);
            return STATUS_REGISTRY_CORRUPT;
        }

        Status = extract_subkey_list(h, is_volatile, subkey_list, subkey_count, &subkeys);
        if (!NT_SUCCESS(Status)) {
            if (is_volatile)
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
            else
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

            if (kn2->Security != 0xffffffff)
                free_sk(h, kn2->Security, is_volatile);

            free_cell(h, offset, is_volatile);
            return Status;
        }

        Status = add_subkey_entry(h, is_volatile, &subkeys, subkey_count, hash, offset, us);
        if (!NT_SUCCESS(Status)) {
            kfree(subkeys);

            if (is_volatile)
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
            else
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

            if (kn2->Security != 0xffffffff)
                free_sk(h, kn2->Security, is_volatile);

            free_cell(h, offset, is_volatile);
            return Status;
        }

        subkey_count++;

        Status = write_subkey_list(h, is_volatile, subkeys, subkey_count, &list_offset);
        if (!NT_SUCCESS(Status)) {
            kfree(subkeys);

            if (is_volatile)
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
            else
                kn2 = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

            if (kn2->Security != 0xffffffff)
                free_sk(h, kn2->Security, is_volatile);

            free_cell(h, offset, is_volatile);
            return Status;
        }

        kfree(subkeys);

        if (parent_is_volatile)
            kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + parent_offset + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h->bins + parent_offset + sizeof(int32_t));

        free_subkey_list(h, is_volatile, subkey_list);

        if (is_volatile) {
            kn->VolatileSubKeyCount++;
            kn->VolatileSubKeyList = list_offset;
        } else {
            kn->SubKeyCount++;
            kn->SubKeyList = list_offset;
        }

        if (us->Length > kn->MaxNameLen)
            kn->MaxNameLen = us->Length;
    }

    *subkey_offset = offset;
    *subkey_is_volatile = is_volatile;
    *created = true;

    return STATUS_SUCCESS;
}

static NTSTATUS create_key_in_hive(hive* h, const UNICODE_STRING* us, PHANDLE KeyHandle, ULONG CreateOptions,
                                   PULONG Disposition, POBJECT_ATTRIBUTES ObjectAttributes,
                                   ACCESS_MASK DesiredAccess) {
    NTSTATUS Status;
    key_object* k;
    bool is_volatile, created;
    uint32_t offset;
    bool parent_is_volatile;
    UNICODE_STRING part;
    unsigned int i;
    WCHAR* ptr;
    SECURITY_DESCRIPTOR_RELATIVE* sd = NULL;
    ACCESS_MASK access;

    static const WCHAR prefix[] = L"\\Registry\\";

    part.Buffer = us->Buffer;
    part.Length = us->Length;

    for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
        if (us->Buffer[i] == '\\') {
            part.Length = i * sizeof(WCHAR);
            break;
        }
    }

    if (h->depth == 0) {
        offset = h->volatile_root_cell;
        is_volatile = parent_is_volatile = true;
    } else {
        offset = ((HBASE_BLOCK*)h->data)->RootCell;
        is_volatile = parent_is_volatile = false;
    }

    if (us->Length > 0) {
        do {
            unsigned int i;
            bool last_part = part.Buffer + (part.Length / sizeof(WCHAR)) == us->Buffer + (us->Length / sizeof(WCHAR));

            Status = create_sub_key(h, offset, is_volatile, &part, &offset, &is_volatile, CreateOptions,
                                    &created, last_part ? ObjectAttributes->SecurityDescriptor : NULL,
                                    last_part ? &sd : NULL);
            if (!NT_SUCCESS(Status))
                return Status;

            if (last_part)
                break;

            part.Buffer += part.Length / sizeof(WCHAR);
            part.Length = (us->Buffer + (us->Length / sizeof(WCHAR)) - part.Buffer) * sizeof(WCHAR);

            while (part.Length >= sizeof(WCHAR) && part.Buffer[0] == '\\') {
                part.Buffer++;
                part.Length -= sizeof(WCHAR);
            }

            if (part.Length < sizeof(WCHAR))
                break;

            for (i = 0; i < part.Length / sizeof(WCHAR); i++) {
                if (part.Buffer[i] == '\\') {
                    part.Length = i * sizeof(WCHAR);
                    break;
                }
            }

            parent_is_volatile = is_volatile;
        } while (true);
    }

    if (!is_volatile && created)
        h->dirty = true;

    if (CreateOptions & REG_OPTION_CREATE_LINK && created) {
        CM_KEY_NODE* kn;

        if (is_volatile)
            kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)h->bins + offset + sizeof(int32_t));

        kn->Flags |= KEY_SYM_LINK;
    }

    // create object

    k = (key_object*)muwine_alloc_object(sizeof(key_object), key_type, sd);
    if (!k) {
        if (sd)
            kfree(sd);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    k->header.path.Length = k->header.path.MaximumLength = sizeof(prefix) - sizeof(WCHAR) + h->path.Length + us->Length;

    if (h->depth != 0 && us->Length > 0)
        k->header.path.Length += sizeof(WCHAR);

    k->header.path.Buffer = kmalloc(k->header.path.Length, GFP_KERNEL);

    if (!k->header.path.Buffer) {
        dec_obj_refcount(&k->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(k->header.path.Buffer, prefix, sizeof(prefix) - sizeof(WCHAR));
    ptr = &k->header.path.Buffer[(sizeof(prefix) / sizeof(WCHAR)) - 1];

    memcpy(ptr, h->path.Buffer, h->path.Length);
    ptr += h->path.Length / sizeof(WCHAR);

    if (h->depth != 0 && us->Length > 0) {
        *ptr = '\\';
        ptr++;
    }

    memcpy(ptr, us->Buffer, us->Length);

    k->h = h;
    __sync_add_and_fetch(&h->refcount, 1);
    k->offset = offset;
    k->is_volatile = is_volatile;
    k->parent_is_volatile = parent_is_volatile;

    Status = access_check_object(&k->header, DesiredAccess, &access);
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&k->header);
        return Status;
    }

    Status = muwine_add_handle(&k->header, KeyHandle,
                               ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE, access);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&k->header);
        return Status;
    }

    if (Disposition)
        *Disposition = created ? REG_CREATED_NEW_KEY : REG_OPENED_EXISTING_KEY;

    return Status;
}

static NTSTATUS NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex,
                            PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {
    NTSTATUS Status;
    UNICODE_STRING us;
    bool us_alloc = false;
    struct list_head* le;
    WCHAR* oa_us_alloc = NULL;

    static const WCHAR prefix[] = L"\\Registry\\";

    if (!ObjectAttributes || ObjectAttributes->Length < sizeof(OBJECT_ATTRIBUTES) || !ObjectAttributes->ObjectName)
        return STATUS_INVALID_PARAMETER;

    if (ObjectAttributes->RootDirectory) {
        ACCESS_MASK access;
        key_object* key = (key_object*)get_object_from_handle(ObjectAttributes->RootDirectory, &access);

        if (!key)
            return STATUS_INVALID_HANDLE;

        if (key->header.type != key_type) {
            dec_obj_refcount(&key->header);
            return STATUS_INVALID_HANDLE;
        }

        spin_lock(&key->header.header_lock);

        us.Length = key->header.path.Length + sizeof(WCHAR) + ObjectAttributes->ObjectName->Length;
        us.Buffer = oa_us_alloc = kmalloc(us.Length, GFP_KERNEL);

        if (!us.Buffer) {
            spin_unlock(&key->header.header_lock);
            dec_obj_refcount(&key->header);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(us.Buffer, key->header.path.Buffer, key->header.path.Length);
        us.Buffer[key->header.path.Length / sizeof(WCHAR)] = '\\';
        memcpy(&us.Buffer[(key->header.path.Length / sizeof(WCHAR)) + 1], ObjectAttributes->ObjectName->Buffer,
               ObjectAttributes->ObjectName->Length);

        spin_unlock(&key->header.header_lock);

        dec_obj_refcount(&key->header);
    } else {
        us.Length = ObjectAttributes->ObjectName->Length;
        us.Buffer = ObjectAttributes->ObjectName->Buffer;
    }

    // fail if ObjectAttributes->ObjectName doesn't begin with "\\Registry\\";

    if (us.Length < sizeof(prefix) - sizeof(WCHAR) ||
        wcsnicmp(us.Buffer, prefix, (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR))) {
        if (oa_us_alloc)
            kfree(oa_us_alloc);

        return STATUS_OBJECT_PATH_INVALID;
    }

    us.Buffer += (sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR);
    us.Length -= sizeof(prefix) - sizeof(WCHAR);

    while (us.Length >= sizeof(WCHAR) && us.Buffer[(us.Length / sizeof(WCHAR)) - 1] == '\\') {
        us.Length -= sizeof(WCHAR);
    }

    // FIXME - is this right? What if we're opening a symlink, but there's another symlink in the path?
    if (!(CreateOptions & REG_OPTION_CREATE_LINK)) {
        Status = resolve_reg_symlinks(&us, &us_alloc);
        if (!NT_SUCCESS(Status)) {
            if (oa_us_alloc)
                kfree(oa_us_alloc);

            return Status;
        }
    }

    down_read(&hive_list_sem);

    le = hive_list.next;

    while (le != &hive_list) {
        hive* h = list_entry(le, hive, list);

        if (us.Length < h->path.Length) {
            le = le->next;
            continue;
        }

        if (h->depth != 0 && us.Length > h->path.Length && us.Buffer[h->path.Length / sizeof(WCHAR)] != '\\') {
            le = le->next;
            continue;
        }

        if (h->depth == 0 || !wcsnicmp(us.Buffer, h->path.Buffer, h->path.Length / sizeof(WCHAR))) {
            UNICODE_STRING us2;

            us2.Buffer = us.Buffer + (h->path.Length / sizeof(WCHAR));
            us2.Length = us.Length -= h->path.Length;

            while (us2.Length >= sizeof(WCHAR) && us2.Buffer[0] == '\\') {
                us2.Buffer++;
                us2.Length -= sizeof(WCHAR);
            }

            while (us2.Length >= sizeof(WCHAR) && us2.Buffer[(us2.Length / sizeof(WCHAR)) - 1] == '\\') {
                us2.Length -= sizeof(WCHAR);
            }

            down_write(&h->sem);

            Status = create_key_in_hive(h, &us2, KeyHandle, CreateOptions, Disposition,
                                        ObjectAttributes, DesiredAccess);

            up_write(&h->sem);
            up_read(&hive_list_sem);

            if (us_alloc)
                kfree(us.Buffer);

            if (oa_us_alloc)
                kfree(oa_us_alloc);

            return Status;
        }

        le = le->next;
    }

    up_read(&hive_list_sem);

    if (us_alloc)
        kfree(us.Buffer);

    if (oa_us_alloc)
        kfree(oa_us_alloc);

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

    if (oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (us.Buffer)
            kfree(us.Buffer);

        free_object_attributes(&oa);

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateKey(&h, DesiredAccess, &oa, TitleIndex, Class ? &us : NULL, CreateOptions, &dispos);

    if (us.Buffer)
        kfree(us.Buffer);

    free_object_attributes(&oa);

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

NTSTATUS NtDeleteKey(HANDLE KeyHandle) {
    NTSTATUS Status;
    ACCESS_MASK access;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;
    CM_KEY_NODE* kn2;
    uint32_t subkey_count;
    uint32_t subkey_list;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end2;
    }

    if (!(access & DELETE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end2;
    }

    down_write(&key->h->sem);

    if (key->is_volatile)
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + key->offset);
    else
        size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (key->is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + key->offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn->NameLength) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (kn->Flags & (KEY_HIVE_EXIT | KEY_HIVE_ENTRY | KEY_NO_DELETE)) {
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    if (kn->SubKeyCount != 0 || kn->VolatileSubKeyCount != 0) {
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    // get parent kn

    if (key->parent_is_volatile)
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + (kn->Parent & 0x7fffffff));
    else
        size = -*(int32_t*)((uint8_t*)key->h->bins + kn->Parent);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (key->parent_is_volatile)
        kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + (kn->Parent & 0x7fffffff) + sizeof(int32_t));
    else
        kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->bins + kn->Parent + sizeof(int32_t));

    if (kn2->Signature != CM_KEY_NODE_SIGNATURE) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn2->NameLength) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    // get parent's subkey list (volatile or non-volatile)

    if (key->is_volatile) {
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + kn2->VolatileSubKeyList);
        subkey_count = kn2->VolatileSubKeyCount;
        subkey_list = kn2->VolatileSubKeyList;
    } else {
        size = -*(int32_t*)((uint8_t*)key->h->bins + kn2->SubKeyList);
        subkey_count = kn2->SubKeyCount;
        subkey_list = kn2->SubKeyList;
    }

    if (size < sizeof(int32_t) + sizeof(uint16_t)) {
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (subkey_count > 1) {
        CM_INDEX* subkeys;
        uint32_t list_offset;
        unsigned int i;
        bool found = false;

        Status = extract_subkey_list(key->h, key->is_volatile, subkey_list, subkey_count, &subkeys);
        if (!NT_SUCCESS(Status))
            goto end;

        for (i = 0; i < subkey_count; i++) {
            if (subkeys[i].Cell == key->offset) {
                memcpy(&subkeys[i], &subkeys[i+1], sizeof(CM_INDEX) * (subkey_count - i - 1));
                subkey_count--;
                found = true;
                break;
            }
        }

        if (!found) {
            kfree(subkeys);
            Status = STATUS_REGISTRY_CORRUPT;
            goto end;
        }

        Status = write_subkey_list(key->h, key->is_volatile, subkeys, subkey_count, &list_offset);
        if (!NT_SUCCESS(Status)) {
            kfree(subkeys);
            goto end;
        }

        kfree(subkeys);

        if (key->is_volatile)
            kn = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + key->offset + sizeof(int32_t));
        else
            kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

        if (key->parent_is_volatile)
            kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + (kn->Parent & 0x7fffffff) + sizeof(int32_t));
        else
            kn2 = (CM_KEY_NODE*)((uint8_t*)key->h->bins + kn->Parent + sizeof(int32_t));

        if (key->is_volatile) {
            kn2->VolatileSubKeyCount--;
            kn2->VolatileSubKeyList = list_offset;
        } else {
            kn2->SubKeyCount--;
            kn2->SubKeyList = list_offset;
        }
    } else {
        if (key->is_volatile) {
            kn2->VolatileSubKeyCount = 0;
            kn2->VolatileSubKeyList = 0xffffffff;
        } else {
            kn2->SubKeyCount = 0;
            kn2->SubKeyList = 0xffffffff;
        }
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
        update_symlink_cache(&key->header.path, NULL, 0);

    free_subkey_list(key->h, key->is_volatile, subkey_list);

    if (kn->Security != 0xffffffff)
        free_sk(key->h, kn->Security, key->is_volatile);

    free_cell(key->h, key->offset, key->is_volatile);

    // FIXME - update MaxNameLen in parent if necessary

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status))
        key->h->dirty = true;

    up_write(&key->h->sem);

end2:
    dec_obj_refcount(&key->header);

    return Status;
}

static unsigned int count_backslashes(UNICODE_STRING* us) {
    unsigned int i;
    unsigned int bs = 0;

    for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
        if (us->Buffer[i] == '\\')
            bs++;
    }

    return bs;
}

static NTSTATUS NtLoadKey(POBJECT_ATTRIBUTES DestinationKeyName, POBJECT_ATTRIBUTES HiveFileName) {
    NTSTATUS Status;
    hive* h;
    UNICODE_STRING us;
    struct list_head* le;
    HANDLE fh;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;
    uint64_t pos;
    ACCESS_MASK access;
    object_header* fileobj;
    UNICODE_STRING fs_path;

    static const WCHAR prefix[] = L"\\Registry\\";

    fs_path.Length = fs_path.MaximumLength = 0;
    fs_path.Buffer = NULL;

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

    Status = NtOpenFile(&fh, SYNCHRONIZE | FILE_READ_DATA, HiveFileName, &iosb, 0,
                        FILE_SYNCHRONOUS_IO_ALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status))
        return Status;

    h = kzalloc(sizeof(hive), GFP_KERNEL);
    if (!h) {
        NtClose(fh);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    h->path.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!h->path.Buffer) {
        NtClose(fh);
        kfree(h);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(h->path.Buffer, us.Buffer, us.Length);
    h->path.Length = h->path.MaximumLength = us.Length;

    h->depth = count_backslashes(&us) + 1;

//     h->file_mode = f->f_inode->i_mode; // FIXME

    Status = NtQueryInformationFile(fh, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        NtClose(fh);
        kfree(h->path.Buffer);
        kfree(h);
        return Status;
    }

    h->size = fsi.EndOfFile.QuadPart;

    if (h->size == 0) {
        NtClose(fh);
        kfree(h->path.Buffer);
        kfree(h);
        return STATUS_REGISTRY_CORRUPT;
    }

    h->data = vmalloc(h->size);
    if (!h->data) {
        NtClose(fh);
        kfree(h->path.Buffer);
        kfree(h);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pos = 0;

    while (pos < h->size) {
        Status = NtReadFile(fh, NULL, NULL, NULL, &iosb, (uint8_t*)h->data + pos, h->size - pos, NULL, NULL);
        if (!NT_SUCCESS(Status)) {
            NtClose(fh);
            vfree(h->data);
            kfree(h->path.Buffer);
            kfree(h);
            return Status;
        }

        pos += iosb.Information;
    }

    fileobj = get_object_from_handle(fh, &access);

    // FIXME - make sure file opened RW

    spin_lock(&fileobj->header_lock);

    if (fileobj->path.Length > 0) {
        fs_path.Buffer = kmalloc(fileobj->path.Length, GFP_KERNEL);
        if (!fs_path.Buffer) {
            spin_unlock(&fileobj->header_lock);
            dec_obj_refcount(fileobj);
            vfree(h->data);
            kfree(h->path.Buffer);
            kfree(h);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(fs_path.Buffer, fileobj->path.Buffer, fileobj->path.Length);

        fs_path.Length = fs_path.MaximumLength = fileobj->path.Length;
    }

    spin_unlock(&fileobj->header_lock);
    dec_obj_refcount(fileobj);

    NtClose(fh);

    if (!hive_is_valid(h)) {
        vfree(h->data);
        kfree(h->path.Buffer);
        kfree(h);

        if (fs_path.Buffer)
            kfree(fs_path.Buffer);

        return STATUS_REGISTRY_CORRUPT;
    }

    Status = init_hive(h);
    if (!NT_SUCCESS(Status)) {
        vfree(h->data);
        kfree(h->path.Buffer);
        kfree(h);

        if (fs_path.Buffer)
            kfree(fs_path.Buffer);

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

        if (parent_hive->depth != 0 && h->path.Buffer[parent_hive->path.Length / sizeof(WCHAR)] != '\\') {
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

                if (fs_path.Buffer)
                    kfree(fs_path.Buffer);

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

                if (fs_path.Buffer)
                    kfree(fs_path.Buffer);

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

            {
                ULONG as_len;

                if (NT_SUCCESS(utf16_to_utf8(NULL, 0, &as_len, fs_path.Buffer, fs_path.Length))) {
                    char* s;

                    s = kmalloc(as_len + 1, GFP_KERNEL);
                    if (s) {
                        if (NT_SUCCESS(utf16_to_utf8(s, as_len, &as_len, fs_path.Buffer, fs_path.Length))) {
                            s[as_len] = 0;

                            printk(KERN_INFO "NtLoadKey: loaded hive at %s\n", s);
                        }

                        kfree(s);
                    }
                }
            }

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

            if (h->fs_path.Length > 0) {
                ULONG as_len;

                if (NT_SUCCESS(utf16_to_utf8(NULL, 0, &as_len, h->fs_path.Buffer, h->fs_path.Length))) {
                    char* s;

                    s = kmalloc(as_len + 1, GFP_KERNEL);
                    if (s) {
                        if (NT_SUCCESS(utf16_to_utf8(s, as_len, &as_len, h->fs_path.Buffer, h->fs_path.Length))) {
                            s[as_len] = 0;

                            printk(KERN_INFO "NtUnloadKey: unloaded hive at %s\n", s);
                        }

                        kfree(s);
                    }
                }
            }

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

    free_object_attributes(&oa);

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
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    unsigned int sdlen;
    CM_KEY_SECURITY* sk;
    UNICODE_STRING us;

    static const WCHAR key_name[] = L"Key";

    us.Length = us.MaximumLength = sizeof(key_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)key_name;

    key_type = muwine_add_object_type(&us, key_object_close, NULL, KEY_GENERIC_READ,
                                      KEY_GENERIC_WRITE, KEY_GENERIC_EXECUTE,
                                      KEY_ALL_ACCESS, KEY_ALL_ACCESS);
    if (IS_ERR(key_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)key_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)key_type);
    }

    h = kzalloc(sizeof(hive), GFP_KERNEL);
    if (!h)
        return STATUS_INSUFFICIENT_RESOURCES;

    INIT_LIST_HEAD(&h->holes);
    init_rwsem(&h->sem);
    INIT_LIST_HEAD(&h->volatile_holes);
    h->volatile_sk = 0xffffffff;

    Status = allocate_cell(h, offsetof(CM_KEY_NODE, Name[0]), &offset, true);
    if (!NT_SUCCESS(Status)) {
        kfree(h);
        return Status;
    }

    kn = (CM_KEY_NODE*)((uint8_t*)h->volatile_bins + offset + sizeof(int32_t));

    kn->Signature = CM_KEY_NODE_SIGNATURE;
    kn->Flags = KEY_HIVE_ENTRY;
    kn->LastWriteTime = 0;
    kn->Spare = 0;
    kn->Parent = 0;
    kn->SubKeyCount = 0;
    kn->VolatileSubKeyCount = 0;
    kn->SubKeyList = 0;
    kn->VolatileSubKeyList = 0;
    kn->ValuesCount = 0;
    kn->Values = 0;
    kn->Security = 0xffffffff; // FIXME
    kn->Class = 0;
    kn->MaxNameLen = 0;
    kn->MaxClassLen = 0;
    kn->MaxValueNameLen = 0;
    kn->MaxValueDataLen = 0;
    kn->WorkVar = 0;
    kn->NameLength = 0;
    kn->ClassLength = 0;

    h->volatile_root_cell = offset;

    // get root SD

    muwine_registry_root_sd(&sd, &sdlen);

    Status = allocate_cell(h, offsetof(CM_KEY_SECURITY, Descriptor) + sdlen, &kn->Security, true);
    if (!NT_SUCCESS(Status)) {
        kfree(h->volatile_bins);
        kfree(h);
        kfree(sd);
        return Status;
    }

    sk = (CM_KEY_SECURITY*)((uint8_t*)h->volatile_bins + kn->Security + sizeof(int32_t));
    sk->Signature = CM_KEY_SECURITY_SIGNATURE;
    sk->Reserved = 0;
    sk->Flink = sk->Blink = kn->Security;
    sk->ReferenceCount = 1;
    sk->DescriptorLength = sdlen;
    memcpy(sk->Descriptor, sd, sdlen);

    h->volatile_sk = kn->Security;

    kfree(sd);

    down_write(&hive_list_sem);

    list_add_tail(&h->list, &hive_list);

    up_write(&hive_list_sem);

    Status = init_flush_thread();
    if (!NT_SUCCESS(Status))
        return Status;

    register_reboot_notifier(&reboot_notifier);

    return STATUS_SUCCESS;
}

static NTSTATUS get_temp_hive_path(hive* h, UNICODE_STRING* out) {
    UNICODE_STRING us;

    static const WCHAR suffix[] = L".tmp";

    // FIXME - also prepend dot, so that file is hidden

    us.Length = h->fs_path.Length + sizeof(suffix) - sizeof(WCHAR);
    us.Buffer = kmalloc(us.Length, GFP_KERNEL);
    if (!us.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(us.Buffer, h->fs_path.Buffer, h->fs_path.Length);
    memcpy(&us.Buffer[h->fs_path.Length / sizeof(WCHAR)], suffix, sizeof(suffix) - sizeof(WCHAR));

    *out = us;

    return STATUS_SUCCESS;
}

static NTSTATUS flush_hive(hive* h) {
    NTSTATUS Status;
    LARGE_INTEGER pos;
    HBASE_BLOCK* base_block;
    unsigned int i;
    uint32_t csum;
    UNICODE_STRING temp_fn;
    HANDLE fh;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES objatt;
    ULONG frilen;
    FILE_RENAME_INFORMATION* fri;

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

    Status = get_temp_hive_path(h, &temp_fn);
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "flush_hive: unable to get temporary filename for hive\n");
        up_read(&h->sem);
        return Status;
    }

    objatt.Length = sizeof(objatt);
    objatt.RootDirectory = NULL;
    objatt.ObjectName = &temp_fn;
    objatt.Attributes = OBJ_KERNEL_HANDLE;
    objatt.SecurityDescriptor = NULL;
    objatt.SecurityQualityOfService = NULL;

    // FIXME - AllocationSize
    Status = NtCreateFile(&fh, FILE_WRITE_DATA | DELETE, &objatt, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "flush_hive: error %08x when opening file for writing\n", Status);
        up_read(&h->sem);
        kfree(temp_fn.Buffer);
        return Status;
    }

    kfree(temp_fn.Buffer);

    pos.QuadPart = 0;

    while (pos.QuadPart < h->size) {
        Status = NtWriteFile(fh, NULL, NULL, NULL, &iosb, (uint8_t*)h->data + pos.QuadPart,
                             h->size - pos.QuadPart, &pos, NULL);
        if (!NT_SUCCESS(Status)) {
            printk(KERN_ALERT "flush_hive: error %08x when writing file\n", Status);
            // FIXME - delete file
            NtClose(fh);
            up_read(&h->sem);
            return Status;
        }

        pos.QuadPart += iosb.Information;
    }

    frilen = offsetof(FILE_RENAME_INFORMATION, FileName) + h->fs_path.Length;

    fri = kmalloc(frilen, GFP_KERNEL);
    if (!fri) {
        // FIXME - delete file
        NtClose(fh);
        up_read(&h->sem);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    fri->ReplaceIfExists = true;
    fri->RootDirectory = NULL;
    fri->FileNameLength = h->fs_path.Length;
    memcpy(fri->FileName, h->fs_path.Buffer, h->fs_path.Length);

    Status = NtSetInformationFile(fh, &iosb, fri, frilen, FileRenameInformation);
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "flush_hive: error %08x when renaming file\n", Status);
        // FIXME - delete file
        NtClose(fh);
        up_read(&h->sem);
        kfree(fri);
        return Status;
    }

    kfree(fri);

    NtClose(fh);

    // FIXME - preserve uid, gid, mode, and extended attributes

    h->dirty = false;

    up_read(&h->sem);

    return STATUS_SUCCESS;
}

NTSTATUS NtFlushKey(HANDLE KeyHandle) {
    NTSTATUS Status;
    ACCESS_MASK access;
    key_object* key;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        dec_obj_refcount(&key->header);
        return STATUS_INVALID_HANDLE;
    }

    Status = flush_hive(key->h);

    dec_obj_refcount(&key->header);

    return Status;
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

static NTSTATUS NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                           ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ACCESS_MASK access;
    key_object* key;
    int32_t size;
    CM_KEY_NODE* kn;

    key = (key_object*)get_object_from_handle(KeyHandle, &access);
    if (!key)
        return STATUS_INVALID_HANDLE;

    if (key->header.type != key_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (KeyInformationClass != KeyNameInformation && KeyInformationClass != KeyHandleTagsInformation &&
        !(access & KEY_QUERY_VALUE)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    down_read(&key->h->sem);

    if (key->is_volatile)
        size = -*(int32_t*)((uint8_t*)key->h->volatile_bins + key->offset);
    else
        size = -*(int32_t*)((uint8_t*)key->h->bins + key->offset);

    if (size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0])) {
        up_read(&key->h->sem);
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    if (key->is_volatile)
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->volatile_bins + key->offset + sizeof(int32_t));
    else
        kn = (CM_KEY_NODE*)((uint8_t*)key->h->bins + key->offset + sizeof(int32_t));

    if (kn->Signature != CM_KEY_NODE_SIGNATURE || size < sizeof(int32_t) + offsetof(CM_KEY_NODE, Name[0]) + kn->NameLength) {
        up_read(&key->h->sem);
        Status = STATUS_REGISTRY_CORRUPT;
        goto end;
    }

    Status = query_key_info(KeyInformationClass, KeyInformation, kn, Length, ResultLength);

    up_read(&key->h->sem);

end:
    dec_obj_refcount(&key->header);

    return Status;
}

NTSTATUS user_NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation,
                         ULONG Length, PULONG ResultLength) {
    NTSTATUS Status;
    ULONG reslen = 0;
    void* buf;

    if ((uintptr_t)KeyHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtQueryKey(KeyHandle, KeyInformationClass, buf, Length, &reslen);

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
        if (buf) {
            if (copy_to_user(KeyInformation, buf, min(Length, reslen)) != 0)
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

NTSTATUS NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {
    printk(KERN_INFO "NtSaveKey(%lx, %lx): stub\n", (uintptr_t)KeyHandle, (uintptr_t)FileHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                           PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchSubtree,
                           PVOID ChangeBuffer, ULONG Length, BOOLEAN Asynchronous) {
    printk(KERN_INFO "NtNotifyChangeKey(%lx, %lx, %p, %p, %p, %x, %x, %p, %x, %x): stub\n",
           (uintptr_t)KeyHandle, (uintptr_t)Event, ApcRoutine, ApcContext, IoStatusBlock,
           CompletionFilter, WatchSubtree, ChangeBuffer, Length, Asynchronous);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects,
                                    HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                    PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter,
                                    BOOLEAN WatchSubtree, PVOID ChangeBuffer, ULONG Length,
                                    BOOLEAN Asynchronous) {
    printk(KERN_INFO "NtNotifyChangeMultipleKeys(%lx, %x, %p, %lx, %p, %p, %p, %x, %x, %p, %x, %x): stub\n",
           (uintptr_t)KeyHandle, Count, SubordinateObjects, (uintptr_t)Event, ApcRoutine,
           ApcContext, IoStatusBlock, CompletionFilter, WatchSubtree, ChangeBuffer,
           Length, Asynchronous);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
