#include "muwine.h"

#define PROCESS_TERMINATE                   0x0001
#define PROCESS_CREATE_THREAD               0x0002
#define PROCESS_SET_SESSIONID               0x0004
#define PROCESS_VM_OPERATION                0x0008
#define PROCESS_VM_READ                     0x0010
#define PROCESS_VM_WRITE                    0x0020
#define PROCESS_DUP_HANDLE                  0x0040
#define PROCESS_CREATE_PROCESS              0x0080
#define PROCESS_SET_QUOTA                   0x0100
#define PROCESS_SET_INFORMATION             0x0200
#define PROCESS_QUERY_INFORMATION           0x0400
#define PROCESS_SUSPEND_RESUME              0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION   0x1000
#define PROCESS_SET_LIMITED_INFORMATION     0x2000
#define PROCESS_RESERVED1                   0x4000
#define PROCESS_RESERVED2                   0x8000

#define PROCESS_GENERIC_READ PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | READ_CONTROL

#define PROCESS_GENERIC_WRITE PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | \
                              PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | \
                              PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME | READ_CONTROL

#define PROCESS_GENERIC_EXECUTE PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | \
                                READ_CONTROL | SYNCHRONIZE

#define PROCESS_ALL_ACCESS PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | \
                           PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | \
                           PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | \
                           PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | \
                           PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION | \
                           PROCESS_SET_LIMITED_INFORMATION | PROCESS_RESERVED1 | \
                           PROCESS_RESERVED2 | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | \
                           SYNCHRONIZE

typedef struct {
    sync_object header;
} process_object;

static type_object* process_type = NULL;

static LIST_HEAD(pid_list);
static DEFINE_SPINLOCK(pid_list_lock);

static void process_object_close(object_header* obj) {
    process_object* p = (process_object*)obj;

    free_object(&p->header.h);
}

process* muwine_current_process(void) {
    struct list_head* le;
    pid_t pid = task_tgid_vnr(current);

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == pid) {
            spin_unlock(&pid_list_lock);

            return p2;
        }

        le = le->next;
    }

    spin_unlock(&pid_list_lock);

    return NULL;
}

void muwine_add_current_process(void) {
    process* p;
    struct list_head* le;
    bool found = false;

    p = kzalloc(sizeof(process), GFP_KERNEL);

    p->pid = task_tgid_vnr(current);
    p->refcount = 1;
    INIT_LIST_HEAD(&p->handle_list);
    spin_lock_init(&p->handle_list_lock);
    p->next_handle_no = MUW_FIRST_HANDLE + 4;
    muwine_make_process_token(&p->token);
    init_rwsem(&p->mapping_list_sem);
    INIT_LIST_HEAD(&p->mapping_list);

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == p->pid) {
            found = true;
            break;
        }

        le = le->next;
    }

    if (!found)
        list_add_tail(&p->list, &pid_list);
    else
        kfree(p);

    spin_unlock(&pid_list_lock);
}

int muwine_group_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    pid_t pid = task_tgid_vnr(current);
    struct list_head* le;
    process* p = NULL;
    bool found = false;

    // skip kernel threads
    if (!current->mm)
        return 1;

    // remove pid from process list

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == pid) {
            p2->refcount--;
            found = true;

            if (p2->refcount == 0) {
                list_del(&p2->list);
                p = p2;
            }

            break;
        }

        le = le->next;
    }

    spin_unlock(&pid_list_lock);

    if (p) {
        // force remove mappings of any sections

        while (!list_empty(&p->mapping_list)) {
            section_map* sm = list_entry(p->mapping_list.next, section_map, list);

            list_del(&sm->list);

            if (sm->sect)
                dec_obj_refcount(sm->sect);

            kfree(sm);
        }

        // force close of all open handles

        while (!list_empty(&p->handle_list)) {
            handle* hand = list_entry(p->handle_list.next, handle, list);

            list_del(&hand->list);

            if (__sync_sub_and_fetch(&hand->object->handle_count, 1) == 0) {
                if (hand->object->type->cleanup)
                    hand->object->type->cleanup(hand->object);
            }

            dec_obj_refcount(hand->object);

            kfree(hand);
        }

        muwine_free_token(p->token);

        kfree(p);
    }

    return 0;
}

static void duplicate_handle(handle* old, handle** new) {
    handle* h = kzalloc(sizeof(handle), GFP_KERNEL); // FIXME - handle malloc failure

    h->object = old->object;
    h->object->refcount++;
    h->object->handle_count++;

    h->number = old->number;

    *new = h;
}

int muwine_fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    long retval;
    struct list_head* le;
    process* p = NULL;
    process* new_p = NULL;
    pid_t pid = task_tgid_vnr(current);

    // FIXME - should we be doing this for the clone syscall as well?

    retval = regs_return_value(regs);

    if (retval < 0) // fork failed
        return 0;

    spin_lock(&pid_list_lock);

    le = pid_list.next;

    while (le != &pid_list) {
        process* p2 = list_entry(le, process, list);

        if (p2->pid == pid) {
            p = p2;
            break;
        }

        le = le->next;
    }

    if (!p) {
        spin_unlock(&pid_list_lock);
        return 0;
    }

    spin_lock(&p->handle_list_lock);

    if (list_empty(&p->handle_list)) {
        spin_unlock(&p->handle_list_lock);
        spin_unlock(&pid_list_lock);
        return 0;
    }

    new_p = kzalloc(sizeof(process), GFP_KERNEL);
    if (!new_p) {
        printk(KERN_ERR "muwine fork_handler: out of memory\n");
        spin_unlock(&p->handle_list_lock);
        spin_unlock(&pid_list_lock);
        return 0;
    }

    new_p->pid = retval;
    new_p->refcount = 1;
    INIT_LIST_HEAD(&new_p->handle_list);
    spin_lock_init(&new_p->handle_list_lock);
    new_p->next_handle_no = p->next_handle_no;
    muwine_duplicate_token(p->token, &new_p->token);
    init_rwsem(&new_p->mapping_list_sem);
    INIT_LIST_HEAD(&new_p->mapping_list);

    // duplicate handles

    le = p->handle_list.next;

    while (le != &p->handle_list) {
        handle* h = list_entry(le, handle, list);
        handle* h2;

        duplicate_handle(h, &h2);
        list_add_tail(&h2->list, &new_p->handle_list);

        le = le->next;
    }

    spin_unlock(&p->handle_list_lock);

    list_add_tail(&new_p->list, &pid_list);

    spin_unlock(&pid_list_lock);

    return 0;
}

NTSTATUS muwine_init_processes(void) {
    UNICODE_STRING us;

    static const WCHAR process_name[] = L"Process";

    us.Length = us.MaximumLength = sizeof(process_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)process_name;

    process_type = muwine_add_object_type(&us, process_object_close, NULL,
                                          PROCESS_GENERIC_READ, PROCESS_GENERIC_WRITE,
                                          PROCESS_GENERIC_EXECUTE, PROCESS_ALL_ACCESS,
                                          PROCESS_ALL_ACCESS);
    if (IS_ERR(process_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)process_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)process_type);
    }

    return STATUS_SUCCESS;
}
