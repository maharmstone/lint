#include <linux/kthread.h>
#include "muwine.h"
#include "proc.h"
#include "sec.h"

type_object* process_type = NULL;

static LIST_HEAD(process_list);
static DEFINE_SPINLOCK(process_list_lock);

static LIST_HEAD(dead_process_list);
static DEFINE_SPINLOCK(dead_process_list_lock);
static struct task_struct* proc_reaper_thread = NULL;
static bool proc_reaper_thread_running = true;

static void process_object_close(object_header* obj) {
    process_object* p = (process_object*)obj;

    dec_obj_refcount(&p->token->header);

    spin_lock(&process_list_lock);
    list_del(&p->list);
    spin_unlock(&process_list_lock);
}

process_object* muwine_current_process_object(void) {
    struct list_head* le;
    pid_t pid = task_tgid_vnr(current);

    spin_lock(&process_list_lock);

    le = process_list.next;

    while (le != &process_list) {
        process_object* obj = list_entry(le, process_object, list);

        if (obj->pid == pid) {
            inc_obj_refcount(&obj->header.h);
            spin_unlock(&process_list_lock);

            return obj;
        }

        le = le->next;
    }

    spin_unlock(&process_list_lock);

    return NULL;
}

NTSTATUS muwine_add_current_process(void) {
    NTSTATUS Status;
    struct list_head* le;
    process_object* obj;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    token_object* tok;

    Status = muwine_make_process_token(&tok);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = muwine_create_sd(NULL, NULL, tok, &process_type->generic_mapping,
                              0, false, &sd, NULL);
    if (!NT_SUCCESS(Status)) {
        if (tok)
            dec_obj_refcount(&tok->header);

        return Status;
    }

    obj = (process_object*)muwine_alloc_object(sizeof(process_object), process_type, sd);
    if (!obj) {
        kfree(sd);

        if (tok)
            dec_obj_refcount(&tok->header);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    obj->pid = task_tgid_vnr(current);

    INIT_LIST_HEAD(&obj->handle_list);
    spin_lock_init(&obj->handle_list_lock);
    obj->next_handle_no = MUW_FIRST_HANDLE + 4;

    obj->token = tok;

    init_rwsem(&obj->mapping_list_sem);
    INIT_LIST_HEAD(&obj->mapping_list);

    spin_lock(&process_list_lock);

    le = process_list.next;

    while (le != &process_list) {
        process_object* obj2 = list_entry(le, process_object, list);

        if (obj2->pid == obj->pid) {
            spin_unlock(&process_list_lock);
            dec_obj_refcount(&obj->token->header);
            free_object(&obj->header.h);
            return STATUS_SUCCESS;
        }

        le = le->next;
    }

    list_add_tail(&obj->list, &process_list);

    spin_unlock(&process_list_lock);

    return STATUS_SUCCESS;
}

static void reap_process(process_object* obj) {
    // force remove mappings of any sections

    while (!list_empty(&obj->mapping_list)) {
        section_map* sm = list_entry(obj->mapping_list.next, section_map, list);

        list_del(&sm->list);

        if (sm->sect)
            dec_obj_refcount(sm->sect);

        kfree(sm);
    }

    // force close of all open handles

    while (!list_empty(&obj->handle_list)) {
        handle* hand = list_entry(obj->handle_list.next, handle, list);

        list_del(&hand->list);

        if (__sync_sub_and_fetch(&hand->object->handle_count, 1) == 0)
            object_cleanup(hand->object);

        dec_obj_refcount(hand->object);

        kfree(hand);
    }
}

static int proc_reaper_thread_func(void* data) {
    while (proc_reaper_thread_running) {
        set_current_state(TASK_INTERRUPTIBLE);

        schedule(); // yield

        while (true) {
            process_object* obj = NULL;

            spin_lock(&dead_process_list_lock);

            if (!list_empty(&dead_process_list)) {
                obj = list_entry(dead_process_list.next, process_object, dead_list);
                list_del(&obj->dead_list);
            }

            spin_unlock(&dead_process_list_lock);

            if (obj) {
                reap_process(obj);
                dec_obj_refcount(&obj->header.h);
            } else
                break;
        }
    }

    set_current_state(TASK_RUNNING);

    do_exit(0);
}

int muwine_group_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    pid_t pid = task_tgid_vnr(current);
    struct list_head* le;
    process_object* obj = NULL;

    // skip kernel threads
    if (!current->mm)
        return 1;

    // find process_object

    spin_lock(&process_list_lock);

    le = process_list.next;

    while (le != &process_list) {
        process_object* obj2 = list_entry(le, process_object, list);

        if (obj2->pid == pid) {
            obj = obj2;
            break;
        }

        le = le->next;
    }

    spin_unlock(&process_list_lock);

    if (!obj)
        return 0;

    spin_lock(&dead_process_list_lock);
    list_add(&obj->dead_list, &dead_process_list);
    wake_up_process(proc_reaper_thread);
    spin_unlock(&dead_process_list_lock);

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
    NTSTATUS Status;
    long retval;
    struct list_head* le;
    process_object* obj = muwine_current_process_object();
    process_object* new_obj;
    SECURITY_DESCRIPTOR_RELATIVE* sd;

    if (!obj)
        return 0;

    retval = regs_return_value(regs);

    if (retval < 0) { // fork failed
        dec_obj_refcount(&obj->header.h);
        return 0;
    }

    spin_lock(&obj->header.h.header_lock);

    if (obj->header.h.sd)
        Status = copy_sd(obj->header.h.sd, &sd);
    else {
        sd = NULL;
        Status = STATUS_SUCCESS;
    }

    spin_unlock(&obj->header.h.header_lock);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return 0;
    }

    new_obj = (process_object*)muwine_alloc_object(sizeof(process_object), process_type, NULL);
    if (!new_obj) {
        printk(KERN_ERR "muwine fork_handler: out of memory\n");

        if (sd)
            kfree(sd);

        dec_obj_refcount(&obj->header.h);
        return 0;
    }

    if (new_obj->header.h.sd)
        kfree(new_obj->header.h.sd);

    new_obj->header.h.sd = sd;

    new_obj->pid = retval;

    new_obj->token = duplicate_token(obj->token);

    init_rwsem(&new_obj->mapping_list_sem);
    INIT_LIST_HEAD(&new_obj->mapping_list);
    // FIXME - duplicate mappings

    INIT_LIST_HEAD(&new_obj->handle_list);
    spin_lock_init(&new_obj->handle_list_lock);

    spin_lock(&obj->handle_list_lock);
    new_obj->next_handle_no = obj->next_handle_no;

    // duplicate handles

    le = obj->handle_list.next;

    while (le != &obj->handle_list) {
        handle* h = list_entry(le, handle, list);
        handle* h2;

        duplicate_handle(h, &h2);
        list_add_tail(&h2->list, &new_obj->handle_list);

        le = le->next;
    }

    spin_unlock(&obj->handle_list_lock);

    spin_lock(&process_list_lock);
    list_add_tail(&new_obj->list, &process_list);
    spin_unlock(&process_list_lock);

    dec_obj_refcount(&obj->header.h);

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

    proc_reaper_thread = kthread_run(proc_reaper_thread_func, NULL, "muwine_proc_reap");

    if (!proc_reaper_thread) {
        printk(KERN_ALERT "muwine failed to create process reaper thread\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

void muwine_free_proc(void) {
    if (proc_reaper_thread) {
        proc_reaper_thread_running = false;
        wake_up_process(proc_reaper_thread);
    }
}

NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask,
                       POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    printk(KERN_INFO "NtOpenProcess(%px, %x, %px, %px): stub\n", ProcessHandle,
           AccessMask, ObjectAttributes, ClientId);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle,
                                   PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                   PVOID ProcessInformation, ULONG ProcessInformationLength,
                                   PULONG ReturnLength) {
    printk(KERN_INFO "NtQueryInformationProcess(%lx, %x, %px, %x, %px): stub\n",
           (uintptr_t)ProcessHandle, ProcessInformationClass, ProcessInformation,
           ProcessInformationLength, ReturnLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle,
                                 PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                 PVOID ProcessInformation, ULONG ProcessInformationLength) {
    printk(KERN_INFO "NtSetInformationProcess(%lx, %x, %px, %x): stub\n",
           (uintptr_t)ProcessHandle, ProcessInformationClass, ProcessInformation,
           ProcessInformationLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    printk(KERN_INFO "NtTerminateProcess(%lx, %x): stub\n", (uintptr_t)ProcessHandle,
           ExitStatus);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSuspendProcess(HANDLE ProcessHandle) {
    printk(KERN_INFO "NtSuspendProcess(%lx): stub\n", (uintptr_t)ProcessHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtResumeProcess(HANDLE ProcessHandle) {
    printk(KERN_INFO "NtResumeProcess(%lx): stub\n", (uintptr_t)ProcessHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
                             ACCESS_MASK ProcessDesiredAccess,
                             ACCESS_MASK ThreadDesiredAccess,
                             POBJECT_ATTRIBUTES ProcessObjectAttributes,
                             POBJECT_ATTRIBUTES ThreadObjectAttributes,
                             ULONG ProcessFlags, ULONG ThreadFlags,
                             PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                             PPS_CREATE_INFO CreateInfo,
                             PPS_ATTRIBUTE_LIST AttributeList) {
    printk(KERN_INFO "NtCreateUserProcess(%px, %px, %x, %x, %px, %px, %x, %x, %px, %px, %px): stub\n",
           ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
           ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags,
           ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
