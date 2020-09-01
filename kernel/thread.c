#include "muwine.h"
#include "thread.h"
#include <linux/kthread.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>
#include <linux/fdtable.h>

void (*_put_files_struct)(struct files_struct* files);
void (*_detach_pid)(struct task_struct* task, enum pid_type type);
void (*_ptrace_notify)(int exit_code);

static LIST_HEAD(thread_list);
static DEFINE_SPINLOCK(thread_list_lock);

static type_object* thread_type = NULL;

static int thread_start(void* arg) {
    thread_start_context* ctx = arg;
    uint64_t cs, ds;
    CONTEXT regs;

    current->mm = current->active_mm = ctx->mm;

    // FIXME - put current->sighand?
    current->sighand = ctx->sighand;

    if (current->files)
        _put_files_struct(current->files);

    current->files = ctx->files;

    cs = __USER_CS;
    ds = __USER_DS;

    // FIXME - allocate and populate TEB, and set in gs

    memcpy(&regs, &ctx->thread_context, sizeof(CONTEXT));

    complete(&ctx->thread_created);

    // FIXME - wait here if CreateSuspended not set

    asm volatile(
        "lea %0, %%rax\n\t"
        "mov 0x80(%%rax), %%rcx\n\t"
        "mov 0x88(%%rax), %%rdx\n\t"
        "mov 0x90(%%rax), %%rbx\n\t"
        "mov 0xa8(%%rax), %%rsi\n\t"
        "mov 0xb0(%%rax), %%rdi\n\t"
        "mov 0xb8(%%rax), %%r8\n\t"
        "mov 0xc0(%%rax), %%r9\n\t"
        "mov 0xc8(%%rax), %%r10\n\t"
        "mov 0xd0(%%rax), %%r11\n\t"
        "mov 0xd8(%%rax), %%r12\n\t"
        "mov 0xe0(%%rax), %%r13\n\t"
        "mov 0xe8(%%rax), %%r14\n\t"
        "mov 0xf0(%%rax), %%r15\n\t"
        "cli\n\t"
        "push $0x2b\n\t"                // push new SS
        "push 0x98(%%rax)\n\t"          // push new RSP
        "pushfq\n\t"                    // push RFLAGS
        "orq $0x3000, (%%rsp)\n\t"      // change IOPL to ring 3
        "orq $0x200, (%%rsp)\n\t"       // re-enable interrupts in usermode
        "push $0x33\n\t"                // push new CS
        "push 0xf8(%%rax)\n\t"          // push new RIP
        "mov 0xa0(%%rax), %%rbp\n\t"
        "mov 0x78(%%rax), %%rax\n\t"
        "swapgs\n\t"
        "iretq\n\t"
        :
        : "m" (regs)
    );

    // doesn't return

    return 0;
}

static void _ptrace_event(int event, unsigned long message) {
    if (unlikely(ptrace_event_enabled(current, event))) {
        current->ptrace_message = message;
        _ptrace_notify((event << 8) | SIGTRAP);
    } else if (event == PTRACE_EVENT_EXEC) {
        if ((current->ptrace & (PT_PTRACED|PT_SEIZED)) == PT_PTRACED)
            send_sig(SIGTRAP, current, 0);
    }
}

static void _ptrace_event_pid(int event, struct pid* pid) {
    unsigned long message = 0;
    struct pid_namespace *ns;

    rcu_read_lock();
    ns = task_active_pid_ns(rcu_dereference(current->parent));
    if (ns)
        message = pid_nr_ns(pid, ns);
    rcu_read_unlock();

    _ptrace_event(event, message);
}

static NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                               BOOLEAN CreateSuspended) {
    NTSTATUS Status;
    struct task_struct* ts;
    thread_start_context* ctx;
    ACCESS_MASK access;
    thread_object* obj;

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtCreateThread: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    access = sanitize_access_mask(DesiredAccess, thread_type);
    if (access & MAXIMUM_ALLOWED)
        access = thread_type->valid;

    ctx = kmalloc(sizeof(thread_start_context), GFP_KERNEL);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(&ctx->thread_context, ThreadContext, sizeof(CONTEXT));

    mmget(current->mm);
    ctx->mm = current->mm;

    refcount_inc(&current->sighand->count);
    ctx->sighand = current->sighand;

    atomic_inc(&current->files->count);
    ctx->files = current->files;

    init_completion(&ctx->thread_created);

    ts = kthread_create_on_node(thread_start, ctx, NUMA_NO_NODE, "%s", "");

    _detach_pid(ts, PIDTYPE_TGID);
    _detach_pid(ts, PIDTYPE_SID);
    _detach_pid(ts, PIDTYPE_PGID);

    ts->flags &= ~PF_KTHREAD;
    ts->flags &= ~PF_NOFREEZE;
    ts->exit_signal = -1;
    ts->group_leader = current->group_leader;
    ts->tgid = current->tgid;

    spin_lock(&current->sighand->siglock);

    ts->signal = current->signal;
    current->signal->nr_threads++;
    atomic_inc(&current->signal->live);
    refcount_inc(&current->signal->sigcnt);
    list_add_tail_rcu(&ts->thread_group, &ts->group_leader->thread_group);
    list_add_tail_rcu(&ts->thread_node, &ts->signal->thread_head);

    // FIXME - should have tasklist_lock held for this?

    list_del_rcu(&ts->tasks);
    list_del(&ts->sibling);

    if (current->ptrace) { // e.g. currently attached to GDB
        ts->ptrace = current->ptrace;
        list_add(&ts->ptrace_entry, &current->parent->ptraced);
        ts->parent = current->parent;
        ts->ptracer_cred = get_cred(current->ptracer_cred);

        if (ts->ptrace & PT_SEIZED)
            ts->jobctl |= JOBCTL_TRAP_STOP;
        else
            sigaddset(&ts->pending.signal, SIGSTOP);
    }

    spin_unlock(&current->sighand->siglock);

    // create thread object

    obj = kzalloc(sizeof(thread_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.h.refcount = 1;

    obj->header.h.type = thread_type;
    inc_obj_refcount(&thread_type->header);

    spin_lock_init(&obj->header.h.path_lock);

    spin_lock_init(&obj->header.sync_lock);
    INIT_LIST_HEAD(&obj->header.waiters);

    get_task_struct(ts);
    obj->ts = ts;

    spin_lock(&thread_list_lock);
    list_add_tail(&obj->list, &thread_list);
    spin_unlock(&thread_list_lock);

    wake_up_process(ts);

    if (current->ptrace) {
        struct pid* pid = get_task_pid(ts, PIDTYPE_PID);

        _ptrace_event_pid(PTRACE_EVENT_CLONE, pid);

        put_pid(pid);
    }

    // wait for thread to start
    wait_for_completion(&ctx->thread_created);
    kfree(ctx);

    // FIXME - set ClientId

    Status = muwine_add_handle(&obj->header.h, ThreadHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&obj->header.h);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS user_NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                             PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                             BOOLEAN CreateSuspended) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    CLIENT_ID client_id;
    CONTEXT context; // FIXME - architecture-dependent
    INITIAL_TEB initial_teb;

    if (!ThreadHandle || !ClientId || !ThreadContext || !InitialTeb)
        return STATUS_INVALID_PARAMETER;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (copy_from_user(&context, ThreadContext, sizeof(CONTEXT)) != 0)
        return STATUS_ACCESS_VIOLATION;

    if (copy_from_user(&initial_teb, InitialTeb, sizeof(INITIAL_TEB)) != 0)
        return STATUS_ACCESS_VIOLATION;

    if (ObjectAttributes && !get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (ObjectAttributes && oa.Attributes & OBJ_KERNEL_HANDLE) {
        if (oa.ObjectName) {
            if (oa.ObjectName->Buffer)
                kfree(oa.ObjectName->Buffer);

            kfree(oa.ObjectName);
        }

        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateThread(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, ProcessHandle,
                            &client_id, &context, &initial_teb, CreateSuspended);

    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

    if (copy_to_user(ClientId, &client_id, sizeof(CLIENT_ID)) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(h, ThreadHandle) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static NTSTATUS NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    if (ThreadHandle != NtCurrentThread()) {
        printk("NtTerminateThread: FIXME - support thread handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    do_exit(ExitStatus);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    if (ThreadHandle != NtCurrentThread() && (uintptr_t)ThreadHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    return NtTerminateThread(ThreadHandle, ExitStatus);
}

static void thread_object_close(object_header* obj) {
    thread_object* t = (thread_object*)obj;

    spin_lock(&thread_list_lock);
    list_del(&t->list);
    spin_unlock(&thread_list_lock);

    put_task_struct(t->ts);

    free_object(&t->header.h);
}

static void signal_object(sync_object* obj) {
    struct list_head* le;

    obj->signalled = true;

    spin_lock(&obj->sync_lock);

    // wake up waiting threads
    le = obj->waiters.next;
    while (le != &obj->waiters) {
        waiter* w = list_entry(le, waiter, list);

        wake_up_process(w->ts);

        le = le->next;
    }

    spin_unlock(&obj->sync_lock);
}

int muwine_thread_exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    thread_object* t = NULL;
    struct list_head* le;

    if (!current->mm) // kernel thread
        return 0;

    spin_lock(&thread_list_lock);

    le = thread_list.next;
    while (le != &thread_list) {
        thread_object* t2 = list_entry(le, thread_object, list);

        if (t2->ts == current) {
            t = t2;
            inc_obj_refcount(&t->header.h);
            break;
        }

        le = le->next;
    }

    spin_unlock(&thread_list_lock);

    if (!t)
        return 0;

    signal_object(&t->header);

    dec_obj_refcount(&t->header.h);

    return 0;
}

NTSTATUS muwine_init_threads(void) {
    NTSTATUS Status;
    UNICODE_STRING us;

    static const WCHAR thread_name[] = L"Thread";

    us.Length = us.MaximumLength = sizeof(thread_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)thread_name;

    thread_type = muwine_add_object_type(&us, thread_object_close, NULL,
                                         THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | READ_CONTROL,
                                         THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_ALERT |
                                         THREAD_SET_CONTEXT | THREAD_SET_INFORMATION |
                                         THREAD_SET_LIMITED_INFORMATION | READ_CONTROL,
                                         THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE,
                                         THREAD_ALL_ACCESS, THREAD_ALL_ACCESS);
    if (IS_ERR(thread_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)thread_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)thread_type);
    }

    Status = get_func_ptr("put_files_struct", (void**)&_put_files_struct);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = get_func_ptr("detach_pid", (void**)&_detach_pid);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = get_func_ptr("ptrace_notify", (void**)&_ptrace_notify);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}
