#include "muwine.h"
#include "thread.h"
#include "sect.h"
#include "proc.h"
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
    uintptr_t teb;
    size_t teb_size;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    token_object* token;

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtCreateThread: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    Status = access_check_type(thread_type, DesiredAccess, &access);
    if (!NT_SUCCESS(Status))
        return Status;

    ctx = kmalloc(sizeof(thread_start_context), GFP_KERNEL);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    teb = 0;
    teb_size = sizeof(TEB);

    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&teb, 0, &teb_size, MEM_COMMIT, NT_PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        kfree(ctx);
        return Status;
    }

    // FIXME - set TEB fields(?)

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

    token = muwine_get_current_token();

    Status = muwine_create_sd(NULL,
                              ObjectAttributes ? ObjectAttributes->SecurityDescriptor : NULL,
                              token, &thread_type->generic_mapping, 0, false, &sd, NULL);

    if (token)
        dec_obj_refcount((object_header*)token);

    if (!NT_SUCCESS(Status))
        return Status;

    obj = (thread_object*)muwine_alloc_object(sizeof(thread_object), thread_type, sd);
    if (!obj) {
        kfree(sd);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    get_task_struct(ts);
    obj->ts = ts;

    obj->teb = teb;
    inc_obj_refcount(&obj->header.h);
    obj->process = muwine_current_process_object();

    spin_lock(&thread_list_lock);
    list_add_tail(&obj->list, &thread_list);
    spin_unlock(&thread_list_lock);

    ts->thread.gsbase = teb;

    ClientId->UniqueProcess = (HANDLE)(uintptr_t)task_tgid_vnr(ts);
    ClientId->UniqueThread = (HANDLE)(uintptr_t)ts->pid;

    wake_up_process(ts);

    if (current->ptrace) {
        struct pid* pid = get_task_pid(ts, PIDTYPE_PID);

        _ptrace_event_pid(PTRACE_EVENT_CLONE, pid);

        put_pid(pid);
    }

    // wait for thread to start
    wait_for_completion(&ctx->thread_created);
    kfree(ctx);

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
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    Status = NtCreateThread(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, ProcessHandle,
                            &client_id, &context, &initial_teb, CreateSuspended);

    if (ObjectAttributes)
        free_object_attributes(&oa);

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

NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                PVOID ThreadInformation, ULONG ThreadInformationLength) {
    printk(KERN_INFO "NtSetInformationThread(%lx, %x, %px, %x): stub\n",
           (uintptr_t)ThreadHandle, ThreadInformationClass, ThreadInformation,
           ThreadInformationLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static void thread_object_close(object_header* obj) {
    thread_object* t = (thread_object*)obj;

    spin_lock(&thread_list_lock);
    list_del(&t->list);
    spin_unlock(&thread_list_lock);

    put_task_struct(t->ts);
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

    signal_object(&t->header, false, false);

    if (t->teb) {
        void* base_address = (void*)t->teb;
        size_t region_size = 0;

        NtFreeVirtualMemory(NtCurrentProcess(), &base_address, &region_size, MEM_RELEASE);

        dec_obj_refcount(&t->header.h);
    }

    if (t->mutant_count != 0)
        release_abandoned_mutants(t);

    dec_obj_refcount(&t->process->header.h);

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
                                         THREAD_GENERIC_READ, THREAD_GENERIC_WRITE,
                                         THREAD_GENERIC_EXECUTE, THREAD_ALL_ACCESS,
                                         THREAD_ALL_ACCESS);
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

thread_object* muwine_current_thread_object(void) {
    NTSTATUS Status;
    struct list_head* le;
    thread_object* obj;
    process_object* proc;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    token_object* token;

    // search through list

    spin_lock(&thread_list_lock);

    le = thread_list.next;

    while (le != &thread_list) {
        obj = list_entry(le, thread_object, list);

        if (obj->ts == current) {
            inc_obj_refcount(&obj->header.h);
            spin_unlock(&thread_list_lock);

            return obj;
        }

        le = le->next;
    }

    spin_unlock(&thread_list_lock);

    // create SD

    proc = muwine_current_process_object();

    token = proc->token;

    if (token)
        inc_obj_refcount((object_header*)token);

    Status = muwine_create_sd(NULL, NULL, token, &thread_type->generic_mapping, 0,
                              false, &sd, NULL);

    if (token)
        dec_obj_refcount((object_header*)token);

    if (!NT_SUCCESS(Status)) {
        kfree(sd);
        dec_obj_refcount(&proc->header.h);
        return NULL;
    }

    // search through list again

    spin_lock(&thread_list_lock);

    le = thread_list.next;

    while (le != &thread_list) {
        obj = list_entry(le, thread_object, list);

        if (obj->ts == current) {
            inc_obj_refcount(&obj->header.h);
            spin_unlock(&thread_list_lock);

            kfree(sd);
            dec_obj_refcount(&proc->header.h);

            return obj;
        }

        le = le->next;
    }

    // add new

    obj = (thread_object*)muwine_alloc_object(sizeof(thread_object), thread_type, sd);
    if (!obj) {
        spin_unlock(&thread_list_lock);
        kfree(sd);
        dec_obj_refcount(&proc->header.h);
        return NULL;
    }

    get_task_struct(current);
    obj->ts = current;

    obj->process = proc;

    list_add_tail(&obj->list, &thread_list);

    spin_unlock(&thread_list_lock);

    return obj;
}

static NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                 PRTL_THREAD_START_ROUTINE StartRoutine, PVOID Argument,
                                 ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize,
                                 SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    printk(KERN_INFO "NtCreateThreadEx(%px, %x, %px, %lx, %px, %px, %x, %lx, %lx, %lx, %px): stub\n",
           ThreadHandle, DesiredAccess, ObjectAttributes, (uintptr_t)ProcessHandle,
           StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,
           AttributeList);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS copy_from_attribute_list(PPS_ATTRIBUTE_LIST ks, PPS_ATTRIBUTE_LIST* us) {
    SIZE_T size;
    PS_ATTRIBUTE_LIST* attlist;
    unsigned int i, count;

    if (get_user(size, (SIZE_T*)ks) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (size < offsetof(PS_ATTRIBUTE_LIST, Attributes))
        return STATUS_INVALID_PARAMETER;

    attlist = kmalloc(size, GFP_KERNEL);
    if (!attlist)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (copy_from_user(attlist, ks, size) != 0) {
        kfree(attlist);
        return STATUS_ACCESS_VIOLATION;
    }

    count = (size - offsetof(PS_ATTRIBUTE_LIST, Attributes)) / sizeof(PS_ATTRIBUTE);

    for (i = 0; i < count; i++) {
        if (attlist->Attributes[i].Attribute == PS_ATTRIBUTE_CLIENT_ID) {
            attlist->Attributes[i].ValuePtr = kmalloc(sizeof(CLIENT_ID), GFP_KERNEL);
            if (!attlist->Attributes[i].ValuePtr) {
                unsigned int j;

                for (j = 0; j < i; j++) {
                    if (attlist->Attributes[j].ValuePtr)
                        kfree(attlist->Attributes[j].ValuePtr);

                    if (attlist->Attributes[j].ReturnLength)
                        kfree(attlist->Attributes[j].ReturnLength);
                }

                kfree(attlist);

                return STATUS_INSUFFICIENT_RESOURCES;
            }
        } else if (attlist->Attributes[i].Attribute == PS_ATTRIBUTE_TEB_ADDRESS) {
            attlist->Attributes[i].ValuePtr = kmalloc(sizeof(void*), GFP_KERNEL);
            if (!attlist->Attributes[i].ValuePtr) {
                unsigned int j;

                for (j = 0; j < i; j++) {
                    if (attlist->Attributes[j].ValuePtr)
                        kfree(attlist->Attributes[j].ValuePtr);

                    if (attlist->Attributes[j].ReturnLength)
                        kfree(attlist->Attributes[j].ReturnLength);
                }

                kfree(attlist);

                return STATUS_INSUFFICIENT_RESOURCES;
            }
        } else
            attlist->Attributes[i].ValuePtr = NULL;

        if (attlist->Attributes[i].ReturnLength) {
            attlist->Attributes[i].ReturnLength = kmalloc(sizeof(SIZE_T), GFP_KERNEL);

            if (!attlist->Attributes[i].ReturnLength) {
                unsigned int j;

                if (attlist->Attributes[i].ValuePtr)
                    kfree(attlist->Attributes[i].ValuePtr);

                for (j = 0; j < i; j++) {
                    if (attlist->Attributes[j].ValuePtr)
                        kfree(attlist->Attributes[j].ValuePtr);

                    if (attlist->Attributes[j].ReturnLength)
                        kfree(attlist->Attributes[j].ReturnLength);
                }

                kfree(attlist);

                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }

    *us = attlist;

    return STATUS_SUCCESS;
}

static NTSTATUS copy_to_attribute_list(PPS_ATTRIBUTE_LIST ks, PPS_ATTRIBUTE_LIST us) {
    unsigned int i, count;

    count = (ks->TotalLength - offsetof(PS_ATTRIBUTE_LIST, Attributes)) / sizeof(PS_ATTRIBUTE);

    for (i = 0; i < count; i++) {
        PSIZE_T retlen;

        if (ks->Attributes[i].ValuePtr) {
            void* value_ptr;

            if (get_user(value_ptr, &us->Attributes[i].ValuePtr) < 0)
                return STATUS_ACCESS_VIOLATION;

            if (ks->Attributes[i].Attribute == PS_ATTRIBUTE_CLIENT_ID) {
                if (copy_to_user(ks->Attributes[i].ValuePtr, value_ptr, sizeof(CLIENT_ID)) != 0)
                    return STATUS_ACCESS_VIOLATION;
            } else if (ks->Attributes[i].Attribute == PS_ATTRIBUTE_TEB_ADDRESS) {
                if (copy_to_user(ks->Attributes[i].ValuePtr, value_ptr, sizeof(void*)) != 0)
                    return STATUS_ACCESS_VIOLATION;
            }
        }

        if (get_user(retlen, &us->Attributes[i].ReturnLength) < 0)
            return STATUS_ACCESS_VIOLATION;

        if (retlen) {
            if (ks->Attributes[i].ReturnLength) {
                if (put_user(*ks->Attributes[i].ReturnLength, retlen) < 0)
                    return STATUS_ACCESS_VIOLATION;
            } else {
                if (put_user(0, retlen) < 0)
                    return STATUS_ACCESS_VIOLATION;
            }
        }
    }

    return STATUS_SUCCESS;
}

static void free_attribute_list(PPS_ATTRIBUTE_LIST attlist) {
    unsigned int i, count;

    count = (attlist->TotalLength - offsetof(PS_ATTRIBUTE_LIST, Attributes)) / sizeof(PS_ATTRIBUTE);

    for (i = 0; i < count; i++) {
        if (attlist->Attributes[i].ValuePtr)
            kfree(attlist->Attributes[i].ValuePtr);

        if (attlist->Attributes[i].ReturnLength)
            kfree(attlist->Attributes[i].ReturnLength);
    }

    kfree(attlist);
}

NTSTATUS user_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                               PRTL_THREAD_START_ROUTINE StartRoutine, PVOID Argument,
                               ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize,
                               SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    PS_ATTRIBUTE_LIST* attlist;

    if (!ThreadHandle)
        return STATUS_INVALID_PARAMETER;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (ObjectAttributes && !get_user_object_attributes(&oa, ObjectAttributes))
        return STATUS_ACCESS_VIOLATION;

    if (ObjectAttributes && oa.Attributes & OBJ_KERNEL_HANDLE) {
        free_object_attributes(&oa);
        return STATUS_INVALID_PARAMETER;
    }

    if (AttributeList) {
        Status = copy_from_attribute_list(AttributeList, &attlist);
        if (!NT_SUCCESS(Status)) {
            if (ObjectAttributes)
                free_object_attributes(&oa);

            return Status;
        }
    }

    Status = NtCreateThreadEx(&h, DesiredAccess, ObjectAttributes ? &oa : NULL, ProcessHandle,
                              StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
                              MaximumStackSize, AttributeList ? attlist : NULL);

    if (AttributeList) {
        NTSTATUS Status2;

        Status2 = copy_to_attribute_list(AttributeList, attlist);
        if (!NT_SUCCESS(Status2))
            Status = Status2;

        free_attribute_list(attlist);
    }

    if (ObjectAttributes)
        free_object_attributes(&oa);

    if (put_user(h, ThreadHandle) != 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    printk(KERN_INFO "NtDelayExecution(%x, %px): stub\n", Alertable, DelayInterval);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

ULONG NtGetCurrentProcessorNumber(void) {
    printk(KERN_INFO "NtGetCurrentProcessorNumber(): stub\n");

    return 1;
}

NTSTATUS NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                      POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    printk(KERN_INFO "NtOpenThread(%px, %x, %px, %px): stub\n", ThreadHandle, DesiredAccess,
           ObjectAttributes, ClientId);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                  PVOID ThreadInformation, ULONG ThreadInformationLength,
                                  PULONG ReturnLength) {
    printk(KERN_INFO "NtQueryInformationThread(%lx, %x, %px, %x, %px): stub\n", (uintptr_t)ThreadHandle,
           ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtQueueApcThread(HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1,
                          ULONG_PTR arg2, ULONG_PTR arg3) {
    printk(KERN_INFO "NtQueueApcThread(%lx, %px, %lx, %lx, %lx): stub\n", (uintptr_t)handle,
           func, arg1, arg2, arg3);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext,
                          BOOLEAN HandleException) {
    printk(KERN_INFO "NtRaiseException(%px, %px, %x): stub\n", ExceptionRecord, ThreadContext,
           HandleException);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    printk(KERN_INFO "NtResumeThread(%lx, %px): stub\n", (uintptr_t)ThreadHandle, SuspendCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    printk(KERN_INFO "NtSetContextThread(%lx, %px): stub\n", (uintptr_t)ThreadHandle, Context);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetThreadExecutionState(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags) {
    printk(KERN_INFO "NtSetThreadExecutionState(%x, %px): stub\n", NewFlags, PreviousFlags);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    printk(KERN_INFO "NtSuspendThread(%lx, %px): stub\n", (uintptr_t)ThreadHandle,
           PreviousSuspendCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtYieldExecution(void) {
    printk(KERN_INFO "NtYieldExecution(): stub\n");

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    printk(KERN_INFO "NtAlertResumeThread(%lx, %px): stub\n", (uintptr_t)ThreadHandle,
           SuspendCount);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtAlertThread(HANDLE ThreadHandle) {
    printk(KERN_INFO "NtAlertThread(%lx): stub\n", (uintptr_t)ThreadHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) {
    printk(KERN_INFO "NtContinue(%px, %x): stub\n", ThreadContext, RaiseAlert);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}
