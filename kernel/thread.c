#include "muwine.h"
#include <linux/kthread.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>
#include <linux/fdtable.h>

typedef struct {
    CONTEXT thread_context;
    struct mm_struct* mm;
    struct sighand_struct* sighand;
    struct files_struct* files;
    pid_t tgid;
    struct completion thread_created;
} context;

typedef struct {
    object_header header;
    struct task_struct* ts;
} thread_object;

#define THREAD_TERMINATE 0x0001
#define THREAD_SUSPEND_RESUME 0x0002
#define THREAD_ALERT 0x0004
#define THREAD_GET_CONTEXT 0x0008
#define THREAD_SET_CONTEXT 0x0010
#define THREAD_SET_INFORMATION 0x0020
#define THREAD_QUERY_INFORMATION 0x0040
#define THREAD_SET_THREAD_TOKEN 0x0080
#define THREAD_IMPERSONATE 0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_ALL_ACCESS STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                          THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION | \
                          THREAD_DIRECT_IMPERSONATION | THREAD_IMPERSONATE | \
                          THREAD_SET_THREAD_TOKEN | THREAD_QUERY_INFORMATION | \
                          THREAD_SET_INFORMATION | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | \
                          THREAD_SUSPEND_RESUME | THREAD_TERMINATE

void (*_put_files_struct)(struct files_struct* files);

static type_object* thread_type = NULL;

static int thread_start(void* arg) {
    context* ctx = arg;
    uint64_t cs, ds;

    current->mm = current->active_mm = ctx->mm;

    // FIXME - put current->sighand?
    current->sighand = ctx->sighand;

    if (current->files)
        _put_files_struct(current->files);

    current->files = ctx->files;

    // FIXME - attach to parent TGID

    cs = __USER_CS;
    ds = __USER_DS;

    // FIXME - free context

    // FIXME - allocate and populate TEB, and set in gs

    complete(&ctx->thread_created);

    // FIXME - wait here if CreateSuspended not set

    // FIXME - set registers

    asm volatile(
        "cli\n\t"
        "push %1\n\t"               // push new SS
        "push %3\n\t"               // push new RSP
        "pushfq\n\t"                // push RFLAGS
        "orq $0x3000, (%%rsp)\n\t"  // change IOPL to ring 3
        "orq $0x200, (%%rsp)\n\t"   // re-enable interrupts in usermode
        "push %0\n\t"               // push new CS
        "push %2\n\t"               // push new RIP
        "swapgs\n\t"
        "iretq\n\t"
        :
        : "r" ((uint64_t)__USER_CS), "r" ((uint64_t)__USER_DS), "m" (ctx->thread_context.Rip), "m" (ctx->thread_context.Rsp)
    );

    // doesn't return

    return 0;
}

static NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                               BOOLEAN CreateSuspended) {
    NTSTATUS Status;
    struct task_struct* ts;
    context* ctx;
    ACCESS_MASK access;
    thread_object* obj;

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtCreateThread: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    access = sanitize_access_mask(DesiredAccess, thread_type);
    if (access & MAXIMUM_ALLOWED)
        access = thread_type->valid;

    ctx = kmalloc(sizeof(context), GFP_KERNEL);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(&ctx->thread_context, ThreadContext, sizeof(CONTEXT));

    mmget(current->mm);
    ctx->mm = current->mm;

    refcount_inc(&current->sighand->count);
    ctx->sighand = current->sighand;

    atomic_inc(&current->files->count);
    ctx->files = current->files;

    ctx->tgid = current->tgid;

    init_completion(&ctx->thread_created);

    ts = kthread_create_on_node(thread_start, ctx, NUMA_NO_NODE, "%s", "");

    ts->flags &= ~PF_KTHREAD;

    wake_up_process(ts);

    // wait for thread to start
    wait_for_completion(&ctx->thread_created);

    // FIXME - set ClientId

    // create thread object

    obj = kzalloc(sizeof(thread_object), GFP_KERNEL);
    if (!obj)
        return STATUS_INSUFFICIENT_RESOURCES;

    obj->header.refcount = 1;

    obj->header.type = thread_type;
    __sync_add_and_fetch(&thread_type->header.refcount, 1);

    spin_lock_init(&obj->header.path_lock);

    get_task_struct(ts);
    obj->ts = ts;

    Status = muwine_add_handle(&obj->header, ThreadHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false, access);

    if (!NT_SUCCESS(Status)) {
        if (__sync_sub_and_fetch(&obj->header.refcount, 1) == 0)
            obj->header.type->close(&obj->header);

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
    printk(KERN_INFO "NtTerminateThread(%lx, %x): stub\n", (uintptr_t)ThreadHandle, ExitStatus);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS user_NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    if (ThreadHandle != NtCurrentThread() && (uintptr_t)ThreadHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    return NtTerminateThread(ThreadHandle, ExitStatus);
}

static void thread_object_close(object_header* obj) {
    thread_object* t = (thread_object*)obj;

    put_task_struct(t->ts);

    free_object(&t->header);
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

    return STATUS_SUCCESS;
}
