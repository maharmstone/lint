#include "muwine.h"
#include <linux/kthread.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>

func_fork __do_fork;

typedef struct {
    CONTEXT thread_context;
    struct mm_struct* mm;
    struct sighand_struct* sighand;
    pid_t tgid;
} context;

static int thread_start(void* arg) {
    context* ctx = arg;
    uint64_t cs, ds;

    current->mm = current->active_mm = ctx->mm;

    // FIXME - put current->sighand?
    current->sighand = ctx->sighand;

    // FIXME - attach to parent TGID
    // FIXME - attach to file descriptors

    cs = __USER_CS;
    ds = __USER_DS;

    // FIXME - free context

    // FIXME - allocate and populate TEB, and set in gs

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
    struct task_struct* ts;
    context* ctx;

    printk(KERN_INFO "NtCreateThread(%px, %x, %px, %lx, %px, %px, %px, %x): stub\n",
        ThreadHandle, DesiredAccess, ObjectAttributes, (uintptr_t)ProcessHandle,
        ClientId, ThreadContext, InitialTeb, CreateSuspended);

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtCreateThread: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    ctx = kmalloc(sizeof(context), GFP_KERNEL);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    memcpy(&ctx->thread_context, ThreadContext, sizeof(CONTEXT));

    mmget(current->mm);
    ctx->mm = current->mm;

    refcount_inc(&current->sighand->count);
    ctx->sighand = current->sighand;

    ctx->tgid = current->tgid;

    ts = kthread_create_on_node(thread_start, ctx, NUMA_NO_NODE, "%s", "");

    ts->flags &= ~PF_KTHREAD;

    // FIXME - wait for thread to start

    wake_up_process(ts); // FIXME - only if CreateSuspended set

    // FIXME - set ClientId
    // FIXME - create thread object
    // FIXME - create handle, with access mask as valid bits from DesiredAccess

    return STATUS_NOT_IMPLEMENTED;
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
