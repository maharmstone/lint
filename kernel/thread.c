#include "muwine.h"

func_fork __do_fork;

static NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                               POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                               PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                               BOOLEAN CreateSuspended) {
    struct kernel_clone_args args;
    long ret;
    pid_t tid;

    printk(KERN_INFO "NtCreateThread(%px, %x, %px, %lx, %px, %px, %px, %x): stub\n",
        ThreadHandle, DesiredAccess, ObjectAttributes, (uintptr_t)ProcessHandle,
        ClientId, ThreadContext, InitialTeb, CreateSuspended);

    if (ProcessHandle != NtCurrentProcess()) {
        printk("NtCreateThread: FIXME - support process handles\n"); // FIXME
        return STATUS_NOT_IMPLEMENTED;
    }

    memset(&args, 0, sizeof(args));
    args.flags = CLONE_FILES | CLONE_FS | CLONE_IO | CLONE_THREAD |
                 CLONE_SIGHAND | CLONE_VM;
    args.stack = (long)InitialTeb->StackBase;
    args.stack_size = (uint8_t*)InitialTeb->StackLimit - (uint8_t*)InitialTeb->StackBase;
    args.set_tid = &tid;

    // FIXME - CreateSuspended (will need to reimplement _do_fork?)
    // FIXME - allocate and populate TEB (and fs and gs) (What about segments?)
    // FIXME - copy context (esp. instruction pointer)

    ret = __do_fork(&args);
    if (ret < 0)
        return muwine_error_to_ntstatus(ret);

    // FIXME - set ClientId (see ret)
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
