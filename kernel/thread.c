#include "muwine.h"

NTSTATUS NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                        POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                        PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                        BOOLEAN CreateSuspended) {
    printk(KERN_INFO "NtCreateThread(%px, %x, %px, %lx, %px, %px, %px, %x): stub\n",
        ThreadHandle, DesiredAccess, ObjectAttributes, (uintptr_t)ProcessHandle,
        ClientId, ThreadContext, InitialTeb, CreateSuspended);

    return STATUS_NOT_IMPLEMENTED;
}
