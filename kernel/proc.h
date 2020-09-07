#pragma once

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

typedef struct _process_object {
    sync_object header;
    struct list_head list;
    struct list_head dead_list;
    pid_t pid;
    struct list_head handle_list;
    spinlock_t handle_list_lock;
    uintptr_t next_handle_no;
    token_object* token;
    struct rw_semaphore mapping_list_sem;
    struct list_head mapping_list;
} process_object;

extern type_object* process_type;
