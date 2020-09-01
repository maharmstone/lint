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

static void process_object_close(object_header* obj) {
    process_object* p = (process_object*)obj;

    free_object(&p->header.h);
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
