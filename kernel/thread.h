#pragma once

typedef struct {
    CONTEXT thread_context;
    struct mm_struct* mm;
    struct sighand_struct* sighand;
    struct signal_struct* signal;
    struct files_struct* files;
    struct completion thread_created;
} thread_start_context;

typedef struct {
    sync_object header;
    struct task_struct* ts;
    struct list_head list;
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
