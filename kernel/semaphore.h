#pragma once

#define SEMAPHORE_QUERY_STATE       0x0001
#define SEMAPHORE_MODIFY_STATE      0x0002

#define SEMAPHORE_GENERIC_READ SEMAPHORE_QUERY_STATE | READ_CONTROL
#define SEMAPHORE_GENERIC_WRITE SEMAPHORE_MODIFY_STATE | READ_CONTROL
#define SEMAPHORE_GENERIC_EXECUTE READ_CONTROL | SYNCHRONIZE

#define SEMAPHORE_ALL_ACCESS SEMAPHORE_QUERY_STATE | SEMAPHORE_MODIFY_STATE | \
                             DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | \
                             SYNCHRONIZE

typedef struct {
    sync_object header;
    LONG count;
    LONG max_count;
} sem_object;

extern type_object* sem_type;
