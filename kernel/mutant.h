#pragma once

#define MUTANT_QUERY_STATE 0x0001

#define MUTANT_GENERIC_READ MUTANT_QUERY_STATE | READ_CONTROL
#define MUTANT_GENERIC_WRITE READ_CONTROL
#define MUTANT_GENERIC_EXECUTE READ_CONTROL | SYNCHRONIZE

#define MUTANT_ALL_ACCESS MUTANT_QUERY_STATE | DELETE | READ_CONTROL | WRITE_DAC | \
                          WRITE_OWNER | SYNCHRONIZE

typedef struct {
    sync_object header;
    thread_object* thread;
    unsigned int hold_count;
    struct list_head list;
} mutant_object;

extern type_object* mutant_type;
