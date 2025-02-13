#pragma once

#define TIMER_QUERY_STATE       0x0001
#define TIMER_MODIFY_STATE      0x0002

#define TIMER_GENERIC_READ TIMER_QUERY_STATE | READ_CONTROL

#define TIMER_GENERIC_WRITE TIMER_MODIFY_STATE | READ_CONTROL

#define TIMER_GENERIC_EXECUTE READ_CONTROL | SYNCHRONIZE

#define TIMER_ALL_ACCESS TIMER_QUERY_STATE | TIMER_MODIFY_STATE | DELETE | \
                         READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE

typedef struct {
    sync_object header;
    TIMER_TYPE type;
    struct timer_list timer;
    spinlock_t lock;
    LONG period;
    struct lock_class_key key;
} timer_object;
