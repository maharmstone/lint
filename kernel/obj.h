#pragma once

typedef struct {
    struct list_head list;
    object_header* object;
    unsigned int name_len;
    WCHAR name[1];
} dir_item;

typedef struct {
    object_header header;
    spinlock_t children_lock;
    struct list_head children;
} dir_object;

typedef struct {
    struct list_head list;
    unsigned int depth;
    UNICODE_STRING src;
    UNICODE_STRING dest;
} symlink_cache;

typedef struct {
    object_header header;
    UNICODE_STRING dest;
    symlink_cache* cache;
} symlink_object;

#define OBJECT_TYPE_CREATE              0x0001

#define OBJECT_TYPE_ALL_ACCESS OBJECT_TYPE_CREATE | DELETE | READ_CONTROL | \
                               WRITE_DAC | WRITE_OWNER
