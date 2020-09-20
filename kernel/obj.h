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

#define DIRECTORY_QUERY                 0x0001
#define DIRECTORY_TRAVERSE              0x0002
#define DIRECTORY_CREATE_OBJECT         0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY   0x0008

#define DIRECTORY_GENERIC_READ DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL
#define DIRECTORY_GENERIC_WRITE DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY | \
                                READ_CONTROL
#define DIRECTORY_GENERIC_EXECUTE DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL
#define DIRECTORY_ALL_ACCESS DIRECTORY_QUERY | DIRECTORY_TRAVERSE | \
                             DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY | \
                             DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

#define SYMBOLIC_LINK_QUERY             0x0001

#define SYMBOLIC_LINK_GENERIC_READ SYMBOLIC_LINK_QUERY | READ_CONTROL
#define SYMBOLIC_LINK_GENERIC_WRITE READ_CONTROL
#define SYMBOLIC_LINK_GENERIC_EXECUTE SYMBOLIC_LINK_QUERY | READ_CONTROL
#define SYMBOLIC_LINK_ALL_ACCESS SYMBOLIC_LINK_QUERY | DELETE | READ_CONTROL | WRITE_DAC | \
                                 WRITE_OWNER

typedef struct _DIRECTORY_BASIC_INFORMATION {
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;
