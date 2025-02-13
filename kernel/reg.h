#pragma once

#define HV_HBLOCK_SIGNATURE 0x66676572  // "regf"
#define HV_HBIN_SIGNATURE   0x6e696268  // "hbin"

#define CM_KEY_HASH_LEAF            0x686c  // "lh"
#define CM_KEY_INDEX_ROOT           0x6972  // "ri"
#define CM_KEY_NODE_SIGNATURE       0x6b6e  // "nk"
#define CM_KEY_VALUE_SIGNATURE      0x6b76  // "vk"
#define CM_KEY_SECURITY_SIGNATURE   0x6b73  // "sk"

#define BIN_SIZE 0x1000

#define CM_KEY_VALUE_SPECIAL_SIZE       0x80000000

#define HSYS_MAJOR 1
#define HSYS_MIN_MINOR 3
#define HSYS_MAX_MINOR 5
#define HFILE_TYPE_PRIMARY 0
#define HBASE_FORMAT_MEMORY 1

#define HIVE_FILENAME_MAXLEN 31

#define KEY_SYM_LINK        0x0010
#define KEY_COMP_NAME       0x0020

#define VALUE_COMP_NAME     0x0001

#define REG_LINK                 6

#define REG_CREATED_NEW_KEY         0x00000001
#define REG_OPENED_EXISTING_KEY     0x00000002

#define REG_OPTION_NON_VOLATILE     0x00000000
#define REG_OPTION_VOLATILE         0x00000001
#define REG_OPTION_CREATE_LINK      0x00000002
#define REG_OPTION_BACKUP_RESTORE   0x00000004
#define REG_OPTION_OPEN_LINK        0x00000008

#define KEY_QUERY_VALUE         0x00000001
#define KEY_SET_VALUE           0x00000002
#define KEY_CREATE_SUB_KEY      0x00000004
#define KEY_ENUMERATE_SUB_KEYS  0x00000008
#define KEY_NOTIFY              0x00000010
#define KEY_CREATE_LINK         0x00000020

#define KEY_GENERIC_READ KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | \
                         READ_CONTROL
#define KEY_GENERIC_WRITE KEY_SET_VALUE | KEY_CREATE_SUB_KEY | READ_CONTROL
#define KEY_GENERIC_EXECUTE KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | \
                            KEY_CREATE_LINK | READ_CONTROL
#define KEY_ALL_ACCESS KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | \
                       KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK | \
                       DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER

extern type_object* key_type;

#pragma pack(push,1)

typedef struct {
    uint32_t Signature;
    uint32_t Sequence1;
    uint32_t Sequence2;
    uint64_t TimeStamp;
    uint32_t Major;
    uint32_t Minor;
    uint32_t Type;
    uint32_t Format;
    uint32_t RootCell;
    uint32_t Length;
    uint32_t Cluster;
    WCHAR FileName[HIVE_FILENAME_MAXLEN + 1];
    uint32_t Reserved1[99];
    uint32_t CheckSum;
    uint32_t Reserved2[0x37E];
    uint32_t BootType;
    uint32_t BootRecover;
} HBASE_BLOCK;

typedef struct {
    ULONG Signature;
    uint32_t FileOffset;
    ULONG Size;
    ULONG Reserved[2];
    LARGE_INTEGER TimeStamp;
    ULONG Spare;
} HBIN;

#define KEY_HIVE_EXIT           0x0002
#define KEY_HIVE_ENTRY          0x0004
#define KEY_NO_DELETE           0x0008

typedef struct {
    uint16_t Signature;
    uint16_t Flags;
    uint64_t LastWriteTime;
    uint32_t Spare;
    uint32_t Parent;
    uint32_t SubKeyCount;
    uint32_t VolatileSubKeyCount;
    uint32_t SubKeyList;
    uint32_t VolatileSubKeyList;
    uint32_t ValuesCount;
    uint32_t Values;
    uint32_t Security;
    uint32_t Class;
    uint32_t MaxNameLen;
    uint32_t MaxClassLen;
    uint32_t MaxValueNameLen;
    uint32_t MaxValueDataLen;
    uint32_t WorkVar;
    uint16_t NameLength;
    uint16_t ClassLength;
    WCHAR Name[1];
} CM_KEY_NODE;

typedef struct {
    uint32_t Cell;
    uint32_t HashKey;
} CM_INDEX;

typedef struct {
    uint16_t Signature;
    uint16_t Count;
    CM_INDEX List[1];
} CM_KEY_FAST_INDEX;

typedef struct {
    uint16_t Signature;
    uint16_t NameLength;
    uint32_t DataLength;
    uint32_t Data;
    uint32_t Type;
    uint16_t Flags;
    uint16_t Spare;
    WCHAR Name[1];
} CM_KEY_VALUE;

typedef struct {
    uint16_t Signature;
    uint16_t Count;
    uint32_t List[1];
} CM_KEY_INDEX;

typedef struct {
    uint16_t Signature;
    uint16_t Reserved;
    uint32_t Flink;
    uint32_t Blink;
    uint32_t ReferenceCount;
    uint32_t DescriptorLength;
    uint8_t Descriptor[1];
} CM_KEY_SECURITY;

typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION;

typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION;

typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NODE_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION;

#pragma pack(pop)

typedef struct {
    struct list_head list;
    uint32_t offset;
    uint32_t size;
} hive_hole;

typedef struct _hive {
    struct list_head list;
    UNICODE_STRING path;
    unsigned int depth;
    void* data;
    void* bins;
    size_t size;
    unsigned int refcount;
    struct list_head holes;
    struct rw_semaphore sem;
    bool dirty;
    void* volatile_bins;
    size_t volatile_size;
    struct list_head volatile_holes;
    uint32_t volatile_root_cell;
    UNICODE_STRING fs_path;
    int file_mode;
    struct _hive* parent_hive;
    uint32_t parent_key_offset;
    bool parent_key_volatile;
    uint32_t volatile_sk;
} hive;

typedef struct {
    object_header header;
    hive* h;
    size_t offset;
    bool is_volatile;
    bool parent_is_volatile;
} key_object;

typedef struct {
    struct list_head list;
    WCHAR* source;
    ULONG source_len;
    WCHAR* destination;
    ULONG destination_len;
    unsigned int depth;
} symlink;
