#pragma once

#define HV_HBLOCK_SIGNATURE 0x66676572  // "regf"

#define CM_KEY_HASH_LEAF        0x686c  // "lh"
#define CM_KEY_INDEX_ROOT       0x6972  // "ri"
#define CM_KEY_NODE_SIGNATURE   0x6b6e  // "nk"
#define CM_KEY_VALUE_SIGNATURE  0x6b76  // "vk"

#define HSYS_MAJOR 1
#define HSYS_MINOR 3
#define HFILE_TYPE_PRIMARY 0
#define HBASE_FORMAT_MEMORY 1

#define HIVE_FILENAME_MAXLEN 31

#define KEY_COMP_NAME       0x0020
#define VALUE_COMP_NAME     0x0001

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
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION;

#pragma pack(pop)

typedef struct {
    void* data;
    void* bins;
    size_t size;
    unsigned int refcount;
} hive;

typedef struct {
    object_header header;
    hive* h;
    size_t offset;
} key_object;