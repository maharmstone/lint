#pragma once

#define FILE_SUPERSEDE                    0x00000000
#define FILE_OPEN                         0x00000001
#define FILE_CREATE                       0x00000002
#define FILE_OPEN_IF                      0x00000003
#define FILE_OVERWRITE                    0x00000004
#define FILE_OVERWRITE_IF                 0x00000005

#define FILE_READ_DATA                    0x0001
#define FILE_LIST_DIRECTORY               0x0001
#define FILE_WRITE_DATA                   0x0002
#define FILE_ADD_FILE                     0x0002
#define FILE_APPEND_DATA                  0x0004
#define FILE_ADD_SUBDIRECTORY             0x0004
#define FILE_CREATE_PIPE_INSTANCE         0x0004
#define FILE_READ_EA                      0x0008
#define FILE_WRITE_EA                     0x0010
#define FILE_EXECUTE                      0x0020
#define FILE_TRAVERSE                     0x0020
#define FILE_DELETE_CHILD                 0x0040
#define FILE_READ_ATTRIBUTES              0x0080
#define FILE_WRITE_ATTRIBUTES             0x0100

// FIXME - these should all have SYNCHRONIZE as well
#define FILE_GENERIC_READ FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | \
                          READ_CONTROL
#define FILE_GENERIC_WRITE FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | \
                           FILE_WRITE_ATTRIBUTES | READ_CONTROL
#define FILE_GENERIC_EXECUTE FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL
#define FILE_ALL_ACCESS FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | \
                        FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE | \
                        FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | \
                        FILE_WRITE_ATTRIBUTES | DELETE | READ_CONTROL | \
                        WRITE_DAC | WRITE_OWNER

#define FILE_DIRECTORY_FILE               0x00000001
#define FILE_WRITE_THROUGH                0x00000002
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT         0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_CREATE_TREE_CONNECTION       0x00000080
#define FILE_COMPLETE_IF_OPLOCKED         0x00000100
#define FILE_NO_EA_KNOWLEDGE              0x00000200
#define FILE_OPEN_REMOTE_INSTANCE         0x00000400
#define FILE_RANDOM_ACCESS                0x00000800
#define FILE_DELETE_ON_CLOSE              0x00001000
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000
#define FILE_NO_COMPRESSION               0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK        0x00010000
#define FILE_DISALLOW_EXCLUSIVE           0x00020000
#define FILE_RESERVE_OPFILTER             0x00100000
#define FILE_OPEN_REPARSE_POINT           0x00200000
#define FILE_OPEN_NO_RECALL               0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY    0x00800000

#define FILE_USE_FILE_POINTER_POSITION    0xfffffffe

#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_DEVICE               0x00000040
#define FILE_ATTRIBUTE_NORMAL               0x00000080
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800
#define FILE_ATTRIBUTE_OFFLINE              0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000
#define FILE_ATTRIBUTE_VIRTUAL              0x00010000

#define FILE_SUPERSEDED         0x00000000
#define FILE_OPENED             0x00000001
#define FILE_CREATED            0x00000002
#define FILE_OVERWRITTEN        0x00000003
#define FILE_EXISTS             0x00000004
#define FILE_DOES_NOT_EXIST     0x00000005

#define FILE_BYTE_ALIGNMENT             0x00000000

#define FILE_SHARE_READ         0x00000001
#define FILE_SHARE_WRITE        0x00000002
#define FILE_SHARE_DELETE       0x00000004

typedef struct _file_object {
    object_header header;
    ULONG options;
    uint64_t offset;
    device* dev;
    loff_t query_dir_offset;
    UNICODE_STRING query_string;
    unsigned int mapping_count;
} file_object;

typedef NTSTATUS (*muwine_create)(device* dev, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, const UNICODE_STRING* us,
                                  PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                                  ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                  PVOID EaBuffer, ULONG EaLength, ULONG oa_attributes);
typedef NTSTATUS (*muwine_query_information)(file_object* obj, ACCESS_MASK access,
                                             PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                             FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*muwine_read)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                PULONG Key);
typedef NTSTATUS (*muwine_write)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                 PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
                                 PULONG Key);
typedef NTSTATUS (*muwine_set_information)(file_object* obj, ACCESS_MASK access, PIO_STATUS_BLOCK IoStatusBlock,
                                           PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*muwine_query_directory)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                           PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                           FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                           PUNICODE_STRING FileMask, BOOLEAN RestartScan);
typedef NTSTATUS (*muwine_query_volume_information)(file_object* obj, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
                                                    ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
typedef NTSTATUS (*muwine_fsctl)(file_object* obj, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                                 PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
                                 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
                                 ULONG OutputBufferLength);
typedef struct file* (*muwine_get_filp)(file_object* obj);


typedef struct _device {
    object_header header;
    muwine_create create;
    muwine_read read;
    muwine_write write;
    muwine_query_information query_information;
    muwine_set_information set_information;
    muwine_query_directory query_directory;
    muwine_query_volume_information query_volume_information;
    muwine_fsctl fsctl;
    muwine_get_filp get_filp;
} device;


typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION;

typedef struct {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION;

typedef struct {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION;

typedef struct {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION;

typedef struct {
    ULONG EaSize;
} FILE_EA_INFORMATION;

typedef struct {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

typedef struct {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION;

typedef struct {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION;

typedef struct {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION;

typedef struct {
    ULONG Mode;
} FILE_MODE_INFORMATION;

typedef struct {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION;

typedef struct {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION;

typedef struct {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef struct {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION;

typedef struct {
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION;

typedef struct {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION;

#define FILE_DEVICE_IS_MOUNTED 0x00000020

#define CTL_CODE(DeviceType,Function,Method,Access) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

#define FILE_DEVICE_DISK_FILE_SYSTEM 0x00000008
#define FILE_DEVICE_FILE_SYSTEM      0x00000009

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

#define FILE_ANY_ACCESS                 0
#define FILE_READ_ACCESS                FILE_READ_DATA
#define FILE_WRITE_ACCESS               FILE_WRITE_DATA

#define FSCTL_GET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct  {
    BYTE ObjectId[16];
    union {
        struct {
            BYTE BirthVolumeId[16];
            BYTE BirthObjectId[16];
            BYTE DomainId[16];
        };
        BYTE ExtendedInfo[48];
    };
} FILE_OBJECTID_BUFFER;
