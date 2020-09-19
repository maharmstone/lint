#pragma once

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
