#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

NTSTATUS __stdcall NtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                   POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess,
                                   BOOLEAN InheritObjectTable, HANDLE SectionHandle,
                                   HANDLE DebugPort, HANDLE ExceptionPort);

NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
                                   const OBJECT_ATTRIBUTES* ObjectAttributes,
                                   const LARGE_INTEGER* MaximumSize,
                                   ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle);

typedef enum {
    SectionBasicInformation,
    SectionImageInformation,
    SectionRelocationInformation,
    MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef struct  {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union {
        UCHAR ImageFlags;
        struct {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR Reserved : 3;
        };
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION;

NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass,
                                  PVOID InformationBuffer, ULONG InformationBufferSize,
                                  PULONG ResultLength);

NTSTATUS __stdcall NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                                    ULONG_PTR ZeroBits, SIZE_T StackSize,
                                    SIZE_T MaximumStackSize, PVOID AttributeList);

#endif

int main() {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    HANDLE file, sect, proc, thread;
    SECTION_IMAGE_INFORMATION sii;

    static const WCHAR path[] = L"\\??\\C:\\Windows\\System32\\notepad.exe";

    us.Length = us.MaximumLength = sizeof(path) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)path;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtOpenFile(&file, FILE_READ_DATA | FILE_EXECUTE, &oa, &iosb, 0, 0);

    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtOpenFile returned %08x\n", (uint32_t)Status);
        return 1;
    }

    Status = NtCreateSection(&sect, SECTION_MAP_EXECUTE | SECTION_QUERY,
                             NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, file);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateSection returned %08x\n", (uint32_t)Status);
        NtClose(file);
        return 1;
    }

    NtClose(file);

    Status = NtQuerySection(sect, SectionImageInformation, &sii,
                            sizeof(sii), NULL);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtQuerySection returned %08x\n", (uint32_t)Status);
        NtClose(sect);
        return 1;
    }

    printf("section info: TransferAddress = %p, ZeroBits = %lu, MaximumStackSize = %I64x, CommittedStackSize = %I64x\n",
           sii.TransferAddress, sii.ZeroBits, (uint64_t)sii.MaximumStackSize, (uint64_t)sii.CommittedStackSize);

    Status = NtCreateProcess(&proc, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),
                             false, sect, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateProcess returned %08x\n", (int32_t)Status);
        NtClose(sect);
        return 1;
    }

    NtClose(sect);

    Status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, proc,
                              sii.TransferAddress, NULL, 0,
                              sii.ZeroBits, sii.CommittedStackSize,
                              sii.MaximumStackSize, NULL);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateThreadEx returned %08x\n", (int32_t)Status);
        NtClose(proc);
        return 1;
    }

    printf("Process started (handle %p).\n", proc);

    NtClose(thread);
    NtClose(proc);

    return 0;
}

