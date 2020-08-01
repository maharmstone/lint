#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#else
#include <muw.h>
#endif

#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
typedef enum {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

NTSTATUS __stdcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, const OBJECT_ATTRIBUTES* ObjectAttributes,
                                   const LARGE_INTEGER* MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes,
                                   HANDLE FileHandle);
NTSTATUS __stdcall NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
                                      SIZE_T CommitSize, const LARGE_INTEGER* SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition,
                                      ULONG AllocationType, ULONG Win32Protect);
NTSTATUS __stdcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
#endif

#if 0
static size_t wchar_len(const WCHAR* s) {
    size_t i = 0;

    while (*s != 0) {
        i++;
        s++;
    }

    return i;
}

static void open_file(const WCHAR* s) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    HANDLE h;

    us.Length = us.MaximumLength = (uint16_t)(wchar_len(s) * sizeof(WCHAR));
    us.Buffer = (WCHAR*)s;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtOpenFile(&h, 0, &oa, &iosb, 0, 0);
    printf("NtOpenFile returned %08x\n", Status);
}
#endif

static void test_section() {
    HANDLE sect;
    NTSTATUS Status;
    LARGE_INTEGER maxsize, off;
    size_t size;
    volatile void* addr = NULL;
    volatile void* addr2 = NULL;
    uint32_t val;

    maxsize.QuadPart = 0x20000;

    Status = NtCreateSection(&sect, SECTION_ALL_ACCESS, NULL, &maxsize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateSection returned %08x\n", (uint32_t)Status);
        return;
    }

    Status = NtMapViewOfSection(sect, NtCurrentProcess(), (void**)&addr, 0, 0, NULL, &size, ViewUnmap,
                                0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtMapViewOfSection returned %08x\n", (uint32_t)Status);
        NtClose(sect);
        return;
    }

#ifdef _WIN32
    printf("mapped %I64x bytes at %p\n", (uint64_t)size, addr);
#else
    printf("mapped %zx bytes at %p\n", (uint64_t)size, addr);
#endif

    size = 0x1000;
    off.QuadPart = 0x10000;

    Status = NtMapViewOfSection(sect, NtCurrentProcess(), (void**)&addr2, 0, 0, &off, &size, ViewUnmap,
                                0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        NtUnmapViewOfSection(NtCurrentProcess(), (void*)addr);
        fprintf(stderr, "NtMapViewOfSection returned %08x\n", (uint32_t)Status);
        NtClose(sect);
        return;
    }

#ifdef _WIN32
    printf("mapped %I64x bytes at %p\n", (uint64_t)size, addr2);
#else
    printf("mapped %zx bytes at %p\n", (uint64_t)size, addr2);
#endif

    val = 0xcafebabe;
    *(uint32_t*)((uint8_t*)addr + 0x10000) = val;

    if (*(uint32_t*)((uint8_t*)addr + 0x10000) != val)
        fprintf(stderr, "value 1 was %08x, expected %08x\n", *(uint32_t*)((uint8_t*)addr + 0x10000), val);

    if (*(uint32_t*)addr2 != val)
        fprintf(stderr, "value 2 was %08x, expected %08x\n", *(uint32_t*)addr2, val);

    Status = NtUnmapViewOfSection(NtCurrentProcess(), (void*)addr2);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtUnmapViewOfSection returned %08x\n", (uint32_t)Status);

    Status = NtUnmapViewOfSection(NtCurrentProcess(), (void*)addr);
    if (!NT_SUCCESS(Status))
        fprintf(stderr, "NtUnmapViewOfSection returned %08x\n", (uint32_t)Status);

    NtClose(sect);
}

int main() {
    test_section();

    return 0;
}
