#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <uchar.h>

#ifdef _WIN32

NTSTATUS __stdcall NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess,
                                     const OBJECT_ATTRIBUTES* ObjectAttributes, LONG InitialCount,
                                     LONG MaximumCount);

NTSTATUS __stdcall NtReleaseSemaphore(HANDLE SemaphoreHandle, ULONG ReleaseCount, PULONG PreviousCount);

#else

#define STATUS_WAIT_0       (NTSTATUS)0x00000000

#endif

int main() {
    NTSTATUS Status;
    HANDLE h;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    ULONG count;

    static const char16_t path[] = u"\\sem";

    us.Length = us.MaximumLength = sizeof(path) - sizeof(char16_t);
    us.Buffer = (WCHAR*)path;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_OPENIF;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateSemaphore(&h, MAXIMUM_ALLOWED, &oa, 2, 2);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateSemaphore returned %08x\n", (int32_t)Status);
        return 1;
    }

    printf("Acquiring semaphore...\n");

    Status = NtWaitForSingleObject(h, false, NULL);
    if (Status != STATUS_WAIT_0) {
        fprintf(stderr, "NtWaitForSingleObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return 1;
    }

    printf("Done.\n");

    getc(stdin);

    printf("Releasing semaphore...\n");

    Status = NtReleaseSemaphore(h, 1, &count);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtReleaseSemaphore returned %08x\n", (int32_t)Status);
        return 1;
    }

    printf("Done (count = %u).\n", (int)count);

    NtClose(h);

    return 0;
}
