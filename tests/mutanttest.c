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

NTSTATUS __stdcall NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess,
                                  const OBJECT_ATTRIBUTES* ObjectAttributes, BOOLEAN InitialOwner);

NTSTATUS __stdcall NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount);

#else

#define STATUS_WAIT_0       (NTSTATUS)0x00000000

#endif

int main() {
    NTSTATUS Status;
    HANDLE h;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LONG count;

    static const char16_t path[] = u"\\mutant";

    us.Length = us.MaximumLength = sizeof(path) - sizeof(char16_t);
    us.Buffer = (WCHAR*)path;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_OPENIF;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateMutant(&h, MAXIMUM_ALLOWED, &oa, false);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateMutant returned %08x\n", (int32_t)Status);
        return 1;
    }

    printf("Acquiring mutant...\n");

    Status = NtWaitForSingleObject(h, false, NULL);
    if (Status != STATUS_WAIT_0) {
        fprintf(stderr, "NtWaitForSingleObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return 1;
    }

    printf("Done.\n");

    printf("Acquiring mutant again...\n");

    Status = NtWaitForSingleObject(h, false, NULL);
    if (Status != STATUS_WAIT_0) {
        fprintf(stderr, "NtWaitForSingleObject returned %08x\n", (int32_t)Status);
        NtClose(h);
        return 1;
    }

    printf("Done.\n");

    getc(stdin);

    printf("Releasing mutant...\n");

    Status = NtReleaseMutant(h, &count);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtReleaseMutant returned %08x\n", (int32_t)Status);
        return 1;
    }

    printf("Done (count = %i).\n", (int)count);

    printf("Releasing mutant again...\n");

    Status = NtReleaseMutant(h, &count);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtReleaseMutant returned %08x\n", (int32_t)Status);
        return 1;
    }

    printf("Done (count = %i).\n", (int)count);

    NtClose(h);

    return 0;
}
