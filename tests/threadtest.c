#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32

typedef struct {
    PVOID PreviousStackBase;
    PVOID PreviousStackLimit;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID AllocatedStackBase;
} INITIAL_TEB, *PINITIAL_TEB;

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

NTSTATUS __stdcall NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                  PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb,
                                  BOOLEAN CreateSuspended);

NTSTATUS __stdcall NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
                                    HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
                                    ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
                                    SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);

NTSTATUS __stdcall NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);

#else

#define STATUS_WAIT_0 0x00000000

#endif

uintptr_t answer = 0;
uint8_t __attribute__((aligned(0x1000))) stack[0x20000];

#ifdef _X86_

#define KGDT_R3_CODE 0x18
#define KGDT_R3_DATA 0x20
#define KGDT_R3_TEB 0x38
#define EFLAGS_INTERRUPT_MASK 0x200

#elif defined(__x86_64__)

#define KGDT64_R3_DATA 0x28
#define KGDT64_R3_CODE 0x30
#define KGDT64_R3_CMTEB 0x50
#define EFLAGS_INTERRUPT_MASK 0x200
#define RPL_MASK 0x3

#endif

static void __stdcall threadfunc(uintptr_t val) {
    // FIXME - use NtWriteFile to write message to stdout

    answer = val;

    while (true) { }

    NtTerminateThread(NtCurrentThread(), 0);
}

int main() {
    NTSTATUS Status;
    HANDLE h;
    CLIENT_ID client_id;
    CONTEXT context;
    INITIAL_TEB initial_teb;
    LARGE_INTEGER timeout;

    printf("Starting main thread (func = %p, stack = %p).\n", threadfunc, stack);

    memset(&context, 0, sizeof(context));

    initial_teb.PreviousStackBase = NULL;
    initial_teb.PreviousStackLimit = NULL;
    initial_teb.StackBase = stack + sizeof(stack);
    initial_teb.StackLimit = stack;
    initial_teb.AllocatedStackBase = stack;

#ifdef _X86_
    context.SegFs = KGDT_R3_TEB;
    context.SegEs = KGDT_R3_DATA;
    context.SegDs = KGDT_R3_DATA;
    context.SegSs = KGDT_R3_DATA;
    context.SegCs = KGDT_R3_CODE;
    context.EFlags = EFLAGS_INTERRUPT_MASK;
    context.Eip = (uintptr_t)threadfunc;
    context.Esp = (uintptr_t)initial_teb.StackBase;
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
#elif defined(__x86_64__)
    context.SegCs = KGDT64_R3_CODE | RPL_MASK;
    context.SegDs = KGDT64_R3_DATA | RPL_MASK;
    context.SegEs = KGDT64_R3_DATA | RPL_MASK;
    context.SegFs = KGDT64_R3_CMTEB | RPL_MASK;
    context.SegGs = KGDT64_R3_DATA | RPL_MASK;
    context.SegSs = KGDT64_R3_DATA | RPL_MASK;
    context.EFlags = EFLAGS_INTERRUPT_MASK;
    context.Rip = (uintptr_t)threadfunc;
    context.Rsp = (uintptr_t)initial_teb.StackBase;
    context.Rcx = 42;
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
#else
#error "Unsupported architecture."
#endif

    Status = NtCreateThread(&h, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                            &client_id, &context, &initial_teb, false);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateThread returned %08x\n", (uint32_t)Status);
        return 1;
    }

//     Status = NtCreateThreadEx(&h, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
//                               threadfunc, NULL, 0, 0, 0x1000, 0x1000, NULL);
//     if (!NT_SUCCESS(Status)) {
//         fprintf(stderr, "NtCreateThreadEx returned %08lx\n", Status);
//         return 1;
//     }

    printf("Thread created.\n");

    timeout.QuadPart = -30000000; // 3 seconds

    Status = NtWaitForSingleObject(h, false, &timeout);
    if (Status != STATUS_WAIT_0) {
        fprintf(stderr, "NtWaitForSingleObject returned %08x (answer = %u)\n", (uint32_t)Status, (unsigned int)answer);
        NtClose(h);
        return 1;
    }

    printf("Thread finished (answer = %u).\n", (unsigned int)answer);

    NtClose(h);

    return 0;
}
