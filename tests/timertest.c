#ifdef _WIN32
#include <winternl.h>
#else
#include <muw.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32

typedef enum {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

typedef void (__stdcall *PTIMER_APC_ROUTINE)(PVOID TimerContext, ULONG TimerLowValue,
                                             LONG TimerHighValue);

NTSTATUS __stdcall NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);

NTSTATUS __stdcall NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime,
                              PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext,
                              BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState);

#else

#define STATUS_WAIT_0       (NTSTATUS)0x00000000

#endif

int main() {
    NTSTATUS Status;
    HANDLE h;
    LARGE_INTEGER time;
    unsigned int i = 0;

    Status = NtCreateTimer(&h, MAXIMUM_ALLOWED, NULL, SynchronizationTimer);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateTimer returned %08x\n", (int32_t)Status);
        return 1;
    }

    time.QuadPart = -10000000;

    Status = NtSetTimer(h, &time, NULL, NULL, false, 1000, NULL);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetTimer returned %08x\n", (int32_t)Status);
        NtClose(h);
        return 1;
    }

    i = 0;
    do {
        Status = NtWaitForSingleObject(h, false, NULL);
        if (Status != STATUS_WAIT_0) {
            fprintf(stderr, "NtWaitForSingleObject returned %08x\n", (int32_t)Status);
            NtClose(h);
            return 1;
        }

        printf("tick\n");

        i++;

        if (i == 3) {
            Status = NtCancelTimer(h, NULL);
            if (!NT_SUCCESS(Status)) {
                fprintf(stderr, "NtCancelTimer returned %08x\n", (int32_t)Status);
                NtClose(h);
                return 1;
            }
        }
    } while (true);

    NtClose(h);

    return 0;
}
