#pragma once

typedef struct {
    CONTEXT thread_context;
    struct mm_struct* mm;
    struct sighand_struct* sighand;
    struct signal_struct* signal;
    struct files_struct* files;
    struct completion thread_created;
} thread_start_context;

typedef struct {
    sync_object header;
    struct task_struct* ts;
    struct list_head list;
    uintptr_t teb;
    process_object* process;
} thread_object;

#define THREAD_TERMINATE 0x0001
#define THREAD_SUSPEND_RESUME 0x0002
#define THREAD_ALERT 0x0004
#define THREAD_GET_CONTEXT 0x0008
#define THREAD_SET_CONTEXT 0x0010
#define THREAD_SET_INFORMATION 0x0020
#define THREAD_QUERY_INFORMATION 0x0040
#define THREAD_SET_THREAD_TOKEN 0x0080
#define THREAD_IMPERSONATE 0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define THREAD_RESUME 0x1000
#define THREAD_RESERVED1 0x2000
#define THREAD_RESERVED2 0x4000
#define THREAD_RESERVED3 0x8000

#define THREAD_ALL_ACCESS THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_ALERT | \
                          THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | \
                          THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                          THREAD_DIRECT_IMPERSONATION | THREAD_SET_LIMITED_INFORMATION | \
                          THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME | THREAD_RESERVED1 | \
                          THREAD_RESERVED2 | THREAD_RESERVED3 | DELETE | READ_CONTROL | \
                          WRITE_DAC | WRITE_OWNER | SYNCHRONIZE

#define THREAD_GENERIC_READ THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | READ_CONTROL

#define THREAD_GENERIC_WRITE THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_ALERT | \
                             THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | \
                             THREAD_SET_LIMITED_INFORMATION | READ_CONTROL

#define THREAD_GENERIC_EXECUTE THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL | SYNCHRONIZE

typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        DWORD Version;
    } DUMMYUNIONNAME;
    PVOID ArbitraryUserPointer;
    struct _NT_TIB* Self;
} NT_TIB;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY;

typedef struct {
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK;

typedef struct {
    ULONG Offset;
    HANDLE HDC;
    ULONG Buffer[0x136];
} GDI_TEB_BATCH;

// FIXME - _WIN64 definition

typedef struct _TEB {
    NT_TIB Tib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    struct _PEB* Peb;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG Win32ClientInfo[31];
    PVOID WOW32Reserved;
    ULONG CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    LONG ExceptionCode;
    ACTIVATION_CONTEXT_STACK ActivationContextStack;
    BYTE SpareBytes1[24];
    PVOID SystemReserved2[10];
    GDI_TEB_BATCH GdiTebBatch;
    HANDLE gdiRgn;
    HANDLE gdiPen;
    HANDLE gdiBrush;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocaleInfo;
    ULONG UserReserved[5];
    PVOID glDispatchTable[280];
    PVOID glReserved1[26];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorDisabled;
    PVOID Instrumentation[16];
    PVOID WinSockData;
    ULONG GdiBatchCount;
    ULONG Spare2;
    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID Reserved5[3];
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID ShimData;
    ULONG HeapVirtualAffinity;
    PVOID CurrentTransactionHandle;
    struct _TEB_ACTIVE_FRAME* ActiveFrame;
    PVOID* FlsSlots;
} TEB;
