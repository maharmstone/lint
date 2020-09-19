#include "muwine.h"

#define IMAGE_DOS_SIGNATURE             0x5a4d // "MZ"
#define IMAGE_NT_SIGNATURE              0x00004550 // "PE\0\0"

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b

#define SECTION_QUERY           0x0001
#define SECTION_MAP_WRITE       0x0002
#define SECTION_MAP_READ        0x0004
#define SECTION_MAP_EXECUTE     0x0008
#define SECTION_EXTEND_SIZE     0x0010

#define SECTION_GENERIC_READ SECTION_QUERY | SECTION_MAP_READ | READ_CONTROL
#define SECTION_GENERIC_WRITE SECTION_MAP_WRITE | READ_CONTROL
#define SECTION_GENERIC_EXECUTE SECTION_MAP_EXECUTE | READ_CONTROL
#define SECTION_ALL_ACCESS SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | \
                           SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE | DELETE | \
                           READ_CONTROL | WRITE_DAC | WRITE_OWNER

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
    object_header header;
    uint64_t max_size;
    ULONG page_protection;
    ULONG alloc_attributes;
    file_object* file;
    struct file* anon_file;
    void* preferred_base;
    bool fixed_base;
    unsigned int num_sections;
    IMAGE_SECTION_HEADER sections[1];
} section_object;

// NT_ prefix added to avoid collision with pgtable_types.h
#define NT_PAGE_NOACCESS 0x01
#define NT_PAGE_READONLY 0x02
#define NT_PAGE_READWRITE 0x04
#define NT_PAGE_WRITECOPY 0x08
#define NT_PAGE_EXECUTE 0x10
#define NT_PAGE_EXECUTE_READ 0x20
#define NT_PAGE_EXECUTE_READWRITE 0x40
#define NT_PAGE_EXECUTE_WRITECOPY 0x80
#define NT_PAGE_GUARD 0x100
#define NT_PAGE_NOCACHE 0x200
#define NT_PAGE_WRITECOMBINE 0x400

#define SEC_FILE 0x800000
#define SEC_IMAGE 0x1000000
#define SEC_PROTECTED_IMAGE 0x2000000
#define SEC_RESERVE 0x4000000
#define SEC_COMMIT 0x8000000
#define SEC_NOCACHE 0x10000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_MAPPED 0x40000
#define MEM_RESET 0x80000

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001

#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[0];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[0];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    };
} IMAGE_NT_HEADERS;

typedef struct {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME;

typedef enum {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE;

#define PROCESSOR_FEATURE_MAX 64

typedef enum {
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

#define MAXIMUM_XSTATE_FEATURES             64

typedef struct {
    ULONG Offset;
    ULONG Size;
} XSTATE_FEATURE;

typedef struct {
    ULONG64 EnabledFeatures;
    ULONG64 EnabledVolatileFeatures;
    ULONG Size;
    ULONG OptimizedSave : 1;
    ULONG CompactionEnabled : 1;
    XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];
    ULONG64 EnabledSupervisorFeatures;
    ULONG64 AlignedFeatures;
    ULONG AllFeatureSize;
    ULONG AllFeatures[MAXIMUM_XSTATE_FEATURES];
    ULONG64 EnabledUserVisibleSupervisorFeatures;
} XSTATE_CONFIGURATION;

typedef struct {
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunLevel;
    volatile ULONG TimeZoneBiasStamp;
    ULONG NtBuildNumber;
    NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    USHORT NativeProcessorArchitecture;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG Reserved1;
    ULONG Reserved3;
    volatile ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG BootId;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;
    UCHAR NXSupportPolicy;
    USHORT CyclesPerYield;
    volatile ULONG ActiveConsoleId;
    volatile ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    UCHAR VirtualizationFlags;
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent       : 1;
            ULONG DbgElevationEnabed        : 1;
            ULONG DbgVirtEnabled            : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled             : 1;
            ULONG DbgDynProcessorEnabled    : 1;
            ULONG DbgConsoleBrokerEnabled   : 1;
            ULONG DbgSecureBootEnabled      : 1;
            ULONG DbgMultiSessionSku        : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits                 : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;
    ULONG SystemCall;
    union {
        ULONG AllFlags;
        struct {
            ULONG Win32Process            : 1;
            ULONG Sgx2Enclave             : 1;
            ULONG VbsBasicEnclave         : 1;
            ULONG SpareBits               : 29;
        } DUMMYSTRUCTNAME;
    } UserCetAvailableEnvironments;
    ULONGLONG SystemCallPad[2];
    union {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
    } DUMMYUNIONNAME;
    ULONG Cookie;
    ULONG CookiePad[1];
    LONGLONG ConsoleSessionForegroundProcessId;
    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;
    ULONG EnclaveFeatureMask[4];
    ULONG TelemetryCoverageRound;
    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;
    ULONG ActiveProcessorAffinity;
    volatile ULONGLONG InterruptTimeBias;
    volatile ULONGLONG QpcBias;
    ULONG ActiveProcessorCount;
    volatile UCHAR ActiveGroupCount;
    USHORT QpcData;
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION XState;
} KSHARED_USER_DATA;

typedef struct {
    PVOID BaseAddress;
    ULONG AllocationAttributes;
    LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION;
