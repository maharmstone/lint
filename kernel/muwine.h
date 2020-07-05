#pragma once

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_REGISTRY_CORRUPT             0xc000014c

typedef uintptr_t NTSTATUS;

typedef NTSTATUS (*muwine_func1arg)(uintptr_t arg1);

NTSTATUS muwine_init_registry(const char* system_hive);
