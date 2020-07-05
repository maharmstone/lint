#pragma once

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_NOT_IMPLEMENTED      0xc0000002
#define STATUS_INVALID_PARAMETER    0xc000000d

typedef uintptr_t NTSTATUS;

typedef NTSTATUS (*muwine_func1arg)(uintptr_t arg1);

NTSTATUS muwine_init_registry(const char* system_hive);
