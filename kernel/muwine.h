#pragma once

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

struct muwine_func {
    void* func;
    unsigned int num_args;
};

#define STATUS_SUCCESS                      0x00000000
#define STATUS_NOT_IMPLEMENTED              0xc0000002
#define STATUS_INVALID_PARAMETER            0xc000000d
#define STATUS_OBJECT_NAME_NOT_FOUND        0xc0000034
#define STATUS_INSUFFICIENT_RESOURCES       0xc000009a
#define STATUS_INTERNAL_ERROR               0xc00000e5
#define STATUS_REGISTRY_CORRUPT             0xc000014c

typedef uintptr_t NTSTATUS;
typedef uint16_t WCHAR;

typedef NTSTATUS (*muwine_func1arg)(uintptr_t arg1);

// muwine.c
NTSTATUS muwine_error_to_ntstatus(int err);
bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen);

// reg.c
NTSTATUS muwine_init_registry(const char* system_hive);
void muwine_free_reg(void);
