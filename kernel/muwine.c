#include "ioctls.h"
#include "muwine.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Harmstone");
MODULE_DESCRIPTION("Multi-user Wine");
MODULE_VERSION("0.01");

static int major_num;

static int muwine_open(struct inode* inode, struct file* file);
static int muwine_release(struct inode* inode, struct file* file);
static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg);

static struct muwine_func funcs[] = {
    { user_NtOpenKey, 3 },
    { user_NtClose, 1 },
    { user_NtEnumerateKey, 6 },
    { user_NtEnumerateValueKey, 6 },
    { user_NtQueryValueKey, 6 },
    { user_NtSetValueKey, 6 },
    { user_NtDeleteValueKey, 2 },
    { user_NtCreateKey, 7 },
    { NtDeleteKey, 1 },
    { user_NtLoadKey, 2 },
    { user_NtUnloadKey, 1 },
    { NtFlushKey, 1 },
    { user_NtOpenKeyEx, 4 },
    { user_NtQueryKey, 5 },
    { NtSaveKey, 2 },
    { NtNotifyChangeKey, 10 },
    { NtNotifyChangeMultipleKeys, 12 },
    { user_NtCreateFile, 11 },
    { user_NtReadFile, 9 },
    { user_NtOpenFile, 6 },
    { user_NtQueryInformationFile, 5 },
    { user_NtWriteFile, 9 },
    { user_NtSetInformationFile, 5 },
    { user_NtQueryDirectoryFile, 11 },
    { user_NtCreateDirectoryObject, 3 },
    { user_NtCreateSymbolicLinkObject, 4 },
    { user_NtCreateSection, 7 },
    { user_NtMapViewOfSection, 10 },
    { user_NtUnmapViewOfSection, 2 },
    { NtExtendSection, 2 },
    { user_NtOpenSection, 3 },
    { user_NtQuerySection, 5 },
    { user_NtProtectVirtualMemory, 5 },
    { user_NtAllocateVirtualMemory, 6 },
    { user_NtQueryVolumeInformationFile, 5 },
    { user_NtFreeVirtualMemory, 4 },
    { NtDeviceIoControlFile, 10 },
    { user_NtFsControlFile, 10 },
    { NtSetVolumeInformationFile, 5 },
    { NtLockFile, 10 },
    { NtQueryQuotaInformationFile, 9 },
    { NtSetQuotaInformationFile, 4 },
    { NtUnlockFile, 5 },
    { NtDeleteFile, 1 },
    { NtFlushBuffersFile, 2 },
    { user_NtQueryAttributesFile, 2 },
    { NtQueryEaFile, 9 },
    { user_NtQueryFullAttributesFile, 2 },
    { NtSetEaFile, 4 },
    { user_NtCreateThread, 8 },
    { user_NtTerminateThread, 2 },
    { user_NtWaitForSingleObject, 3 },
    { NtWaitForMultipleObjects, 5 },
    { user_NtCreateTimer, 4 },
    { user_NtOpenTimer, 3 },
    { NtQueryTimer, 5 },
    { user_NtSetTimer, 7 },
    { user_NtCancelTimer, 2 },
    { user_NtCreateEvent, 5 },
    { user_NtOpenEvent, 3 },
    { user_NtSetEvent, 2 },
    { user_NtResetEvent, 2 },
    { user_NtClearEvent, 1 },
    { user_NtPulseEvent, 2 },
    { NtQueryEvent, 5 },
    { user_NtCreateMutant, 4 },
    { user_NtOpenMutant, 3 },
    { NtQueryMutant, 5 },
    { user_NtReleaseMutant, 2 },
    { user_NtCreateSemaphore, 5 },
    { user_NtOpenSemaphore, 3 },
    { NtQuerySemaphore, 5 },
    { user_NtReleaseSemaphore, 3 },
    { user_NtCreateToken, 13 },
    { user_NtOpenProcessToken, 3 },
    { user_NtAdjustPrivilegesToken, 6 },
    { user_NtQueryInformationToken, 5 },
    { user_NtAllocateLocallyUniqueId, 1 },
    { user_NtQuerySecurityObject, 5 },
    { NtOpenThreadToken, 4 },
    { NtSetInformationThread, 4 },
    { user_NtOpenDirectoryObject, 3 },
    { user_NtAccessCheck, 8 },
    { NtSetSecurityObject, 3 },
    { NtPrivilegeCheck, 3 },
    { NtDuplicateToken, 6 },
    { NtSetInformationToken, 4 },
    { NtOpenProcessTokenEx, 4 },
    { NtOpenThreadTokenEx, 5 },
    { user_NtCreateThreadEx, 11 },
    { NtDelayExecution, 2 },
    { NtGetCurrentProcessorNumber, 0 },
    { NtOpenThread, 4 },
    { NtQueryInformationThread, 5 },
    { NtQueueApcThread, 5 },
    { NtRaiseException, 3 },
    { NtResumeThread, 2 },
    { NtSetContextThread, 2 },
    { NtSetThreadExecutionState, 2 },
    { NtSuspendThread, 2 },
    { NtYieldExecution, 0 },
    { NtAlertResumeThread, 2 },
    { NtAlertThread, 1 },
    { NtContinue, 2 },
    { NtOpenProcess, 4 },
    { NtQueryInformationProcess, 5 },
    { NtSetInformationProcess, 4 },
    { NtTerminateProcess, 2 },
    { NtSuspendProcess, 1 },
    { NtResumeProcess, 1 },
    { NtCreateUserProcess, 11 },
    { NtMakeTemporaryObject, 1 },
    { NtOpenSymbolicLinkObject, 3 },
    { NtQueryDirectoryObject, 7 },
    { NtQuerySymbolicLinkObject, 3 },
};

// FIXME - compat_ioctl for 32-bit ioctls on 64-bit system (will need to fix kernel handles, and -1 dummy handles)

static struct file_operations file_ops = {
    .open = muwine_open,
    .release = muwine_release,
    .unlocked_ioctl = muwine_ioctl
};

void (*_fput)(struct file* file);

bool read_user_string(const char* str_us, char* str_ks, unsigned int maxlen) {
    while (maxlen > 0) {
        char c;

        if (get_user(c, str_us) < 0)
            return false;

        *str_ks = c;
        str_ks++;
        str_us++;
        maxlen--;

        if (c == 0)
            return true;
    }

    return false;
}

bool get_user_unicode_string(UNICODE_STRING* ks, const __user UNICODE_STRING* us) {
    WCHAR* srcbuf;

    if (get_user(ks->Length, &us->Length) < 0)
        return false;

    if (get_user(ks->MaximumLength, &us->MaximumLength) < 0)
        return false;

    if (ks->Length == 0) {
        ks->Buffer = NULL;
        return true;
    }

    if (get_user(srcbuf, &us->Buffer) < 0)
        return false;

    ks->Buffer = kmalloc(ks->Length, GFP_KERNEL);
    if (!ks->Buffer)
        return false;

    if (copy_from_user(ks->Buffer, srcbuf, ks->Length) != 0) {
        kfree(ks->Buffer);
        return false;
    }

    return true;
}

bool get_user_object_attributes(OBJECT_ATTRIBUTES* ks, const __user OBJECT_ATTRIBUTES* us) {
    UNICODE_STRING* usus;
    void* qos;

    if (get_user(ks->Length, &us->Length) < 0)
        return false;

    if (get_user(ks->RootDirectory, &us->RootDirectory) < 0)
        return false;

    if (get_user(ks->Attributes, &us->Attributes) < 0)
        return false;

    if (get_user(ks->SecurityDescriptor, &us->SecurityDescriptor) < 0) // FIXME - copy buffer to user space
        return false;

    if (get_user(qos, &us->SecurityQualityOfService) < 0)
        return false;

    if (get_user(usus, &us->ObjectName) < 0)
        return false;

    if (usus) {
        ks->ObjectName = kmalloc(sizeof(UNICODE_STRING), GFP_KERNEL);
        if (!ks->ObjectName)
            return false;

        if (!get_user_unicode_string(ks->ObjectName, usus)) {
            kfree(ks->ObjectName);
            return false;
        }
    } else
        ks->ObjectName = NULL;

    if (qos) {
        DWORD size;

        if (get_user(size, (DWORD*)qos) < 0) {
            if (ks->ObjectName) {
                if (ks->ObjectName->Buffer)
                    kfree(ks->ObjectName->Buffer);

                kfree(ks->ObjectName);
            }

            return false;
        }

        if (size == 0)
            ks->SecurityQualityOfService = NULL;
        else {
            ks->SecurityQualityOfService = kmalloc(size, GFP_KERNEL);
            if (!ks->SecurityQualityOfService) {
                if (ks->ObjectName) {
                    if (ks->ObjectName->Buffer)
                        kfree(ks->ObjectName->Buffer);

                    kfree(ks->ObjectName);
                }

                return false;
            }

            if (copy_from_user(ks->SecurityQualityOfService, qos, size) != 0) {
                if (ks->ObjectName) {
                    if (ks->ObjectName->Buffer)
                        kfree(ks->ObjectName->Buffer);

                    kfree(ks->ObjectName);
                }

                return false;
            }
        }
    } else
        ks->SecurityQualityOfService = NULL;

    return true;
}

void free_object_attributes(OBJECT_ATTRIBUTES* oa) {
    if (oa->ObjectName) {
        if (oa->ObjectName->Buffer)
            kfree(oa->ObjectName->Buffer);

        kfree(oa->ObjectName);
    }

    if (oa->SecurityQualityOfService)
        kfree(oa->SecurityQualityOfService);
}

int wcsnicmp(const WCHAR* string1, const WCHAR* string2, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        WCHAR c1 = *string1;
        WCHAR c2 = *string2;

        if (c1 >= 'A' && c1 <= 'Z')
            c1 = c1 - 'A' + 'a';

        if (c2 >= 'A' && c2 <= 'Z')
            c2 = c2 - 'A' + 'a';

        if (c1 < c2)
            return -1;
        else if (c1 > c2)
            return 1;

        string1++;
        string2++;
    }

    return 0;
}

int strnicmp(const char* string1, const char* string2, size_t count) {
    size_t i;

    // FIXME - do this properly (including Greek, Cyrillic, etc.)

    for (i = 0; i < count; i++) {
        char c1 = *string1;
        char c2 = *string2;

        if (c1 >= 'A' && c1 <= 'Z')
            c1 = c1 - 'A' + 'a';

        if (c2 >= 'A' && c2 <= 'Z')
            c2 = c2 - 'A' + 'a';

        if (c1 < c2)
            return -1;
        else if (c1 > c2)
            return 1;

        string1++;
        string2++;
    }

    return 0;
}

NTSTATUS utf8_to_utf16(WCHAR* dest, ULONG dest_max, ULONG* dest_len, const char* src, ULONG src_len) {
    NTSTATUS Status = STATUS_SUCCESS;
    uint8_t* in = (uint8_t*)src;
    uint16_t* out = (uint16_t*)dest;
    ULONG i, needed = 0, left = dest_max / sizeof(uint16_t);

    for (i = 0; i < src_len; i++) {
        uint32_t cp;

        if (!(in[i] & 0x80))
            cp = in[i];
        else if ((in[i] & 0xe0) == 0xc0) {
            if (i == src_len - 1 || (in[i+1] & 0xc0) != 0x80) {
                cp = 0xfffd;
                Status = STATUS_SOME_NOT_MAPPED;
            } else {
                cp = ((in[i] & 0x1f) << 6) | (in[i+1] & 0x3f);
                i++;
            }
        } else if ((in[i] & 0xf0) == 0xe0) {
            if (i >= src_len - 2 || (in[i+1] & 0xc0) != 0x80 || (in[i+2] & 0xc0) != 0x80) {
                cp = 0xfffd;
                Status = STATUS_SOME_NOT_MAPPED;
            } else {
                cp = ((in[i] & 0xf) << 12) | ((in[i+1] & 0x3f) << 6) | (in[i+2] & 0x3f);
                i += 2;
            }
        } else if ((in[i] & 0xf8) == 0xf0) {
            if (i >= src_len - 3 || (in[i+1] & 0xc0) != 0x80 || (in[i+2] & 0xc0) != 0x80 || (in[i+3] & 0xc0) != 0x80) {
                cp = 0xfffd;
                Status = STATUS_SOME_NOT_MAPPED;
            } else {
                cp = ((in[i] & 0x7) << 18) | ((in[i+1] & 0x3f) << 12) | ((in[i+2] & 0x3f) << 6) | (in[i+3] & 0x3f);
                i += 3;
            }
        } else {
            cp = 0xfffd;
            Status = STATUS_SOME_NOT_MAPPED;
        }

        if (cp > 0x10ffff) {
            cp = 0xfffd;
            Status = STATUS_SOME_NOT_MAPPED;
        }

        if (dest) {
            if (cp <= 0xffff) {
                if (left < 1)
                    return STATUS_BUFFER_OVERFLOW;

                *out = (uint16_t)cp;
                out++;

                left--;
            } else {
                if (left < 2)
                    return STATUS_BUFFER_OVERFLOW;

                cp -= 0x10000;

                *out = 0xd800 | ((cp & 0xffc00) >> 10);
                out++;

                *out = 0xdc00 | (cp & 0x3ff);
                out++;

                left -= 2;
            }
        }

        if (cp <= 0xffff)
            needed += sizeof(uint16_t);
        else
            needed += 2 * sizeof(uint16_t);
    }

    if (dest_len)
        *dest_len = needed;

    return Status;
}

NTSTATUS utf16_to_utf8(char* dest, ULONG dest_max, ULONG* dest_len, const WCHAR* src, ULONG src_len) {
    NTSTATUS Status = STATUS_SUCCESS;
    uint16_t* in = (uint16_t*)src;
    uint8_t* out = (uint8_t*)dest;
    ULONG in_len = src_len / sizeof(uint16_t);
    ULONG needed = 0, left = dest_max;
    ULONG i;

    for (i = 0; i < in_len; i++) {
        uint32_t cp = *in;
        in++;

        if ((cp & 0xfc00) == 0xd800) {
            if (i == in_len - 1 || (*in & 0xfc00) != 0xdc00) {
                cp = 0xfffd;
                Status = STATUS_SOME_NOT_MAPPED;
            } else {
                cp = (cp & 0x3ff) << 10;
                cp |= *in & 0x3ff;
                cp += 0x10000;

                in++;
                i++;
            }
        } else if ((cp & 0xfc00) == 0xdc00) {
            cp = 0xfffd;
            Status = STATUS_SOME_NOT_MAPPED;
        }

        if (cp > 0x10ffff) {
            cp = 0xfffd;
            Status = STATUS_SOME_NOT_MAPPED;
        }

        if (dest) {
            if (cp < 0x80) {
                if (left < 1)
                    return STATUS_BUFFER_OVERFLOW;

                *out = (uint8_t)cp;
                out++;

                left--;
            } else if (cp < 0x800) {
                if (left < 2)
                    return STATUS_BUFFER_OVERFLOW;

                *out = 0xc0 | ((cp & 0x7c0) >> 6);
                out++;

                *out = 0x80 | (cp & 0x3f);
                out++;

                left -= 2;
            } else if (cp < 0x10000) {
                if (left < 3)
                    return STATUS_BUFFER_OVERFLOW;

                *out = 0xe0 | ((cp & 0xf000) >> 12);
                out++;

                *out = 0x80 | ((cp & 0xfc0) >> 6);
                out++;

                *out = 0x80 | (cp & 0x3f);
                out++;

                left -= 3;
            } else {
                if (left < 4)
                    return STATUS_BUFFER_OVERFLOW;

                *out = 0xf0 | ((cp & 0x1c0000) >> 18);
                out++;

                *out = 0x80 | ((cp & 0x3f000) >> 12);
                out++;

                *out = 0x80 | ((cp & 0xfc0) >> 6);
                out++;

                *out = 0x80 | (cp & 0x3f);
                out++;

                left -= 4;
            }
        }

        if (cp < 0x80)
            needed++;
        else if (cp < 0x800)
            needed += 2;
        else if (cp < 0x10000)
            needed += 3;
        else
            needed += 4;
    }

    if (dest_len)
        *dest_len = needed;

    return Status;
}

NTSTATUS muwine_error_to_ntstatus(int err) {
    switch (err) {
        case -ENOENT:
            return STATUS_OBJECT_NAME_NOT_FOUND;

        case -EEXIST:
            return STATUS_OBJECT_NAME_EXISTS;

        case -EINVAL:
            return STATUS_INVALID_PARAMETER;

        case -EISDIR:
            return STATUS_FILE_IS_A_DIRECTORY;

        case -ENOTDIR:
            return STATUS_NOT_A_DIRECTORY;

        case -EACCES:
            return STATUS_ACCESS_DENIED;

        default:
            printk(KERN_INFO "muwine: Unable to translate error %d to NTSTATUS.\n", err);
            return STATUS_INTERNAL_ERROR;
    }
}

static int muwine_open(struct inode* inode, struct file* file) {
    NTSTATUS Status;

    Status = muwine_add_current_process();
    if (!NT_SUCCESS(Status))
        return -ENOMEM;

    try_module_get(THIS_MODULE);

    return 0;
}

static int muwine_release(struct inode* inode, struct file* file) {
    module_put(THIS_MODULE);

    return 0;
}

static long muwine_ioctl(struct file* file, unsigned int cmd, unsigned long arg) {
    uintptr_t* temp;
    uintptr_t num_args;

    cmd = _IOC_NR(cmd);

    if (cmd > MUWINE_IOCTL_MAX)
        return STATUS_NOT_IMPLEMENTED;

    temp = (uintptr_t*)arg;

    if (!temp)
        return STATUS_INVALID_PARAMETER;

    if (get_user(num_args, temp) < 0)
        return STATUS_INVALID_PARAMETER;

    temp++;

    if (num_args != funcs[cmd].num_args) {
        printk(KERN_INFO "muwine_ioctl: ioctl %u passed %u args, expected %u\n", cmd, (unsigned int)num_args, funcs[cmd].num_args);
        return STATUS_INVALID_PARAMETER;
    }

    if (num_args == 0)
        return ((muwine_func0arg)funcs[cmd].func)();
    else if (num_args == 1) {
        uintptr_t arg1;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func1arg)funcs[cmd].func)(arg1);
    } else if (num_args == 2) {
        uintptr_t arg1, arg2;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        // account for fact NtTerminateThread won't return
        // FIXME - account for when arg1 is handle to current thread
        if (funcs[cmd].func == user_NtTerminateThread && (HANDLE)arg1 == NtCurrentThread())
            _fput(file);

        return ((muwine_func2arg)funcs[cmd].func)(arg1, arg2);
    } else if (num_args == 3) {
        uintptr_t arg1, arg2, arg3;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func3arg)funcs[cmd].func)(arg1, arg2, arg3);
    } else if (num_args == 4) {
        uintptr_t arg1, arg2, arg3, arg4;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func4arg)funcs[cmd].func)(arg1, arg2, arg3, arg4);
    } else if (num_args == 5) {
        uintptr_t arg1, arg2, arg3, arg4, arg5;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func5arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5);
    } else if (num_args == 6) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func6arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6);
    } else if (num_args == 7) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func7arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
    } else if (num_args == 8) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func8arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
    } else if (num_args == 9) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func9arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                  arg9);
    } else if (num_args == 10) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func10arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10);
    } else if (num_args == 11) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg11, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func11arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10, arg11);
    } else if (num_args == 12) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg11, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg12, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func12arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10, arg11, arg12);
    } else if (num_args == 13) {
        uintptr_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13;

        if (get_user(arg1, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg2, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg3, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg4, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg5, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg6, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg7, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg8, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg9, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg10, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg11, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg12, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        temp++;

        if (get_user(arg13, temp) < 0)
            return STATUS_INVALID_PARAMETER;

        return ((muwine_func13arg)funcs[cmd].func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                                                   arg9, arg10, arg11, arg12, arg13);
    } else {
        printk(KERN_ALERT "muwine_ioctl: unexpected number of arguments %u\n", (unsigned int)num_args);
        return STATUS_INVALID_PARAMETER;
    }
}

static struct kretprobe fork_kretprobe = {
    .handler    = muwine_fork_handler,
    .maxactive  = 20,
};

static struct kretprobe group_exit_kretprobe = {
    .entry_handler  = muwine_group_exit_handler,
    .maxactive      = 20,
};

static struct kretprobe exit_kretprobe = {
    .entry_handler  = muwine_thread_exit_handler,
    .maxactive      = 20,
};

static int init_kretprobes(void) {
    int ret;

    fork_kretprobe.kp.symbol_name = "_do_fork";

    ret = register_kretprobe(&fork_kretprobe);

    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

    group_exit_kretprobe.kp.symbol_name = "do_group_exit";

    ret = register_kretprobe(&group_exit_kretprobe);

    if (ret < 0) {
        unregister_kretprobe(&fork_kretprobe);
        printk(KERN_ERR "register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

    exit_kretprobe.kp.symbol_name = "do_exit";

    ret = register_kretprobe(&exit_kretprobe);

    if (ret < 0) {
        unregister_kretprobe(&group_exit_kretprobe);
        unregister_kretprobe(&fork_kretprobe);
        printk(KERN_ERR "register_kretprobe failed, returned %d\n", ret);
        return ret;
    }

    return 0;
}

NTSTATUS get_func_ptr(const char* name, void** func) {
    struct kretprobe dummy_kretprobe;
    int ret;

    // trick kretprobes into giving us address of non-exported symbol

    memset(&dummy_kretprobe, 0, sizeof(struct kretprobe));

    dummy_kretprobe.maxactive = 20;
    dummy_kretprobe.kp.symbol_name = name;

    ret = register_kretprobe(&dummy_kretprobe);

    if (ret < 0) {
        printk(KERN_ERR "register_kretprobe failed, returned %d\n", ret);
        return muwine_error_to_ntstatus(ret);
    }

    if (!dummy_kretprobe.kp.addr) {
        printk(KERN_ERR "unable to get the address for mprotect_fixup\n");
        unregister_kretprobe(&dummy_kretprobe);
        return STATUS_INTERNAL_ERROR;
    }

    *func = (void*)dummy_kretprobe.kp.addr;

    unregister_kretprobe(&dummy_kretprobe);

    return STATUS_SUCCESS;
}

static int __init muwine_init(void) {
    NTSTATUS Status;
    int ret;

    major_num = register_chrdev(0, "muwine", &file_ops);

    if (major_num < 0) {
        printk(KERN_ALERT "Could not register device: %d\n", major_num);
        return major_num;
    }

    Status = muwine_init_objdir();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_objdir returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_registry();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_registry returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_unixroot();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_unixroot returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_sections();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_sections returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_threads();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_threads returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_tokens();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_tokens returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_processes();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_processes returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_timers();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_timers returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_events();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_events returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_mutants();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_mutants returned %08x\n", Status);
        return -ENOMEM;
    }

    Status = muwine_init_semaphores();
    if (!NT_SUCCESS(Status)) {
        printk(KERN_ALERT "muwine_init_semaphores returned %08x\n", Status);
        return -ENOMEM;
    }

    ret = init_kretprobes();
    if (ret < 0)
        return ret;

    Status = get_func_ptr("fput", (void**)&_fput);
    if (!NT_SUCCESS(Status))
        return -ENOMEM;

    printk(KERN_INFO "muwine module loaded with device major number %d\n", major_num);

    return 0;
}

static void __exit muwine_exit(void) {
    unregister_chrdev(major_num, "muwine");

    unregister_kretprobe(&fork_kretprobe);
    unregister_kretprobe(&group_exit_kretprobe);
    unregister_kretprobe(&exit_kretprobe);

    muwine_free_kernel_handles();

    muwine_free_reg();
    muwine_free_objs();
    muwine_free_proc();

    printk(KERN_INFO "muwine unloaded\n");
}

module_init(muwine_init);
module_exit(muwine_exit);
