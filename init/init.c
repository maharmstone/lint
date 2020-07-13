#include <muw.h>
#include <stdio.h>

#define STATUS_SUCCESS 0x00000000

static NTSTATUS mount_system_hive() {
    NTSTATUS Status;
    UNICODE_STRING file_us, key_us;
    OBJECT_ATTRIBUTES key, file;

    static const WCHAR file_str[] = L"\\Device\\UnixRoot\\root\\temp\\init\\SYSTEM"; // FIXME
    static const WCHAR key_str[] = L"\\Registry\\Machine\\System";

    file_us.Length = file_us.MaximumLength = sizeof(file_str) - sizeof(WCHAR);
    file_us.Buffer = (WCHAR*)file_str;

    key.Length = sizeof(key);
    key.RootDirectory = NULL;
    key.ObjectName = &key_us;
    key.Attributes = 0;
    key.SecurityDescriptor = NULL;
    key.SecurityQualityOfService = NULL;

    key_us.Length = key_us.MaximumLength = sizeof(key_str) - sizeof(WCHAR);
    key_us.Buffer = (WCHAR*)key_str;

    file.Length = sizeof(file);
    file.RootDirectory = NULL;
    file.ObjectName = &file_us;
    file.Attributes = 0;
    file.SecurityDescriptor = NULL;
    file.SecurityQualityOfService = NULL;

    Status = NtLoadKey(&key, &file);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtLoadKey returned %08x.\n", (int32_t)Status);
        return Status;
    }

    return Status;
}

static NTSTATUS create_reg_keys() {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    ULONG dispos;

    static const WCHAR machine[] = L"\\Registry\\Machine";
    static const WCHAR system[] = L"\\Registry\\Machine\\System";

    us.Length = us.MaximumLength = sizeof(machine) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)machine;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_VOLATILE, &dispos);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateKey returned %08x\n", (int32_t)Status);
        return Status;
    }

    NtClose(h);

    us.Length = us.MaximumLength = sizeof(system) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)system;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_VOLATILE, &dispos);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateKey returned %08x\n", (int32_t)Status);
        return Status;
    }

    NtClose(h);

    return STATUS_SUCCESS;
}

static NTSTATUS create_current_control_set_symlink() {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING symlink, value_name;
    ULONG dispos;

    static const WCHAR ccs[] = L"\\Registry\\Machine\\System\\CurrentControlSet";
    static const WCHAR slv[] = L"SymbolicLinkValue";
    static const WCHAR target[] = L"\\Registry\\Machine\\System\\ControlSet001";

    symlink.Length = symlink.MaximumLength = sizeof(ccs) - sizeof(WCHAR);
    symlink.Buffer = (WCHAR*)ccs;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &symlink;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &dispos);
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtCreateKey returned %08x\n", (int32_t)Status);
        return Status;
    }

    value_name.Length = value_name.MaximumLength = sizeof(slv) - sizeof(WCHAR);
    value_name.Buffer = (WCHAR*)slv;

    Status = NtSetValueKey(h, &value_name, 0, REG_LINK, (void*)target, sizeof(target) - sizeof(WCHAR));
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "NtSetValueKey returned %08x\n", (int32_t)Status);
        return Status;
    }

    NtClose(h);

    return STATUS_SUCCESS;
}

int main() {
    NTSTATUS Status;

    Status = create_reg_keys();
    if (!NT_SUCCESS(Status))
        return 1;

    Status = mount_system_hive();
    if (!NT_SUCCESS(Status))
        return 1;

    Status = create_current_control_set_symlink();
    if (!NT_SUCCESS(Status))
        return 1;

    return 0;
}
