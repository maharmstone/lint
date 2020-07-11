#include <muw.h>
#include <stdio.h>

int main() {
    NTSTATUS Status;
    UNICODE_STRING file_us, key_us;
    OBJECT_ATTRIBUTES key, file;

    static const WCHAR file_str[] = L"\\Device\\UnixRoot\\root\\temp\\init\\SYSTEM"; // FIXME
    static const WCHAR key_str[] = L"\\Registry\\Machine";

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
        return 1;
    }

    return 0;
}
