#include <muw.h>
#include <stdio.h>

static size_t wchar_len(const WCHAR* s) {
    size_t i = 0;

    while (*s != 0) {
        i++;
        s++;
    }

    return i;
}

static void open_file(const WCHAR* s) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    IO_STATUS_BLOCK iosb;
    HANDLE h;

    us.Length = us.MaximumLength = (uint16_t)(wchar_len(s) * sizeof(WCHAR));
    us.Buffer = (WCHAR*)s;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtOpenFile(&h, 0, &oa, &iosb, 0, 0);
    printf("NtOpenFile returned %08x\n", Status);
}

int main() {
    open_file(L"\\Device\\UnixRoot\\root\\temp\\init\\subvol1\\file1");
    open_file(L"\\Device\\UnixRoot\\root\\temp\\init\\subvol1\\file2");
    open_file(L"\\Device\\UnixRoot\\root\\temp\\init\\subvol2\\file3");

    return 0;
}
