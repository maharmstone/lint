#include <muw.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string>
#include <iostream>
#include <fmt/format.h>

using namespace std;

#define STATUS_SUCCESS 0x00000000

class formatted_error : public exception {
public:
    template<typename... Args>
    formatted_error(const string_view& s, Args&&... args) {
        msg = fmt::format(s, forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

static u16string utf8_to_utf16(const string_view& s) {
    u16string ret;

    for (unsigned int i = 0; i < s.length(); i++) {
        uint32_t cp;

        if (!(s[i] & 0x80))
            cp = s[i];
        else if ((s[i] & 0xe0) == 0xc0) {
            if (i == s.length() - 1 || (s[i+1] & 0xc0) != 0x80)
                throw runtime_error("Malformed UTF-8.");

            cp = ((s[i] & 0x1f) << 6) | (s[i+1] & 0x3f);
            i++;
        } else if ((s[i] & 0xf0) == 0xe0) {
            if (i >= s.length() - 2 || (s[i+1] & 0xc0) != 0x80 || (s[i+2] & 0xc0) != 0x80)
                throw runtime_error("Malformed UTF-8.");

            cp = ((s[i] & 0xf) << 12) | ((s[i+1] & 0x3f) << 6) | (s[i+2] & 0x3f);
            i += 2;
        } else if ((s[i] & 0xf8) == 0xf0) {
            if (i >= s.length() - 3 || (s[i+1] & 0xc0) != 0x80 || (s[i+2] & 0xc0) != 0x80 || (s[i+3] & 0xc0) != 0x80)
                throw runtime_error("Malformed UTF-8.");

            cp = ((s[i] & 0x7) << 18) | ((s[i+1] & 0x3f) << 12) | ((s[i+2] & 0x3f) << 6) | (s[i+3] & 0x3f);
            i += 3;
        } else
            throw runtime_error("Malformed UTF-8.");

        if (cp > 0x10ffff)
            throw runtime_error("Malformed UTF-8.");

        if (cp <= 0xffff)
            ret += (char16_t)cp;
        else {
            cp -= 0x10000;

            ret += (char16_t)(0xd800 | ((cp & 0xffc00) >> 10));
            ret += (char16_t)(0xdc00 | (cp & 0x3ff));
        }
    }

    return ret;
}

static u16string get_nt_path(const string& s) {
    u16string path;

    {
        auto abs = realpath(s.c_str(), nullptr);

        if (!abs)
            throw runtime_error("realpath returned NULL.");

        try {
            path = utf8_to_utf16(abs);
        } catch (...) {
            free(abs);
            throw;
        }

        free(abs);
    }

    if (!path.empty() && path[0] == u'/')
        path = path.substr(1);

    for (auto& c : path) {
        if (c == u'/')
            c = u'\\';
    }

    return u"\\Device\\UnixRoot\\" + path;
}

static void mount_hive(const u16string_view& key, const u16string_view& file) {
    NTSTATUS Status;
    UNICODE_STRING file_us, key_us;
    OBJECT_ATTRIBUTES key_oa, file_oa;

    file_us.Length = file_us.MaximumLength = (USHORT)(file.length() * sizeof(char16_t));
    file_us.Buffer = (WCHAR*)file.data();

    key_oa.Length = sizeof(key_oa);
    key_oa.RootDirectory = nullptr;
    key_oa.ObjectName = &key_us;
    key_oa.Attributes = 0;
    key_oa.SecurityDescriptor = nullptr;
    key_oa.SecurityQualityOfService = nullptr;

    key_us.Length = key_us.MaximumLength = (USHORT)(key.length() * sizeof(char16_t));
    key_us.Buffer = (WCHAR*)key.data();

    file_oa.Length = sizeof(file);
    file_oa.RootDirectory = nullptr;
    file_oa.ObjectName = &file_us;
    file_oa.Attributes = 0;
    file_oa.SecurityDescriptor = nullptr;
    file_oa.SecurityQualityOfService = nullptr;

    Status = NtLoadKey(&key_oa, &file_oa);
    if (!NT_SUCCESS(Status))
        throw formatted_error("NtLoadKey returned {:08x}.\n", (int32_t)Status);
}

static void mount_hives() {
    mount_hive(u"\\Registry\\Machine\\System", get_nt_path("SYSTEM"));
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
    try {
        NTSTATUS Status;

        Status = create_reg_keys();
        if (!NT_SUCCESS(Status))
            return 1;

        mount_hives();

        Status = create_current_control_set_symlink();
        if (!NT_SUCCESS(Status))
            return 1;
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
