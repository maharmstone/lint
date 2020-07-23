#include <muw.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <string>
#include <stdexcept>
#include <fmt/format.h>

using namespace std;

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

u16string get_nt_path(const string_view& s) {
    u16string path = utf8_to_utf16(s);

    if (!path.empty() && path[0] == u'/')
        path = path.substr(1);

    for (auto& c : path) {
        if (c == u'/')
            c = u'\\';
    }

    return u"\\Device\\UnixRoot\\" + path;
}

void mount_hive(const u16string_view& key, const u16string_view& file) {
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
        throw formatted_error("NtLoadKey returned {:08x}.", (uint32_t)Status);
}

void unmount_hive(const u16string_view& key) {
    NTSTATUS Status;
    UNICODE_STRING key_us;
    OBJECT_ATTRIBUTES key_oa;

    key_oa.Length = sizeof(key_oa);
    key_oa.RootDirectory = nullptr;
    key_oa.ObjectName = &key_us;
    key_oa.Attributes = 0;
    key_oa.SecurityDescriptor = nullptr;
    key_oa.SecurityQualityOfService = nullptr;

    key_us.Length = key_us.MaximumLength = (USHORT)(key.length() * sizeof(char16_t));
    key_us.Buffer = (WCHAR*)key.data();

    Status = NtUnloadKey(&key_oa);
    if (!NT_SUCCESS(Status))
        throw formatted_error("NtUnloadKey returned {:08x}.", (uint32_t)Status);
}

void create_reg_key(const u16string_view& key, bool is_volatile) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    ULONG dispos;

    us.Length = us.MaximumLength = (USHORT)(key.length() * sizeof(char16_t));
    us.Buffer = (WCHAR*)key.data();

    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr;
    oa.ObjectName = &us;
    oa.Attributes = 0;
    oa.SecurityDescriptor = nullptr;
    oa.SecurityQualityOfService = nullptr;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, is_volatile ? REG_OPTION_VOLATILE : REG_OPTION_NON_VOLATILE, &dispos);
    if (!NT_SUCCESS(Status)) {
        NtClose(h);
        throw formatted_error("NtCreateKey returned {:08x}\n", (uint32_t)Status);
    }

    NtClose(h);
}

void create_reg_symlink(const u16string_view& src, const u16string_view& dest) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING symlink, value_name;
    ULONG dispos;

    static const WCHAR slv[] = L"SymbolicLinkValue";

    symlink.Length = symlink.MaximumLength = (USHORT)(src.length() * sizeof(char16_t));
    symlink.Buffer = (WCHAR*)src.data();

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &symlink;
    oa.Attributes = 0;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    Status = NtCreateKey(&h, 0, &oa, 0, NULL, REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, &dispos);
    if (!NT_SUCCESS(Status))
        throw formatted_error("NtCreateKey returned {:08x}.", (uint32_t)Status);

    value_name.Length = value_name.MaximumLength = sizeof(slv) - sizeof(WCHAR);
    value_name.Buffer = (WCHAR*)slv;

    Status = NtSetValueKey(h, &value_name, 0, REG_LINK, (void*)dest.data(), (ULONG)(dest.length() * sizeof(char16_t)));
    if (!NT_SUCCESS(Status)) {
        NtClose(h);
        throw formatted_error("NtSetValueKey returned {:08x}.", (uint32_t)Status);
    }

    NtClose(h);
}

void delete_key(const u16string_view& key) {
    NTSTATUS Status;
    HANDLE h;
    UNICODE_STRING key_us;
    OBJECT_ATTRIBUTES key_oa;

    key_oa.Length = sizeof(key_oa);
    key_oa.RootDirectory = nullptr;
    key_oa.ObjectName = &key_us;
    key_oa.Attributes = 0;
    key_oa.SecurityDescriptor = nullptr;
    key_oa.SecurityQualityOfService = nullptr;

    key_us.Length = key_us.MaximumLength = (USHORT)(key.length() * sizeof(char16_t));
    key_us.Buffer = (WCHAR*)key.data();

    Status = NtOpenKey(&h, DELETE, &key_oa);
    if (!NT_SUCCESS(Status))
        throw formatted_error("NtOpenKey returned {:08x}.", (uint32_t)Status);

    Status = NtDeleteKey(h);

    NtClose(h);

    if (!NT_SUCCESS(Status))
        throw formatted_error("NtDeleteKey returned {:08x}.", (uint32_t)Status);
}