#include "muwine.h"
#include "sec.h"
#include "proc.h"

static const uint8_t sid_users[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x21, 0x2, 0, 0 }; // S-1-5-32-545
static const uint8_t sid_administrators[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x2, 0, 0 }; // S-1-5-32-544
static const uint8_t sid_local_system[] = { 1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0 }; // S-1-5-18
static const uint8_t sid_creator_owner[] = { 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0 }; // S-1-3-0

typedef struct {
    unsigned int num;
    bool enabled;
} default_privilege;

static const default_privilege def_user_privs[] = {
    { SE_SHUTDOWN_PRIVILEGE, false },
    { SE_CHANGE_NOTIFY_PRIVILEGE, true },
    { SE_UNDOCK_PRIVILEGE, false },
    { SE_INC_WORKING_SET_PRIVILEGE, false },
    { SE_TIME_ZONE_PRIVILEGE, false }
};

// these are what Windows gives LocalSystem
static const default_privilege def_root_privs[] = {
    { SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, false },
    { SE_AUDIT_PRIVILEGE, true },
    { SE_BACKUP_PRIVILEGE, false },
    { SE_CHANGE_NOTIFY_PRIVILEGE, true },
    { SE_CREATE_GLOBAL_PRIVILEGE, true },
    { SE_CREATE_PAGEFILE_PRIVILEGE, true },
    { SE_CREATE_PERMANENT_PRIVILEGE, true },
    { SE_CREATE_TOKEN_PRIVILEGE, false },
    { SE_DEBUG_PRIVILEGE, true },
    { SE_IMPERSONATE_PRIVILEGE, true },
    { SE_INC_BASE_PRIORITY_PRIVILEGE, true },
    { SE_INCREASE_QUOTA_PRIVILEGE, false },
    { SE_LOAD_DRIVER_PRIVILEGE, false },
    { SE_LOCK_MEMORY_PRIVILEGE, true },
    { SE_MANAGE_VOLUME_PRIVILEGE, false },
    { SE_PROF_SINGLE_PROCESS_PRIVILEGE, true },
    { SE_RESTORE_PRIVILEGE, false },
    { SE_SECURITY_PRIVILEGE, false },
    { SE_SHUTDOWN_PRIVILEGE, false },
    { SE_SYSTEM_ENVIRONMENT_PRIVILEGE, false },
    { SE_SYSTEMTIME_PRIVILEGE, false },
    { SE_TAKE_OWNERSHIP_PRIVILEGE, false },
    { SE_TCB_PRIVILEGE, true },
    { SE_UNDOCK_PRIVILEGE, false }
};

static type_object* token_type = NULL;
static uint64_t last_luid = 1000;

static void token_object_close(object_header* obj) {
    token_object* tok = (token_object*)obj;

    if (tok->user)
        kfree(tok->user);

    if (tok->groups) {
        unsigned int i;

        for (i = 0; i < tok->groups->GroupCount; i++) {
            kfree(tok->groups->Groups[i].Sid);
        }

        kfree(tok->groups);
    }

    if (tok->privs)
        kfree(tok->privs);

    if (tok->default_dacl)
        kfree(tok->default_dacl);

    free_object(&tok->header);
}

static unsigned int __inline sid_length(SID* sid) {
    return offsetof(SID, SubAuthority[0]) + (sid->SubAuthorityCount * sizeof(uint32_t));
}

static unsigned int inherited_acl_length(ACL* acl, bool container) {
    unsigned int len = sizeof(ACL);
    unsigned int i;
    ACE_HEADER* h;

    h = (ACE_HEADER*)&acl[1];

    for (i = 0; i < acl->AceCount; i++) {
        if ((container && h->AceFlags & CONTAINER_INHERIT_ACE) || (!container && h->AceFlags & OBJECT_INHERIT_ACE))
            len += h->AceSize;

        h = (ACE_HEADER*)((uint8_t*)h + h->AceSize);
    }

    return len;
}

static void get_inherited_acl(ACL* src, ACL* dest, bool container) {
    ACE_HEADER* src_ace;
    ACE_HEADER* dest_ace;
    unsigned int i;

    dest->AclRevision = 2;
    dest->Sbz1 = 0;
    dest->AclSize = sizeof(ACL); // FIXME
    dest->AceCount = 0;
    dest->Sbz2 = 0;

    src_ace = (ACE_HEADER*)&src[1];
    dest_ace = (ACE_HEADER*)&dest[1];

    for (i = 0; i < src->AceCount; i++) {
        if ((container && src_ace->AceFlags & CONTAINER_INHERIT_ACE) || (!container && src_ace->AceFlags & OBJECT_INHERIT_ACE)) {
            dest->AclSize += src_ace->AceSize;
            dest->AceCount++;

            memcpy(dest_ace, src_ace, src_ace->AceSize);

            dest_ace->AceFlags |= INHERITED_ACE;

            if (dest_ace->AceFlags & NO_PROPAGATE_INHERIT_ACE)
                dest_ace->AceFlags &= (uint8_t)~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

            dest_ace->AceFlags &= (uint8_t)~INHERIT_ONLY_ACE;

            dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }
}

NTSTATUS muwine_create_inherited_sd(const SECURITY_DESCRIPTOR_RELATIVE* parent_sd, unsigned int parent_sd_len, bool container,
                                    token_object* tok, SECURITY_DESCRIPTOR_RELATIVE** out, unsigned int* outlen) {
    unsigned int len = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    uint8_t* ptr;
    unsigned int sacl_length = 0, dacl_length = 0;

    // FIXME - check parent_sd is valid

    if (tok && tok->owner)
        len += sid_length(tok->owner);

    if (tok && tok->primary_group)
        len += sid_length(tok->primary_group);

    if (parent_sd->Sacl != 0) {
        sacl_length = inherited_acl_length((ACL*)((uint8_t*)parent_sd + parent_sd->Sacl), container);
        len += sacl_length;
    }

    if (parent_sd->Dacl != 0) {
        dacl_length = inherited_acl_length((ACL*)((uint8_t*)parent_sd + parent_sd->Dacl), container);
        len += dacl_length;
    }

    sd = kmalloc(len, GFP_KERNEL);

    if (!sd)
        return STATUS_INSUFFICIENT_RESOURCES;

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE;

    if (parent_sd->Sacl != 0)
        sd->Control |= SE_SACL_PRESENT;

    if (parent_sd->Dacl != 0)
        sd->Control |= SE_DACL_PRESENT;

    ptr = (uint8_t*)&sd[1];

    if (tok && tok->owner) {
        unsigned int sidlen = sid_length(tok->owner);

        sd->Owner = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, tok->owner, sidlen);
        ptr += sidlen;
    } else
        sd->Owner = 0;

    if (tok && tok->primary_group) {
        unsigned int sidlen = sid_length(tok->primary_group);

        sd->Group = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, tok->primary_group, sidlen);
        ptr += sidlen;
    } else
        sd->Group = 0;

    if (parent_sd->Sacl != 0) {
        sd->Sacl = (uint32_t)(ptr - (uint8_t*)sd);

        get_inherited_acl((ACL*)((uint8_t*)parent_sd + parent_sd->Sacl),
                          (ACL*)((uint8_t*)sd + sd->Sacl), container);

        ptr += sacl_length;
    } else
        sd->Sacl = 0;

    if (parent_sd->Dacl != 0) {
        sd->Dacl = (uint32_t)(ptr - (uint8_t*)sd);

        get_inherited_acl((ACL*)((uint8_t*)parent_sd + parent_sd->Dacl),
                          (ACL*)((uint8_t*)sd + sd->Dacl), container);

        ptr += dacl_length;
    } else
        sd->Dacl = 0;

    *out = sd;
    *outlen = len;

    return STATUS_SUCCESS;
}

static void uid_to_sid(SID** sid, kuid_t uid) {
    SID* s;

    // FIXME - allow overrides in Registry
    // FIXME - map root separately

    // FIXME - create from machine SID

#if 1 // Samba's scheme
    // use Samba's S-1-22-1 mappings

    s = kmalloc(offsetof(SID, SubAuthority) + (2 * sizeof(uint32_t)), GFP_KERNEL);
    // FIXME - handle malloc failure

    s->Revision = 1;
    s->SubAuthorityCount = 2;
    s->IdentifierAuthority[0] = 0;
    s->IdentifierAuthority[1] = 0;
    s->IdentifierAuthority[2] = 0;
    s->IdentifierAuthority[3] = 0;
    s->IdentifierAuthority[4] = 0;
    s->IdentifierAuthority[5] = 22;
    s->SubAuthority[0] = 1;
    s->SubAuthority[1] = (uint32_t)uid.val;
#else // Wine's scheme
    if (uid.val == 1000) { // S-1-5-21-0-0-0-1000
        s = kmalloc(offsetof(SID, SubAuthority) + (5 * sizeof(uint32_t)), GFP_KERNEL);
        // FIXME - handle malloc failure

        s->Revision = 1;
        s->SubAuthorityCount = 5;
        s->IdentifierAuthority[0] = 0;
        s->IdentifierAuthority[1] = 0;
        s->IdentifierAuthority[2] = 0;
        s->IdentifierAuthority[3] = 0;
        s->IdentifierAuthority[4] = 0;
        s->IdentifierAuthority[5] = 5;
        s->SubAuthority[0] = 21;
        s->SubAuthority[1] = 0;
        s->SubAuthority[2] = 0;
        s->SubAuthority[3] = 0;
        s->SubAuthority[4] = 1000;
    } else { // S-1-5-7, Anonymous
        s = kmalloc(offsetof(SID, SubAuthority) + sizeof(uint32_t), GFP_KERNEL);
        // FIXME - handle malloc failure

        s->Revision = 1;
        s->SubAuthorityCount = 1;
        s->IdentifierAuthority[0] = 0;
        s->IdentifierAuthority[1] = 0;
        s->IdentifierAuthority[2] = 0;
        s->IdentifierAuthority[3] = 0;
        s->IdentifierAuthority[4] = 0;
        s->IdentifierAuthority[5] = 5;
        s->SubAuthority[0] = 7;
    }
#endif

    *sid = s;
}

static void gid_to_sid(SID** sid, kgid_t gid) {
    SID* s;

    // FIXME - allow overrides in Registry

    // use Samba's S-1-22-2 mappings

    s = kmalloc(offsetof(SID, SubAuthority) + (2 * sizeof(uint32_t)), GFP_KERNEL);
    // FIXME - handle malloc failure

    s->Revision = 1;
    s->SubAuthorityCount = 2;
    s->IdentifierAuthority[0] = 0;
    s->IdentifierAuthority[1] = 0;
    s->IdentifierAuthority[2] = 0;
    s->IdentifierAuthority[3] = 0;
    s->IdentifierAuthority[4] = 0;
    s->IdentifierAuthority[5] = 22;
    s->SubAuthority[0] = 2;
    s->SubAuthority[1] = (uint32_t)gid.val;

    *sid = s;
}

static SID* duplicate_sid(SID* in) {
    SID* out;
    size_t size;

    size = sid_length(in);

    out = kmalloc(size, GFP_KERNEL);
    // FIXME - handle malloc failure

    memcpy(out, in, size);

    return out;
}

static NTSTATUS get_current_process_groups(token_object* tok) {
    NTSTATUS Status;
    struct group_info* groups;
    kgid_t primary_group;
    bool primary_group_in_list;
    unsigned int num_groups, i;

    primary_group = current_egid();

    groups = get_current_groups();
    primary_group_in_list = false;

    for (i = 0; i < groups->ngroups; i++) {
        kgid_t gid = groups->gid[i];

        if (gid.val == primary_group.val) {
            primary_group_in_list = true;
            break;
        }
    }

    num_groups = groups->ngroups;

    if (!primary_group_in_list)
        num_groups++;

    tok->groups = kmalloc(offsetof(TOKEN_GROUPS, Groups) + (num_groups * sizeof(SID_AND_ATTRIBUTES)),
                          GFP_KERNEL);
    if (!tok->groups) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    tok->groups->GroupCount = num_groups;

    for (i = 0; i < groups->ngroups; i++) {
        gid_to_sid(&tok->groups->Groups[i].Sid, groups->gid[i]);
        tok->groups->Groups[i].Attributes =
            SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

        if (groups->gid[i].val == primary_group.val)
            tok->primary_group = tok->groups->Groups[i].Sid;
    }

    if (!primary_group_in_list) {
        gid_to_sid(&tok->groups->Groups[groups->ngroups].Sid, primary_group);
        tok->groups->Groups[groups->ngroups].Attributes =
            SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

        tok->primary_group = tok->groups->Groups[groups->ngroups].Sid;
    }

    Status = STATUS_SUCCESS;

end:
    put_group_info(groups);

    return Status;
}

static void alloc_luid(LUID* luid) {
    uint64_t val;

    val = __sync_add_and_fetch(&last_luid, 1);

    luid->LowPart = val & 0xffffffff;
    luid->HighPart = val >> 32;
}

static NTSTATUS NtAllocateLocallyUniqueId(PLUID Luid) {
    alloc_luid(Luid);

    return STATUS_SUCCESS;
}

NTSTATUS user_NtAllocateLocallyUniqueId(PLUID Luid) {
    NTSTATUS Status;
    LUID l;

    if (!Luid)
        return STATUS_INVALID_PARAMETER;

    Status = NtAllocateLocallyUniqueId(&l);

    if (put_user(l, Luid) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

void muwine_make_process_token(token_object** t) {
    token_object* tok;
    unsigned int priv_count, i;
    const default_privilege* def_privs;
    size_t dacl_size;
    ACCESS_ALLOWED_ACE* aaa;

    tok = (token_object*)muwine_alloc_object(sizeof(token_object), token_type);
    // FIXME - handle malloc failure

    init_rwsem(&tok->sem);

    uid_to_sid(&tok->user, current_euid());

    get_current_process_groups(tok); // FIXME - handle errors

    tok->owner = tok->user;

    if (current_euid().val == 0) { // root
        priv_count = sizeof(def_root_privs) / sizeof(default_privilege);
        def_privs = def_root_privs;
    } else {
        priv_count = sizeof(def_user_privs) / sizeof(default_privilege);
        def_privs = def_user_privs;
    }

    tok->privs = kmalloc(offsetof(TOKEN_PRIVILEGES, Privileges) +
                         (sizeof(LUID_AND_ATTRIBUTES) * priv_count), GFP_KERNEL);
    // FIXME - handle malloc failure

    tok->privs->PrivilegeCount = priv_count;

    for (i = 0; i < priv_count; i++) {
        tok->privs->Privileges[i].Luid.LowPart = def_privs[i].num;
        tok->privs->Privileges[i].Luid.HighPart = 0;

        if (def_privs[i].enabled) {
            tok->privs->Privileges[i].Attributes =
                SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        } else
            tok->privs->Privileges[i].Attributes = 0;
    }

    tok->auth_id.LowPart = 0x3e7; // SYSTEM_LUID
    tok->auth_id.HighPart = 0;

    strcpy(tok->source.SourceName, "SeMgr");

    tok->type = TokenPrimary;

    dacl_size = sizeof(ACL);
    dacl_size += 2 * offsetof(ACCESS_ALLOWED_ACE, SidStart);
    dacl_size += sid_length(tok->owner);
    dacl_size += sizeof(sid_local_system);
    // FIXME - don't duplicate ACE if owner is same as sid_local_system

    tok->default_dacl = kmalloc(dacl_size, GFP_KERNEL);
    // FIXME - handle malloc failure

    // FIXME - should also have ACE for logon SID and GENERIC_READ | GENERIC_EXECUTE

    tok->default_dacl->AclRevision = 2;
    tok->default_dacl->Sbz1 = 0;
    tok->default_dacl->AclSize = dacl_size;
    tok->default_dacl->AceCount = 2;
    tok->default_dacl->Sbz2 = 0;

    aaa = (ACCESS_ALLOWED_ACE*)&tok->default_dacl[1];
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = 0;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sid_length(tok->owner);
    aaa->Mask = GENERIC_ALL;
    memcpy(&aaa->SidStart, tok->owner, sid_length(tok->owner));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)aaa + aaa->Header.AceSize);
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = 0;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_local_system);
    aaa->Mask = GENERIC_ALL;
    memcpy(&aaa->SidStart, sid_local_system, sizeof(sid_local_system));

    alloc_luid(&tok->token_id);
    alloc_luid(&tok->modified_id);

    tok->expiry = 0x7fffffffffffffff;

    *t = tok;
}

void muwine_registry_root_sd(SECURITY_DESCRIPTOR_RELATIVE** out, unsigned int* sdlen) {
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    unsigned int len = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    unsigned int dacl_len;
    ACL* sacl;
    ACL* dacl;
    ACCESS_ALLOWED_ACE* aaa;

    len += sizeof(sid_administrators); // owner
    len += sizeof(sid_local_system); // group
    len += sizeof(ACL); // SACL

    // DACL
    dacl_len = sizeof(ACL);
    dacl_len += 4 * offsetof(ACCESS_ALLOWED_ACE, SidStart);
    dacl_len += sizeof(sid_users);
    dacl_len += sizeof(sid_administrators);
    dacl_len += sizeof(sid_local_system);
    dacl_len += sizeof(sid_creator_owner);
    len += dacl_len;

    sd = kmalloc(len, GFP_KERNEL);
    // FIXME - handle malloc failures

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT;
    sd->Owner = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    sd->Group = sd->Owner + sizeof(sid_administrators);
    sd->Sacl = sd->Group + sizeof(sid_local_system);
    sd->Dacl = sd->Sacl + sizeof(ACL);

    memcpy((uint8_t*)sd + sd->Owner, sid_administrators, sizeof(sid_administrators));
    memcpy((uint8_t*)sd + sd->Group, sid_local_system, sizeof(sid_local_system));

    sacl = (ACL*)((uint8_t*)sd + sd->Sacl);
    dacl = (ACL*)((uint8_t*)sd + sd->Dacl);

    sacl->AclRevision = 2;
    sacl->Sbz1 = 0;
    sacl->AclSize = sizeof(ACL);
    sacl->AceCount = 0;
    sacl->Sbz2 = 0;

    dacl->AclRevision = 2;
    dacl->Sbz1 = 0;
    dacl->AclSize = dacl_len;
    dacl->AceCount = 4;
    dacl->Sbz2 = 0;

    aaa = (ACCESS_ALLOWED_ACE*)&dacl[1];
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_users);
    aaa->Mask = READ_CONTROL | KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE;
    memcpy(&aaa->SidStart, sid_users, sizeof(sid_users));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa->SidStart + sizeof(sid_users));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_administrators);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa->SidStart, sid_administrators, sizeof(sid_administrators));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa->SidStart + sizeof(sid_administrators));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_local_system);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa->SidStart, sid_local_system, sizeof(sid_local_system));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa->SidStart + sizeof(sid_local_system));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_creator_owner);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa->SidStart, sid_creator_owner, sizeof(sid_creator_owner));

    *out = sd;
    *sdlen = len;
}

ACCESS_MASK sanitize_access_mask(ACCESS_MASK access, type_object* type) {
    if (access & MAXIMUM_ALLOWED)
        return MAXIMUM_ALLOWED;

    if (access & GENERIC_READ) {
        access &= ~GENERIC_READ;
        access |= type->generic_read;
    }

    if (access & GENERIC_WRITE) {
        access &= ~GENERIC_WRITE;
        access |= type->generic_write;
    }

    if (access & GENERIC_EXECUTE) {
        access &= ~GENERIC_EXECUTE;
        access |= type->generic_execute;
    }

    if (access & GENERIC_ALL) {
        access &= ~GENERIC_ALL;
        access |= type->generic_all;
    }

    access &= type->valid;

    return access;
}

static bool __inline sid_equal(PSID sid1, PSID sid2) {
    size_t size1 = sid_length(sid1);
    size_t size2 = sid_length(sid2);

    if (size1 != size2)
        return false;

    return !memcmp(sid1, sid2, size1);
}

static bool check_privilege(DWORD priv) {
    process_object* proc;
    token_object* tok;
    unsigned int i;
    bool found = false;

    proc = muwine_current_process_object();

    if (!proc)
        return false;

    // FIXME - should be thread token if impersonating

    tok = proc->token;
    inc_obj_refcount(&tok->header);

    dec_obj_refcount(&proc->header.h);

    down_read(&tok->sem);

    for (i = 0; i < tok->privs->PrivilegeCount; i++) {
        if (tok->privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED &&
            tok->privs->Privileges[i].Luid.HighPart == 0 &&
            tok->privs->Privileges[i].Luid.LowPart == priv) {
            found = true;
            break;
        }
    }

    up_read(&tok->sem);

    dec_obj_refcount(&tok->header);

    return found;
}

static NTSTATUS NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                              PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                              PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                              PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                              PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                              PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource) {
    NTSTATUS Status;
    token_object* tok;
    ACCESS_MASK access;
    unsigned int i;
    size_t privsize;
    SECURITY_IMPERSONATION_LEVEL impersonation_level;

    if (!check_privilege(SE_CREATE_TOKEN_PRIVILEGE))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (TokenType != TokenPrimary && TokenType != TokenImpersonation)
        return STATUS_INVALID_PARAMETER;

    if (TokenType == TokenImpersonation) {
        SECURITY_QUALITY_OF_SERVICE* qos;

        if (!ObjectAttributes || !ObjectAttributes->SecurityQualityOfService)
            return STATUS_BAD_IMPERSONATION_LEVEL;

        qos = ObjectAttributes->SecurityQualityOfService;

        if (qos->Length < sizeof(SECURITY_QUALITY_OF_SERVICE))
            return STATUS_INVALID_PARAMETER;

        impersonation_level = qos->ImpersonationLevel;

        if (impersonation_level != SecurityAnonymous && impersonation_level != SecurityIdentification &&
            impersonation_level != SecurityImpersonation && impersonation_level != SecurityDelegation) {
            return STATUS_BAD_IMPERSONATION_LEVEL;
        }
    }

    tok = (token_object*)muwine_alloc_object(sizeof(token_object), token_type);
    if (!tok)
        return STATUS_INSUFFICIENT_RESOURCES;

    init_rwsem(&tok->sem);

    tok->auth_id.LowPart = AuthenticationId->LowPart;
    tok->auth_id.HighPart = AuthenticationId->HighPart;

    tok->expiry = ExpirationTime->QuadPart;

    tok->user = duplicate_sid(TokenUser->User.Sid);

    if (!TokenOwner || sid_equal(tok->user, TokenOwner->Owner))
        tok->owner = tok->user;

    tok->groups = kmalloc(offsetof(TOKEN_GROUPS, Groups) + (sizeof(SID_AND_ATTRIBUTES) * TokenGroups->GroupCount),
                          GFP_KERNEL);
    if (!tok->groups) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    tok->groups->GroupCount = TokenGroups->GroupCount;
    for (i = 0; i < TokenGroups->GroupCount; i++) {
        tok->groups->Groups[i].Attributes = TokenGroups->Groups[i].Attributes;
        tok->groups->Groups[i].Sid = duplicate_sid(TokenGroups->Groups[i].Sid);

        if (sid_equal(tok->groups->Groups[i].Sid, TokenPrimaryGroup->PrimaryGroup))
            tok->primary_group = tok->groups->Groups[i].Sid;

        if (!tok->owner && sid_equal(tok->groups->Groups[i].Sid, TokenOwner->Owner))
            tok->owner = tok->groups->Groups[i].Sid;
    }

    if (!tok->primary_group || !tok->owner) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    privsize = offsetof(TOKEN_PRIVILEGES, Privileges) +
               (sizeof(LUID_AND_ATTRIBUTES) * TokenPrivileges->PrivilegeCount);

    tok->privs = kmalloc(privsize, GFP_KERNEL);
    if (!tok->privs) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    memcpy(tok->privs, TokenPrivileges, privsize);

    memcpy(&tok->source, TokenSource, sizeof(TOKEN_SOURCE));

    if (TokenDefaultDacl) {
        tok->default_dacl = kmalloc(TokenDefaultDacl->DefaultDacl->AclSize, GFP_KERNEL);
        if (!tok->default_dacl) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        memcpy(tok->default_dacl, TokenDefaultDacl->DefaultDacl,
               TokenDefaultDacl->DefaultDacl->AclSize);
    }

    tok->type = TokenType;

    alloc_luid(&tok->token_id);
    alloc_luid(&tok->modified_id);

    if (TokenType == TokenImpersonation)
        tok->impersonation_level = impersonation_level;

    // add handle

    access = sanitize_access_mask(DesiredAccess, token_type);

    if (access == MAXIMUM_ALLOWED)
        access = TOKEN_ALL_ACCESS;

    Status = muwine_add_handle(&tok->header, TokenHandle,
                               ObjectAttributes ? ObjectAttributes->Attributes & OBJ_KERNEL_HANDLE : false,
                               access);

end:
    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&tok->header);

    return Status;
}

static bool get_user_sid(PSID* ks, const __user PSID us) {
    uint8_t count;
    PSID sid;

    if (get_user(count, &us->SubAuthorityCount) < 0)
        return false;

    sid = kmalloc(offsetof(SID, SubAuthority) + (sizeof(uint32_t) * count), GFP_KERNEL);
    if (!sid)
        return false;

    if (copy_from_user(sid, us, offsetof(SID, SubAuthority) + (sizeof(uint32_t) * count)) != 0) {
        kfree(sid);
        return false;
    }

    *ks = sid;

    return true;
}

static bool get_user_token_groups(TOKEN_GROUPS** ks, const __user TOKEN_GROUPS* us) {
    DWORD count;
    TOKEN_GROUPS* g;
    unsigned int i;

    if (get_user(count, &us->GroupCount) < 0)
        return false;

    g = kmalloc(offsetof(TOKEN_GROUPS, Groups) + (count * sizeof(SID_AND_ATTRIBUTES)),
                GFP_KERNEL);
    if (!g)
        return false;

    g->GroupCount = count;

    for (i = 0; i < count; i++) {
        unsigned int j;
        PSID sid;

        if (get_user(g->Groups[i].Attributes, &us->Groups[i].Attributes) < 0)
            goto fail;

        if (get_user(sid, &us->Groups[i].Sid) < 0)
            goto fail;

        if (!get_user_sid(&g->Groups[i].Sid, sid))
            goto fail;

        continue;

fail:
        for (j = 0; j < i; j++) {
            kfree(g->Groups[j].Sid);
        }

        kfree(g);

        return false;
    }

    *ks = g;

    return true;
}

static bool get_user_token_privileges(TOKEN_PRIVILEGES** ks, const __user TOKEN_PRIVILEGES* us) {
    DWORD count;
    TOKEN_PRIVILEGES* priv;
    size_t size;

    if (get_user(count, &us->PrivilegeCount) < 0)
        return false;

    size = offsetof(TOKEN_PRIVILEGES, Privileges) + (count * sizeof(LUID_AND_ATTRIBUTES));

    priv = kmalloc(size, GFP_KERNEL);
    if (!priv)
        return false;

    if (copy_from_user(priv, us, size) != 0) {
        kfree(priv);
        return false;
    }

    *ks = priv;

    return true;
}

static bool get_user_acl(PACL* ks, const __user PACL us) {
    uint16_t size;
    PACL acl;

    if (get_user(size, &us->AclSize) < 0)
        return false;

    if (size == 0)
        return false;

    acl = kmalloc(size, GFP_KERNEL);
    if (!acl)
        return false;

    if (copy_from_user(acl, us, size) != 0) {
        kfree(acl);
        return false;
    }

    *ks = acl;

    return true;
}

NTSTATUS user_NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                            POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                            PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                            PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                            PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                            PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                            PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource) {
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    LUID auth_id;
    LARGE_INTEGER expiry;
    TOKEN_SOURCE source;
    PSID sid;
    TOKEN_OWNER owner;
    TOKEN_PRIMARY_GROUP primary_group;
    TOKEN_USER user;
    TOKEN_GROUPS* groups;
    TOKEN_PRIVILEGES* privs;
    TOKEN_DEFAULT_DACL default_dacl;
    unsigned int i;

    if (!TokenHandle || !AuthenticationId || !ExpirationTime || !TokenUser ||
        !TokenGroups || !TokenPrivileges || !TokenPrimaryGroup || !TokenSource) {
        return STATUS_INVALID_PARAMETER;
    }

    if (copy_from_user(&auth_id, AuthenticationId, sizeof(LUID)) != 0)
        return STATUS_ACCESS_VIOLATION;

    if (get_user(expiry.QuadPart, &ExpirationTime->QuadPart) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (copy_from_user(&source, TokenSource, sizeof(TOKEN_SOURCE)) != 0)
        return STATUS_ACCESS_VIOLATION;

    if (TokenOwner) {
        if (get_user(sid, &TokenOwner->Owner) < 0)
            return STATUS_ACCESS_VIOLATION;

        if (!get_user_sid(&owner.Owner, sid))
            return STATUS_ACCESS_VIOLATION;
    }

    if (get_user(sid, &TokenPrimaryGroup->PrimaryGroup) < 0) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end7;
    }

    if (!get_user_sid(&primary_group.PrimaryGroup, sid)) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end7;
    }

    if (get_user(user.User.Attributes, &TokenUser->User.Attributes) < 0) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end6;
    }

    if (get_user(sid, &TokenUser->User.Sid) < 0) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end6;
    }

    if (!get_user_sid(&user.User.Sid, sid)) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end6;
    }

    if (!get_user_token_groups(&groups, TokenGroups)) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end5;
    }

    if (!get_user_token_privileges(&privs, TokenPrivileges)) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end4;
    }

    if (TokenDefaultDacl) {
        PACL acl;

        if (get_user(acl, &TokenDefaultDacl->DefaultDacl) < 0) {
            Status = STATUS_ACCESS_VIOLATION;
            goto end3;
        }

        if (!get_user_acl(&default_dacl.DefaultDacl, acl)) {
            Status = STATUS_ACCESS_VIOLATION;
            goto end3;
        }
    }

    if (ObjectAttributes && !get_user_object_attributes(&oa, ObjectAttributes)) {
        Status = STATUS_ACCESS_VIOLATION;
        goto end2;
    }

    if (ObjectAttributes && oa.Attributes & OBJ_KERNEL_HANDLE) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Status = NtCreateToken(&h, DesiredAccess, ObjectAttributes ? &oa : NULL,
                           TokenType, &auth_id, &expiry, &user, groups,
                           privs, TokenOwner ? &owner : NULL, &primary_group,
                           TokenDefaultDacl ? &default_dacl : NULL, &source);

    if (put_user(h, TokenHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

end:
    if (ObjectAttributes)
        free_object_attributes(&oa);

end2:
    if (TokenDefaultDacl)
        kfree(default_dacl.DefaultDacl);

end3:
    kfree(privs);

end4:
    for (i = 0; i < groups->GroupCount; i++) {
        kfree(groups->Groups[i].Sid);
    }

    kfree(groups);

end5:
    kfree(user.User.Sid);

end6:
    kfree(primary_group.PrimaryGroup);

end7:
    if (TokenOwner)
        kfree(owner.Owner);

    return Status;
}

static NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                   PHANDLE TokenHandle) {
    NTSTATUS Status;
    process_object* proc;
    token_object* tok;
    ACCESS_MASK access;

    if (ProcessHandle == NtCurrentProcess()) {
        proc = muwine_current_process_object();

        tok = proc->token;
        inc_obj_refcount(&tok->header);

        dec_obj_refcount(&proc->header.h);
    } else {
        proc = (process_object*)get_object_from_handle(ProcessHandle, &access);
        if (!proc)
            return STATUS_INVALID_HANDLE;

        if (proc->header.h.type != process_type) {
            dec_obj_refcount(&proc->header.h);
            return STATUS_INVALID_HANDLE;
        }

        if (!(access & PROCESS_QUERY_INFORMATION)) {
            dec_obj_refcount(&proc->header.h);
            return STATUS_ACCESS_DENIED;
        }

        tok = proc->token;
        inc_obj_refcount(&tok->header);

        dec_obj_refcount(&proc->header.h);
    }

    // FIXME - check DesiredAccess against token SD

    access = sanitize_access_mask(DesiredAccess, token_type);

    if (access == MAXIMUM_ALLOWED)
        access = TOKEN_ALL_ACCESS;

    Status = muwine_add_handle(&tok->header, TokenHandle, false, access);

    if (!NT_SUCCESS(Status))
        dec_obj_refcount(&tok->header);

    return Status;
}

NTSTATUS user_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                 PHANDLE TokenHandle) {
    NTSTATUS Status;
    HANDLE h;

    if (!TokenHandle)
        return STATUS_INVALID_PARAMETER;

    if (ProcessHandle != NtCurrentProcess() && (uintptr_t)ProcessHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    Status = NtOpenProcessToken(ProcessHandle, DesiredAccess, &h);

    if (put_user(h, TokenHandle) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                           BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {
    printk(KERN_INFO "NtOpenThreadToken(%lx, %x, %x, %px): stub\n",
           (uintptr_t)ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static bool __inline luid_equal(const LUID* luid1, const LUID* luid2) {
    return luid1->LowPart == luid2->LowPart && luid1->HighPart == luid2->HighPart;
}

static NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                        PTOKEN_PRIVILEGES TokenPrivileges,
                                        ULONG PreviousPrivilegesLength,
                                        PTOKEN_PRIVILEGES PreviousPrivileges,
                                        PULONG RequiredLength) {
    NTSTATUS Status;
    token_object* tok;
    ACCESS_MASK access;
    unsigned int i, j;
    bool not_all_assigned = false;

    tok = (token_object*)get_object_from_handle(TokenHandle, &access);
    if (!tok)
        return STATUS_INVALID_HANDLE;

    if (tok->header.type != token_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    if (!(access & TOKEN_ADJUST_PRIVILEGES)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (PreviousPrivileges && !(access & TOKEN_QUERY)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    down_write(&tok->sem);

    if (PreviousPrivileges) {
        unsigned int changed = 0;
        ULONG len;
        LUID_AND_ATTRIBUTES* laa;

        for (i = 0; i < TokenPrivileges->PrivilegeCount; i++) {
            if (!DisableAllPrivileges && TokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED)
                continue;

            for (j = 0; j < tok->privs->PrivilegeCount; j++) {
                if (luid_equal(&TokenPrivileges->Privileges[i].Luid, &tok->privs->Privileges[j].Luid)) {
                    changed++;
                    break;
                }
            }
        }

        len = offsetof(TOKEN_PRIVILEGES, Privileges) + (sizeof(LUID_AND_ATTRIBUTES) * changed);

        if (RequiredLength)
            *RequiredLength = len;

        if (PreviousPrivilegesLength < len) {
            Status = STATUS_BUFFER_TOO_SMALL;
            goto end2;
        }

        // copy previous privileges

        PreviousPrivileges->PrivilegeCount = 0;
        laa = &PreviousPrivileges->Privileges[0];

        for (i = 0; i < TokenPrivileges->PrivilegeCount; i++) {
            if (!DisableAllPrivileges && TokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED)
                continue;

            for (j = 0; j < tok->privs->PrivilegeCount; j++) {
                if (luid_equal(&TokenPrivileges->Privileges[i].Luid, &tok->privs->Privileges[j].Luid)) {
                    laa->Luid.LowPart = tok->privs->Privileges[j].Luid.LowPart;
                    laa->Luid.HighPart = tok->privs->Privileges[j].Luid.HighPart;
                    laa->Attributes = tok->privs->Privileges[j].Attributes;

                    laa++;

                    break;
                }
            }
        }
    }

    // enable or disable privileges

    if (DisableAllPrivileges) {
        for (i = 0; i < tok->privs->PrivilegeCount; i++) {
            tok->privs->Privileges[i].Attributes &= ~SE_PRIVILEGE_ENABLED;
        }

        Status = STATUS_SUCCESS;

        goto end2;
    }

    for (i = 0; i < TokenPrivileges->PrivilegeCount; i++) {
        bool found = false;

        for (j = 0; j < tok->privs->PrivilegeCount; j++) {
            if (luid_equal(&TokenPrivileges->Privileges[i].Luid, &tok->privs->Privileges[j].Luid)) {
                if (TokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_REMOVED) {
                    memcpy(&tok->privs->Privileges[j], &tok->privs->Privileges[j + 1],
                           sizeof(LUID_AND_ATTRIBUTES) * (tok->privs->PrivilegeCount - j - 1));
                    tok->privs->PrivilegeCount--;
                } else {
                    if (TokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                        tok->privs->Privileges[j].Attributes |= SE_PRIVILEGE_ENABLED;
                    else
                        tok->privs->Privileges[j].Attributes &= ~SE_PRIVILEGE_ENABLED;
                }

                found = true;

                break;
            }
        }

        if (!found)
            not_all_assigned = true;
    }

    Status = not_all_assigned ? STATUS_NOT_ALL_ASSIGNED : STATUS_SUCCESS;

end2:
    up_write(&tok->sem);

end:
    dec_obj_refcount(&tok->header);

    return Status;
}

NTSTATUS user_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                      PTOKEN_PRIVILEGES TokenPrivileges,
                                      ULONG PreviousPrivilegesLength,
                                      PTOKEN_PRIVILEGES PreviousPrivileges,
                                      PULONG RequiredLength) {
    NTSTATUS Status;
    TOKEN_PRIVILEGES* privs;
    ULONG reqlen;
    TOKEN_PRIVILEGES* prev;

    if (!TokenPrivileges)
        return STATUS_INVALID_PARAMETER;

    if ((uintptr_t)TokenHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (!get_user_token_privileges(&privs, TokenPrivileges))
        return STATUS_ACCESS_VIOLATION;

    if (PreviousPrivilegesLength > 0) {
        prev = kmalloc(PreviousPrivilegesLength, GFP_KERNEL);
        if (!prev)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, privs,
                                     PreviousPrivilegesLength,
                                     PreviousPrivilegesLength > 0 ? prev : NULL,
                                     RequiredLength ? &reqlen : NULL);

    if (PreviousPrivilegesLength > 0) {
        if (copy_to_user(PreviousPrivileges, prev, PreviousPrivilegesLength) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(prev);
    }

    if (RequiredLength && put_user(reqlen, RequiredLength) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    kfree(privs);

    return Status;
}

static NTSTATUS NtQueryInformationToken(HANDLE TokenHandle,
                                        TOKEN_INFORMATION_CLASS TokenInformationClass,
                                        PVOID TokenInformation, ULONG TokenInformationLength,
                                        PULONG ReturnLength) {
    NTSTATUS Status;
    token_object* tok;
    ACCESS_MASK access;

    tok = (token_object*)get_object_from_handle(TokenHandle, &access);
    if (!tok)
        return STATUS_INVALID_HANDLE;

    if (tok->header.type != token_type) {
        Status = STATUS_INVALID_HANDLE;
        goto end;
    }

    down_read(&tok->sem);

    switch (TokenInformationClass) {
        case TokenUser: {
            TOKEN_USER* tu = (TOKEN_USER*)TokenInformation;
            size_t size;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            size = sid_length(tok->user);

            *ReturnLength = sizeof(TOKEN_USER) + size;

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            tu->User.Attributes = 0;
            tu->User.Sid = (PSID)&tu[1];

            memcpy(tu->User.Sid, tok->user, size);

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenGroups: {
            TOKEN_GROUPS* tg = (TOKEN_GROUPS*)TokenInformation;
            unsigned int i;
            uint8_t* buf;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            *ReturnLength = offsetof(TOKEN_GROUPS, Groups);
            *ReturnLength += sizeof(SID_AND_ATTRIBUTES) * tok->groups->GroupCount;

            buf = (uint8_t*)TokenInformation + *ReturnLength;

            for (i = 0; i < tok->groups->GroupCount; i++) {
                *ReturnLength += sid_length(tok->groups->Groups[i].Sid);
            }

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            tg->GroupCount = tok->groups->GroupCount;

            for (i = 0; i < tok->groups->GroupCount; i++) {
                size_t size = sid_length(tok->groups->Groups[i].Sid);

                tg->Groups[i].Attributes = tok->groups->Groups[i].Attributes;
                tg->Groups[i].Sid = (PSID)buf;

                memcpy(buf, tok->groups->Groups[i].Sid, size);
                buf += size;
            }

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenPrimaryGroup: {
            TOKEN_PRIMARY_GROUP* tpg = (TOKEN_PRIMARY_GROUP*)TokenInformation;
            size_t size;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            size = sid_length(tok->primary_group);

            *ReturnLength = sizeof(TOKEN_PRIMARY_GROUP) + size;

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            tpg->PrimaryGroup = (PSID)&tpg[1];

            memcpy(tpg->PrimaryGroup, tok->primary_group, size);

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenPrivileges: {
            TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)TokenInformation;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            *ReturnLength = offsetof(TOKEN_PRIVILEGES, Privileges);
            *ReturnLength += sizeof(LUID_AND_ATTRIBUTES) * tok->privs->PrivilegeCount;

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            memcpy(tp, tok->privs, *ReturnLength);

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenOwner: {
            TOKEN_OWNER* to = (TOKEN_OWNER*)TokenInformation;
            size_t size;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            size = sid_length(tok->owner);

            *ReturnLength = sizeof(TOKEN_OWNER) + size;

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            to->Owner = (PSID)&to[1];

            memcpy(to->Owner, tok->owner, size);

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenImpersonationLevel: {
            SECURITY_IMPERSONATION_LEVEL* sil = (SECURITY_IMPERSONATION_LEVEL*)TokenInformation;

            if (tok->type != TokenImpersonation) {
                Status = STATUS_INVALID_INFO_CLASS;
                break;
            }

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            *ReturnLength = sizeof(SECURITY_IMPERSONATION_LEVEL);

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            *sil = tok->impersonation_level;

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenStatistics: {
            TOKEN_STATISTICS* ts = (TOKEN_STATISTICS*)TokenInformation;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            *ReturnLength = sizeof(TOKEN_STATISTICS);

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            ts->TokenId.LowPart = tok->token_id.LowPart;
            ts->TokenId.HighPart = tok->token_id.HighPart;
            ts->AuthenticationId.LowPart = tok->auth_id.LowPart;
            ts->AuthenticationId.HighPart = tok->auth_id.HighPart;
            ts->ExpirationTime.QuadPart = tok->expiry;
            ts->TokenType = tok->type;
            ts->ImpersonationLevel = tok->impersonation_level;
            ts->DynamicCharged = 0;
            ts->DynamicAvailable = 0;
            ts->GroupCount = tok->groups->GroupCount;
            ts->PrivilegeCount = tok->privs->PrivilegeCount;
            ts->ModifiedId.LowPart = tok->modified_id.LowPart;
            ts->ModifiedId.HighPart = tok->modified_id.HighPart;

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenType: {
            TOKEN_TYPE* type = (TOKEN_TYPE*)TokenInformation;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            *ReturnLength = sizeof(TOKEN_TYPE);

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            *type = tok->type;

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenDefaultDacl: {
            TOKEN_DEFAULT_DACL* tdd = (TOKEN_DEFAULT_DACL*)TokenInformation;

            if (!(access & TOKEN_QUERY)) {
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            if (!tok->default_dacl) {
                *ReturnLength = sizeof(TOKEN_DEFAULT_DACL);

                if (TokenInformationLength < *ReturnLength) {
                    Status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                tdd->DefaultDacl = NULL;
                Status = STATUS_SUCCESS;

                break;
            }

            *ReturnLength = sizeof(TOKEN_DEFAULT_DACL) + tok->default_dacl->AclSize;

            if (TokenInformationLength < *ReturnLength) {
                Status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            tdd->DefaultDacl = (PACL)&tdd[1];

            memcpy(tdd->DefaultDacl, tok->default_dacl, tok->default_dacl->AclSize);

            Status = STATUS_SUCCESS;

            break;
        }

        case TokenElevationType: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenElevationType\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenElevation: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenElevation\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenSessionId: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenSessionId\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenVirtualizationEnabled: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenVirtualizationEnabled\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenIntegrityLevel: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenIntegrityLevel\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenAppContainerSid: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenAppContainerSid\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenIsAppContainer: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenIsAppContainer\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        case TokenLogonSid: // FIXME
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class TokenLogonSid\n");
            Status = STATUS_INVALID_INFO_CLASS;
            break;

        default:
            printk(KERN_INFO "NtQueryInformationToken: unhandled info class %u\n",
                   TokenInformationClass);

            Status = STATUS_INVALID_INFO_CLASS;
            break;
    }

    up_read(&tok->sem);

end:
    dec_obj_refcount(&tok->header);

    return Status;
}

NTSTATUS user_NtQueryInformationToken(HANDLE TokenHandle,
                                      TOKEN_INFORMATION_CLASS TokenInformationClass,
                                      PVOID TokenInformation, ULONG TokenInformationLength,
                                      PULONG ReturnLength) {
    NTSTATUS Status;
    ULONG retlen;
    uint8_t* buf;

    if (!ReturnLength)
        return STATUS_INVALID_PARAMETER;

    if ((uintptr_t)TokenHandle & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (TokenInformationLength > 0) {
        buf = kmalloc(TokenInformationLength, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtQueryInformationToken(TokenHandle, TokenInformationClass,
                                     buf, TokenInformationLength,
                                     &retlen);

    if (buf) {
        ULONG size = retlen;

        if (size > TokenInformationLength)
            size = TokenInformationLength;

        if (NT_SUCCESS(Status)) { // fix pointers
            switch (TokenInformationClass) {
                case TokenUser: {
                    TOKEN_USER* tu = (TOKEN_USER*)buf;

                    tu->User.Sid = (PSID)((uint8_t*)TokenInformation + ((uint8_t*)tu->User.Sid - buf));

                    break;
                }

                case TokenGroups: {
                    TOKEN_GROUPS* tg = (TOKEN_GROUPS*)buf;
                    unsigned int i;

                    for (i = 0; i < tg->GroupCount; i++) {
                        tg->Groups[i].Sid = (PSID)((uint8_t*)TokenInformation +
                                                ((uint8_t*)tg->Groups[i].Sid - buf));
                    }

                    break;
                }

                case TokenPrimaryGroup: {
                    TOKEN_PRIMARY_GROUP* tpg = (TOKEN_PRIMARY_GROUP*)buf;

                    tpg->PrimaryGroup = (PSID)((uint8_t*)TokenInformation + ((uint8_t*)tpg->PrimaryGroup - buf));

                    break;
                }

                case TokenOwner: {
                    TOKEN_OWNER* to = (TOKEN_OWNER*)buf;

                    to->Owner = (PSID)((uint8_t*)TokenInformation + ((uint8_t*)to->Owner - buf));

                    break;
                }

                case TokenDefaultDacl: {
                    TOKEN_DEFAULT_DACL* tdd = (TOKEN_DEFAULT_DACL*)buf;

                    if (!tdd->DefaultDacl)
                        break;

                    tdd->DefaultDacl = (PACL)((uint8_t*)TokenInformation + ((uint8_t*)tdd->DefaultDacl - buf));

                    break;
                }

                default:
                    break;
            }
        }

        if (copy_to_user(TokenInformation, buf, size) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    if (put_user(retlen, ReturnLength) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

static __inline SID* sd_get_owner(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    return (SID*)((uint8_t*)sd + sd->Owner);
}

static __inline SID* sd_get_group(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    return (SID*)((uint8_t*)sd + sd->Group);
}

static __inline ACL* sd_get_dacl(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    return (ACL*)((uint8_t*)sd + sd->Dacl);
}

static __inline ACL* sd_get_sacl(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    return (ACL*)((uint8_t*)sd + sd->Sacl);
}

static NTSTATUS NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                      PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                      PULONG LengthNeeded) {
    NTSTATUS Status;
    ACCESS_MASK access;
    object_header* obj;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    DWORD off;

    obj = get_object_from_handle(Handle, &access);
    if (!obj)
        return STATUS_INVALID_HANDLE;

    // FIXME - ATTRIBUTE_SECURITY_INFORMATION (8+)
    // FIXME - BACKUP_SECURITY_INFORMATION (8+)
    // FIXME - LABEL_SECURITY_INFORMATION (Vista+)
    // FIXME - SCOPE_SECURITY_INFORMATION (8+)

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION) &&
        !(access & READ_CONTROL)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION && !(access & ACCESS_SYSTEM_SECURITY)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    *LengthNeeded = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    spin_lock(&obj->header_lock);

    if (SecurityInformation & OWNER_SECURITY_INFORMATION && obj->sd && obj->sd->Owner != 0)
        *LengthNeeded += sid_length(sd_get_owner(obj->sd));

    if (SecurityInformation & GROUP_SECURITY_INFORMATION && obj->sd && obj->sd->Group != 0)
        *LengthNeeded += sid_length(sd_get_group(obj->sd));

    if (SecurityInformation & DACL_SECURITY_INFORMATION && obj->sd && obj->sd->Dacl != 0)
        *LengthNeeded += sd_get_dacl(obj->sd)->AclSize;

    if (SecurityInformation & SACL_SECURITY_INFORMATION && obj->sd && obj->sd->Sacl != 0)
        *LengthNeeded += sd_get_sacl(obj->sd)->AclSize;

    if (*LengthNeeded > Length) {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto end2;
    }

    sd = (SECURITY_DESCRIPTOR_RELATIVE*)SecurityDescriptor;
    memset(sd, 0, *LengthNeeded);

    sd->Revision = 1;

    if (obj->sd)
        sd->Control = obj->sd->Control;
    else
        sd->Control = SE_SELF_RELATIVE;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (SecurityInformation & OWNER_SECURITY_INFORMATION && obj->sd && obj->sd->Owner != 0) {
        SID* owner = sd_get_owner(obj->sd);
        size_t length = sid_length(owner);

        sd->Owner = off;
        memcpy(sd_get_owner(sd), owner, length);
        off += length;
    }

    if (SecurityInformation & GROUP_SECURITY_INFORMATION && obj->sd && obj->sd->Group != 0) {
        SID* group = sd_get_group(obj->sd);
        size_t length = sid_length(group);

        sd->Group = off;
        memcpy(sd_get_group(sd), group, length);
        off += length;
    }

    if (SecurityInformation & DACL_SECURITY_INFORMATION && obj->sd && obj->sd->Dacl != 0) {
        ACL* dacl = sd_get_dacl(obj->sd);

        sd->Dacl = off;
        memcpy(sd_get_dacl(sd), dacl, dacl->AclSize);
        off += dacl->AclSize;
    }

    if (SecurityInformation & SACL_SECURITY_INFORMATION && obj->sd && obj->sd->Sacl != 0) {
        ACL* sacl = sd_get_sacl(obj->sd);

        sd->Sacl = off;
        memcpy(sd_get_sacl(sd), sacl, sacl->AclSize);
        off += sacl->AclSize;
    }

    Status = STATUS_SUCCESS;

end2:
    spin_unlock(&obj->header_lock);

end:
    dec_obj_refcount(obj);

    return Status;
}

NTSTATUS user_NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                                    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length,
                                    PULONG LengthNeeded) {
    NTSTATUS Status;
    void* buf;
    ULONG needed;

    if (!SecurityDescriptor || !LengthNeeded)
        return STATUS_INVALID_PARAMETER;

    if (Handle != NtCurrentProcess() && Handle != NtCurrentThread() &&
        (uintptr_t)Handle & KERNEL_HANDLE_MASK) {
        return STATUS_INVALID_HANDLE;
    }

    if (Length > 0) {
        buf = kmalloc(Length, GFP_KERNEL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
    } else
        buf = NULL;

    Status = NtQuerySecurityObject(Handle, SecurityInformation, buf, Length, &needed);

    if (buf) {
        size_t size = needed;

        if (needed > Length)
            size = Length;

        if (copy_to_user(SecurityDescriptor, buf, size) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(buf);
    }

    if (put_user(needed, LengthNeeded) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS muwine_init_tokens(void) {
    UNICODE_STRING us;

    static const WCHAR token_name[] = L"Token";

    us.Length = us.MaximumLength = sizeof(token_name) - sizeof(WCHAR);
    us.Buffer = (WCHAR*)token_name;

    token_type = muwine_add_object_type(&us, token_object_close, NULL,
                                        TOKEN_GENERIC_READ, TOKEN_GENERIC_WRITE,
                                        TOKEN_GENERIC_EXECUTE, TOKEN_ALL_ACCESS,
                                        TOKEN_ALL_ACCESS);
    if (IS_ERR(token_type)) {
        printk(KERN_ALERT "muwine_add_object_type returned %d\n", (int)(uintptr_t)token_type);
        return muwine_error_to_ntstatus((int)(uintptr_t)token_type);
    }

    return STATUS_SUCCESS;
}
