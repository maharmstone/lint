#include "muwine.h"
#include "sec.h"
#include "proc.h"
#include "obj.h"
#include "reg.h"

static const uint8_t sid_users[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x21, 0x2, 0, 0 }; // S-1-5-32-545
static const uint8_t sid_administrators[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x2, 0, 0 }; // S-1-5-32-544
static const uint8_t sid_local_system[] = { 1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0 }; // S-1-5-18
static const uint8_t sid_creator_owner[] = { 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0 }; // S-1-3-0
static const uint8_t sid_creator_group[] = { 1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0 }; // S-1-3-1
static const uint8_t sid_everyone[] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }; // S-1-1-0
static const uint8_t sid_restricted[] = { 1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0 }; // S-1-5-12

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
}

static unsigned int __inline sid_length(SID* sid) {
    return offsetof(SID, SubAuthority[0]) + (sid->SubAuthorityCount * sizeof(uint32_t));
}

static void uid_to_sid(SID** sid, kuid_t uid) {
    SID* s;

    // FIXME - allow overrides in Registry

    if (uid.val == 0) { // map root to Local System
        s = kmalloc(sizeof(sid_local_system), GFP_KERNEL);
        // FIXME - handle malloc failure

        memcpy(s, sid_local_system, sizeof(sid_local_system));

        *sid = s;

        return;
    }

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

static NTSTATUS gid_to_sid(SID** sid, kgid_t gid) {
    SID* s;

    // FIXME - allow overrides in Registry

    // use Samba's S-1-22-2 mappings

    s = kmalloc(offsetof(SID, SubAuthority) + (2 * sizeof(uint32_t)), GFP_KERNEL);
    if (!s)
        return STATUS_INSUFFICIENT_RESOURCES;

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

    return STATUS_SUCCESS;
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
    SID_AND_ATTRIBUTES* g;

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

    num_groups++; // for Everyone SID

    tok->groups = kmalloc(offsetof(TOKEN_GROUPS, Groups) + (num_groups * sizeof(SID_AND_ATTRIBUTES)),
                          GFP_KERNEL);
    if (!tok->groups) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    tok->groups->GroupCount = 0;
    g = tok->groups->Groups;

    for (i = 0; i < groups->ngroups; i++) {
        Status = gid_to_sid(&g->Sid, groups->gid[i]);

        if (!NT_SUCCESS(Status)) {
            unsigned int j;

            for (j = 0; j < tok->groups->GroupCount; j++) {
                kfree(tok->groups->Groups[j].Sid);
            }

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        g->Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

        if (groups->gid[i].val == primary_group.val)
            tok->primary_group = g->Sid;

        g++;
        tok->groups->GroupCount++;
    }

    if (!primary_group_in_list) {
        Status = gid_to_sid(&g->Sid, primary_group);

        if (!NT_SUCCESS(Status)) {
            unsigned int j;

            for (j = 0; j < tok->groups->GroupCount; j++) {
                kfree(tok->groups->Groups[j].Sid);
            }

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        g->Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

        tok->primary_group = g->Sid;

        g++;
        tok->groups->GroupCount++;
    }

    g->Sid = kmalloc(sizeof(sid_everyone), GFP_KERNEL);
    if (!g->Sid) {
        unsigned int j;

        for (j = 0; j < tok->groups->GroupCount; j++) {
            kfree(tok->groups->Groups[j].Sid);
        }

        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    memcpy(g->Sid, sid_everyone, sizeof(sid_everyone));
    g->Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

    tok->groups->GroupCount++;

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

NTSTATUS muwine_make_process_token(token_object** t) {
    NTSTATUS Status;
    token_object* tok;
    unsigned int priv_count, i;
    const default_privilege* def_privs;
    size_t dacl_size, sd_size;
    ACCESS_ALLOWED_ACE* aaa;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    DWORD off;

    tok = (token_object*)muwine_alloc_object(sizeof(token_object), token_type, NULL);
    if (!tok)
        return STATUS_INSUFFICIENT_RESOURCES;

    spin_lock_init(&tok->lock);

    uid_to_sid(&tok->user, current_euid());

    Status = get_current_process_groups(tok);
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&tok->header);
        return Status;
    }

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
    if (!tok->privs) {
        dec_obj_refcount(&tok->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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

    if (memcmp(tok->owner, sid_local_system, sizeof(sid_local_system)))
        dacl_size += sizeof(sid_local_system);

    tok->default_dacl = kmalloc(dacl_size, GFP_KERNEL);
    if (!tok->default_dacl) {
        dec_obj_refcount(&tok->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // FIXME - should also have ACE for logon SID and GENERIC_READ | GENERIC_EXECUTE

    tok->default_dacl->AclRevision = 2;
    tok->default_dacl->Sbz1 = 0;
    tok->default_dacl->AclSize = dacl_size;
    tok->default_dacl->AceCount = 0;
    tok->default_dacl->Sbz2 = 0;

    aaa = (ACCESS_ALLOWED_ACE*)&tok->default_dacl[1];
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = 0;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sid_length(tok->owner);
    aaa->Mask = GENERIC_ALL;
    memcpy(&aaa->SidStart, tok->owner, sid_length(tok->owner));
    tok->default_dacl->AceCount++;

    if (memcmp(tok->owner, sid_local_system, sizeof(sid_local_system))) {
        aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)aaa + aaa->Header.AceSize);
        aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        aaa->Header.AceFlags = 0;
        aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_local_system);
        aaa->Mask = GENERIC_ALL;
        memcpy(&aaa->SidStart, sid_local_system, sizeof(sid_local_system));
        tok->default_dacl->AceCount++;
    }

    alloc_luid(&tok->token_id);
    alloc_luid(&tok->modified_id);

    tok->expiry = 0x7fffffffffffffff;

    // create SD for token

    sd_size = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    sd_size += tok->owner ? sid_length(tok->owner) : 0;
    sd_size += tok->primary_group ? sid_length(tok->primary_group) : 0;
    sd_size += tok->default_dacl ? tok->default_dacl->AclSize : 0;

    sd = kzalloc(sd_size, GFP_KERNEL);
    if (!sd) {
        dec_obj_refcount(&tok->header);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // FIXME - create token SD

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (tok->owner) {
        sd->Owner = off;
        memcpy(sd_get_owner(sd), tok->owner, sid_length(tok->owner));
        off += sid_length(tok->owner);
    }

    if (tok->primary_group) {
        sd->Group = off;
        memcpy(sd_get_group(sd), tok->primary_group, sid_length(tok->primary_group));
        off += sid_length(tok->primary_group);
    }

    if (tok->default_dacl) {
        ACL* dacl;
        ACE_HEADER* ace;
        unsigned int i;

        sd->Dacl = off;
        dacl = sd_get_dacl(sd);

        memcpy(dacl, tok->default_dacl, tok->default_dacl->AclSize);
        sd->Control |= SE_DACL_PRESENT;

        // fix generics
        ace = (ACE_HEADER*)&dacl[1];
        for (i = 0; i < dacl->AceCount; i++) {
            if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE || ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)ace;

                if (aaa->Mask & GENERIC_READ) {
                    aaa->Mask &= ~GENERIC_READ;
                    aaa->Mask |= token_type->generic_mapping.GenericRead;
                }

                if (aaa->Mask & GENERIC_WRITE) {
                    aaa->Mask &= ~GENERIC_WRITE;
                    aaa->Mask |= token_type->generic_mapping.GenericWrite;
                }

                if (aaa->Mask & GENERIC_EXECUTE) {
                    aaa->Mask &= ~GENERIC_EXECUTE;
                    aaa->Mask |= token_type->generic_mapping.GenericExecute;
                }

                if (aaa->Mask & GENERIC_ALL) {
                    aaa->Mask &= ~GENERIC_ALL;
                    aaa->Mask |= token_type->generic_mapping.GenericAll;
                }
            }

            ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
        }

        // FIXME - Windows 10 gives Administrators TOKEN_QUERY access if not already set(?)
    }

    tok->header.sd = sd;

    *t = tok;

    return STATUS_SUCCESS;
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

static bool __inline sid_equal(PSID sid1, PSID sid2) {
    size_t size1 = sid_length(sid1);
    size_t size2 = sid_length(sid2);

    if (size1 != size2)
        return false;

    return !memcmp(sid1, sid2, size1);
}

static bool check_privilege_token(token_object* tok, DWORD priv) {
    unsigned int i;

    if (!tok->privs)
        return false;

    for (i = 0; i < tok->privs->PrivilegeCount; i++) {
        if (tok->privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED &&
            tok->privs->Privileges[i].Luid.HighPart == 0 &&
            tok->privs->Privileges[i].Luid.LowPart == priv) {
            return true;
        }
    }

    return false;
}

static bool check_privilege(DWORD priv) {
    process_object* proc;
    token_object* tok;
    bool found = false;

    proc = muwine_current_process_object();

    if (!proc)
        return false;

    // FIXME - should be thread token if impersonating

    tok = proc->token;
    inc_obj_refcount(&tok->header);

    dec_obj_refcount(&proc->header.h);

    spin_lock(&tok->lock);

    found = check_privilege_token(tok, priv);

    spin_unlock(&tok->lock);

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
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    token_object* cur_token;

    if (!check_privilege(SE_CREATE_TOKEN_PRIVILEGE))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (TokenType != TokenPrimary && TokenType != TokenImpersonation)
        return STATUS_INVALID_PARAMETER;

    Status = access_check_type(token_type, DesiredAccess, &access);
    if (!NT_SUCCESS(Status))
        return Status;

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

    // create object

    cur_token = muwine_get_current_token();

    Status = muwine_create_sd(NULL,
                              ObjectAttributes ? ObjectAttributes->SecurityDescriptor : NULL,
                              cur_token, &token_type->generic_mapping, 0, false, &sd, NULL);

    dec_obj_refcount(&cur_token->header);

    if (!NT_SUCCESS(Status))
        return Status;

    tok = (token_object*)muwine_alloc_object(sizeof(token_object), token_type, sd);
    if (!tok) {
        kfree(sd);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    spin_lock_init(&tok->lock);

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

NTSTATUS NtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                              ULONG HandleAttributes, PHANDLE TokenHandle) {
    printk(KERN_INFO "NtOpenProcessTokenEx(%lx, %x, %x, %px): stub\n", (uintptr_t)ProcessHandle,
           DesiredAccess, HandleAttributes, TokenHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

    Status = access_check_object(&tok->header, DesiredAccess, &access);
    if (!NT_SUCCESS(Status)) {
        dec_obj_refcount(&tok->header);
        return Status;
    }

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

NTSTATUS NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
                             ULONG HandleAttributes, PHANDLE TokenHandle) {
    printk(KERN_INFO "NtOpenThreadTokenEx(%lx, %x, %x, %x, %px): stub\n", (uintptr_t)ThreadHandle,
           DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

    spin_lock(&tok->lock);

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
    spin_unlock(&tok->lock);

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

    spin_lock(&tok->lock);

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

    spin_unlock(&tok->lock);

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

NTSTATUS NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                               PVOID TokenInformation, ULONG TokenInformationLength) {
    printk(KERN_INFO "NtSetInformationToken(%lx, %x, %px, %x): stub\n",
           (uintptr_t)TokenHandle, TokenInformationClass, TokenInformation,
           TokenInformationLength);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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

NTSTATUS NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
                             PSECURITY_DESCRIPTOR SecurityDescriptor) {
    printk(KERN_INFO "NtSetSecurityObject(%lx, %x, %px): stub\n", (uintptr_t)Handle,
           SecurityInformation, SecurityDescriptor);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

token_object* muwine_get_current_token(void) {
    process_object* proc;
    token_object* tok;

    // FIXME - get thread impersonation token if available

    proc = muwine_current_process_object();
    if (!proc)
        return NULL;

    if (!proc->token) {
        dec_obj_refcount(&proc->header.h);
        return NULL;
    }

    tok = proc->token;
    inc_obj_refcount(&tok->header);

    dec_obj_refcount(&proc->header.h);

    return tok;
}

size_t sd_length(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    size_t len;

    len = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (sd->Owner != 0)
        len += sid_length(sd_get_owner(sd));

    if (sd->Group != 0)
        len += sid_length(sd_get_group(sd));

    if (sd->Dacl != 0)
        len += sd_get_dacl(sd)->AclSize;

    if (sd->Sacl != 0)
        len += sd_get_sacl(sd)->AclSize;

    return len;
}

static void add_access_allowed_ace(ACE_HEADER** ace, PSID sid, ACCESS_MASK access) {
    ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)*ace;
    size_t sidlen = sid_length(sid);

    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = 0;
    aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sidlen;
    aaa->Mask = access;
    memcpy(&aaa->SidStart, sid, sidlen);

    *ace = (ACE_HEADER*)((uint8_t*)*ace + aaa->Header.AceSize);
}

SECURITY_DESCRIPTOR_RELATIVE* create_dir_root_sd(void) {
    size_t len, dacl_size;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    DWORD off;
    ACL* dacl;
    ACE_HEADER* ace;

    len = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    len += sizeof(sid_administrators);
    len += sizeof(sid_local_system);

    dacl_size = sizeof(ACL);
    dacl_size += 4 * offsetof(ACCESS_ALLOWED_ACE, SidStart);
    dacl_size += sizeof(sid_everyone);
    dacl_size += sizeof(sid_local_system);
    dacl_size += sizeof(sid_administrators);
    dacl_size += sizeof(sid_restricted);

    len += dacl_size;

    sd = kzalloc(len, GFP_KERNEL);
    if (!sd)
        return NULL;

    sd->Revision = 1;
    sd->Control = SE_SELF_RELATIVE;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    sd->Owner = off;
    memcpy(sd_get_owner(sd), sid_administrators, sizeof(sid_administrators));
    off += sizeof(sid_administrators);

    sd->Group = off;
    memcpy(sd_get_group(sd), sid_local_system, sizeof(sid_local_system));
    off += sizeof(sid_local_system);

    sd->Dacl = off;
    dacl = sd_get_dacl(sd);

    dacl->AclRevision = ACL_REVISION;
    dacl->Sbz1 = 0;
    dacl->AclSize = dacl_size;
    dacl->AceCount = 4;
    dacl->Sbz2 = 0;

    ace = (ACE_HEADER*)&dacl[1];
    add_access_allowed_ace(&ace, (PSID)sid_everyone, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL);
    add_access_allowed_ace(&ace, (PSID)sid_local_system, DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
                                                         DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY |
                                                         STANDARD_RIGHTS_REQUIRED);
    add_access_allowed_ace(&ace, (PSID)sid_administrators, DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
                                                           DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY |
                                                           STANDARD_RIGHTS_REQUIRED);
    add_access_allowed_ace(&ace, (PSID)sid_restricted, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL);

    return sd;
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

static bool acl_contains_inheritable_ace(ACL* acl) {
    unsigned int i;
    ACE_HEADER* ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < acl->AceCount; i++) {
        if (ace->AceFlags & CONTAINER_INHERIT_ACE || ace->AceFlags & OBJECT_INHERIT_ACE)
            return true;

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }

    return false;
}

static NTSTATUS preprocess_acl_from_creator(ACL* creator, ACL** ret) {
    unsigned int i;
    size_t size;
    ACE_HEADER* src_ace;
    ACE_HEADER* dest_ace;
    ACL* acl;

    size = sizeof(ACL);

    src_ace = (ACE_HEADER*)&creator[1];

    for (i = 0; i < creator->AceCount; i++) {
        if (!(src_ace->AceFlags & INHERITED_ACE))
            size += src_ace->AceSize;

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    acl = kmalloc(size, GFP_KERNEL);
    if (!acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = 0;
    acl->Sbz2 = 0;

    src_ace = (ACE_HEADER*)&creator[1];
    dest_ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < creator->AceCount; i++) {
        if (!(src_ace->AceFlags & INHERITED_ACE)) {
            memcpy(dest_ace, src_ace, src_ace->AceSize);
            acl->AceCount++;

            dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    *ret = acl;

    return STATUS_SUCCESS;
}

static NTSTATUS post_process_acl(ACL* src_acl, bool copy_all, SID* owner, SID* group,
                                 GENERIC_MAPPING* generic_mapping, ACL** ret) {
    unsigned int i;
    size_t size;
    ACL* acl;
    ACE_HEADER* src_ace;
    ACE_HEADER* dest_ace;

    size = sizeof(ACL);

    src_ace = (ACE_HEADER*)&src_acl[1];

    for (i = 0; i < src_acl->AceCount; i++) {
        if (src_ace->AceFlags & INHERITED_ACE || copy_all) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE || src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)src_ace;

                size += offsetof(ACCESS_ALLOWED_ACE, SidStart);

                if (!memcmp(&aaa->SidStart, &sid_creator_owner, sizeof(sid_creator_owner)))
                    size += sid_length(owner);
                else if (!memcmp(&aaa->SidStart, &sid_creator_group, sizeof(sid_creator_group)))
                    size += sid_length(group);
                else
                    size += sid_length((SID*)&aaa->SidStart);
            }
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    acl = kmalloc(size, GFP_KERNEL);
    if (!acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = 0;
    acl->Sbz2 = 0;

    src_ace = (ACE_HEADER*)&src_acl[1];
    dest_ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < src_acl->AceCount; i++) {
        if (src_ace->AceFlags & INHERITED_ACE || copy_all) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE || src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE* src_aaa = (ACCESS_ALLOWED_ACE*)src_ace;
                ACCESS_ALLOWED_ACE* dest_aaa = (ACCESS_ALLOWED_ACE*)dest_ace;

                memcpy(dest_aaa, src_aaa, offsetof(ACCESS_ALLOWED_ACE, SidStart));

                dest_aaa->Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart);

                if (!memcmp(&src_aaa->SidStart, &sid_creator_owner, sizeof(sid_creator_owner))) {
                    dest_aaa->Header.AceSize += sid_length(owner);
                    memcpy(&dest_aaa->SidStart, owner, sid_length(owner));
                } else if (!memcmp(&src_aaa->SidStart, &sid_creator_group, sizeof(sid_creator_group))) {
                    dest_aaa->Header.AceSize += sid_length(group);
                    memcpy(&dest_aaa->SidStart, group, sid_length(group));
                } else {
                    dest_aaa->Header.AceSize += sid_length((SID*)&src_aaa->SidStart);
                    memcpy(&dest_aaa->SidStart, &src_aaa->SidStart, sid_length((SID*)&src_aaa->SidStart));
                }

                if (dest_aaa->Mask & GENERIC_READ) {
                    dest_aaa->Mask &= ~GENERIC_READ;
                    dest_aaa->Mask |= generic_mapping->GenericRead;
                }

                if (dest_aaa->Mask & GENERIC_WRITE) {
                    dest_aaa->Mask &= ~GENERIC_WRITE;
                    dest_aaa->Mask |= generic_mapping->GenericWrite;
                }

                if (dest_aaa->Mask & GENERIC_EXECUTE) {
                    dest_aaa->Mask &= ~GENERIC_EXECUTE;
                    dest_aaa->Mask |= generic_mapping->GenericExecute;
                }

                if (dest_aaa->Mask & GENERIC_ALL) {
                    dest_aaa->Mask &= ~GENERIC_ALL;
                    dest_aaa->Mask |= generic_mapping->GenericAll;
                }

                acl->AceCount++;

                dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
            }
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    *ret = acl;

    return STATUS_SUCCESS;
}

static NTSTATUS compute_inherited_acl_from_parent(ACL* parent, bool is_container,
                                                  ACL** ret) {
    unsigned int i;
    size_t size;
    ACE_HEADER* src_ace;
    ACE_HEADER* dest_ace;
    ACL* acl;

    size = sizeof(ACL);

    src_ace = (ACE_HEADER*)&parent[1];

    for (i = 0; i < parent->AceCount; i++) {
        if (!(src_ace->AceFlags & INHERIT_ONLY_ACE) &&
            ((is_container && src_ace->AceFlags & CONTAINER_INHERIT_ACE) ||
            (!is_container && src_ace->AceFlags & OBJECT_INHERIT_ACE))) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                size += src_ace->AceSize;
            }
        }

        if (is_container && !(src_ace->AceFlags & NO_PROPAGATE_INHERIT_ACE)) {
            if (src_ace->AceFlags & CONTAINER_INHERIT_ACE || src_ace->AceFlags & OBJECT_INHERIT_ACE)
                size += src_ace->AceSize;
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    acl = kmalloc(size, GFP_KERNEL);
    if (!acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = 0;
    acl->Sbz2 = 0;

    src_ace = (ACE_HEADER*)&parent[1];
    dest_ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < parent->AceCount; i++) {
        if (src_ace->AceFlags & INHERIT_ONLY_ACE) {
            src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
            continue;
        }

        if ((is_container && src_ace->AceFlags & CONTAINER_INHERIT_ACE) ||
            (!is_container && src_ace->AceFlags & OBJECT_INHERIT_ACE)) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                memcpy(dest_ace, src_ace, src_ace->AceSize);
                dest_ace->AceFlags = INHERITED_ACE;

                // not in [MS-DTYP] 2.5.3.4.4 - is this correct?
                if (is_container) {
                    dest_ace->AceFlags |= src_ace->AceFlags | CONTAINER_INHERIT_ACE;
                    dest_ace->AceFlags |= src_ace->AceFlags | OBJECT_INHERIT_ACE;
                }

                acl->AceCount++;
                dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
            }
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    if (!is_container) {
        *ret = acl;
        return STATUS_SUCCESS;
    }

    src_ace = (ACE_HEADER*)&parent[1];

    for (i = 0; i < parent->AceCount; i++) {
        if (!(src_ace->AceFlags & NO_PROPAGATE_INHERIT_ACE)) {
            if (src_ace->AceFlags & CONTAINER_INHERIT_ACE || src_ace->AceFlags & OBJECT_INHERIT_ACE) {
                memcpy(dest_ace, src_ace, src_ace->AceSize);
                dest_ace->AceFlags |= INHERITED_ACE | INHERIT_ONLY_ACE;

                acl->AceCount++;
                dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
            }
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    *ret = acl;

    return STATUS_SUCCESS;
}

static NTSTATUS compute_inherited_acl_from_creator(ACL* creator, bool is_container, ACL** ret) {
    unsigned int i;
    ACE_HEADER* src_ace;
    ACE_HEADER* dest_ace;
    size_t size;
    ACL* acl;

    size = sizeof(ACL);
    src_ace = (ACE_HEADER*)&creator[1];

    for (i = 0; i < creator->AceCount; i++) {
        if ((is_container && src_ace->AceFlags & CONTAINER_INHERIT_ACE) ||
            (!is_container && src_ace->AceFlags & OBJECT_INHERIT_ACE)) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                size += src_ace->AceSize;
            }
        }

        if (is_container && (src_ace->AceFlags & CONTAINER_INHERIT_ACE || src_ace->AceFlags & OBJECT_INHERIT_ACE))
            size += src_ace->AceSize;

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    acl = kmalloc(size, GFP_KERNEL);
    if (!acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = 0;
    acl->Sbz2 = 0;

    src_ace = (ACE_HEADER*)&creator[1];
    dest_ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < creator->AceCount; i++) {
        if ((is_container && src_ace->AceFlags & CONTAINER_INHERIT_ACE) ||
            (!is_container && src_ace->AceFlags & OBJECT_INHERIT_ACE)) {
            if (src_ace->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                src_ace->AceType == ACCESS_DENIED_ACE_TYPE) {
                memcpy(dest_ace, src_ace, src_ace->AceSize);
                dest_ace->AceFlags = 0;

                acl->AceCount++;
                dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
            }
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    if (!is_container) {
        *ret = acl;
        return STATUS_SUCCESS;
    }

    src_ace = (ACE_HEADER*)&creator[1];

    for (i = 0; i < creator->AceCount; i++) {
        if (src_ace->AceFlags & CONTAINER_INHERIT_ACE || src_ace->AceFlags & OBJECT_INHERIT_ACE) {
            memcpy(dest_ace, src_ace, src_ace->AceSize);
            dest_ace->AceFlags |= INHERIT_ONLY_ACE;

            acl->AceCount++;
            dest_ace = (ACE_HEADER*)((uint8_t*)dest_ace + dest_ace->AceSize);
        }

        src_ace = (ACE_HEADER*)((uint8_t*)src_ace + src_ace->AceSize);
    }

    *ret = acl;

    return STATUS_SUCCESS;
}

static NTSTATUS compute_acl(ACL* parent, SECURITY_DESCRIPTOR_RELATIVE* creator_sd,
                            ACL* default_acl, bool dacl, SID* owner, SID* group,
                            GENERIC_MAPPING* generic_mapping, unsigned int flags,
                            bool is_container, SECURITY_DESCRIPTOR_CONTROL* control,
                            ACL** ret) {
    NTSTATUS Status;
    ACL* creator;

    // See 2.5.3.4.2 of [MS-DTYP]

    // FIXME - handle object ACEs?

    if (creator_sd) {
        if (dacl)
            creator = creator_sd->Dacl != 0 ? sd_get_dacl(creator_sd) : NULL;
        else
            creator = creator_sd->Sacl != 0 ? sd_get_sacl(creator_sd) : NULL;
    } else
        creator = NULL;

    *control = 0;

    if (parent && acl_contains_inheritable_ace(parent)) {
        if (!creator || (creator && flags & SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT)) {
            ACL* next_acl;

            Status = compute_inherited_acl_from_parent(parent, is_container, &next_acl);
            if (!NT_SUCCESS(Status))
                return Status;

            Status = post_process_acl(next_acl, false, owner, group, generic_mapping, ret);

            kfree(next_acl);

            return Status;
        } else {
            ACL* pre_acl;
            ACL* tmp_acl;
            ACL* inherited = NULL;

            Status = preprocess_acl_from_creator(creator, &pre_acl);
            if (!NT_SUCCESS(Status))
                return Status;

            Status = compute_inherited_acl_from_creator(pre_acl, is_container, &tmp_acl);

            kfree(pre_acl);

            if (!NT_SUCCESS(Status))
                return Status;

            if (dacl) {
                if (!(creator_sd->Control & SE_DACL_PROTECTED) && flags & SEF_DACL_AUTO_INHERIT) {
                    ACL* inherited;

                    Status = compute_inherited_acl_from_parent(parent, is_container, &inherited);
                    if (!NT_SUCCESS(Status)) {
                        kfree(tmp_acl);
                        return Status;
                    }

                    *control |= SE_DACL_AUTO_INHERITED;
                }
            } else { // sacl
                if (!(creator_sd->Control & SE_SACL_PROTECTED) && flags & SEF_SACL_AUTO_INHERIT) {
                    Status = compute_inherited_acl_from_parent(parent, is_container, &inherited);
                    if (!NT_SUCCESS(Status)) {
                        kfree(tmp_acl);
                        return Status;
                    }

                    *control |= SE_SACL_AUTO_INHERITED;
                }
            }

            if (inherited) { // append inherited ACEs to tmp_acl
                ACL* new_acl;
                size_t size = tmp_acl->AclSize + inherited->AclSize - sizeof(ACL);

                new_acl = kmalloc(size, GFP_KERNEL);
                if (!new_acl) {
                    kfree(inherited);
                    kfree(tmp_acl);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                new_acl->AclRevision = ACL_REVISION;
                new_acl->Sbz1 = 0;
                new_acl->AclSize = size;
                new_acl->AceCount = tmp_acl->AceCount + inherited->AceCount;
                new_acl->Sbz2 = 0;

                memcpy(&new_acl[1], tmp_acl, tmp_acl->AclSize - sizeof(ACL));
                memcpy((uint8_t*)new_acl + tmp_acl->AclSize, &inherited[1],
                       inherited->AclSize - sizeof(ACL));

                kfree(inherited);
                kfree(tmp_acl);

                tmp_acl = new_acl;
            }

            Status = post_process_acl(tmp_acl, false, owner, group, generic_mapping, ret);

            kfree(tmp_acl);

            return Status;
        }
    } else {
        ACL* tmp_acl;

        if (!creator)
            tmp_acl = default_acl;
        else
            preprocess_acl_from_creator(creator, &tmp_acl);

        if (!tmp_acl) {
            *ret = NULL;
            return STATUS_SUCCESS;
        }

        Status = post_process_acl(tmp_acl, true, owner, group, generic_mapping, ret);

        if (creator)
            kfree(tmp_acl);

        return Status;
    }
}

NTSTATUS copy_sd(SECURITY_DESCRIPTOR_RELATIVE* in, SECURITY_DESCRIPTOR_RELATIVE** out) {
    size_t size;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    DWORD off;

    size = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    size += in->Owner != 0 ? sid_length(sd_get_owner(in)) : 0;
    size += in->Group != 0 ? sid_length(sd_get_group(in)) : 0;
    size += in->Dacl != 0 ? sd_get_dacl(in)->AclSize : 0;
    size += in->Sacl != 0 ? sd_get_sacl(in)->AclSize : 0;

    sd = kmalloc(size, GFP_KERNEL);
    if (!sd)
        return STATUS_INSUFFICIENT_RESOURCES;

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = in->Control;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (in->Owner != 0) {
        sd->Owner = off;
        memcpy(sd_get_owner(sd), sd_get_owner(in), sid_length(sd_get_owner(in)));
        off += sid_length(sd_get_owner(in));
    } else
        sd->Owner = 0;

    if (in->Group != 0) {
        sd->Group = off;
        memcpy(sd_get_group(sd), sd_get_group(in), sid_length(sd_get_group(in)));
        off += sid_length(sd_get_group(in));
    } else
        sd->Group = 0;

    if (in->Dacl != 0) {
        sd->Dacl = off;
        memcpy(sd_get_dacl(sd), sd_get_dacl(in), sd_get_dacl(in)->AclSize);
        off += sd_get_dacl(in)->AclSize;
    } else
        sd->Dacl = 0;

    if (in->Sacl != 0) {
        sd->Sacl = off;
        memcpy(sd_get_sacl(sd), sd_get_sacl(in), sd_get_sacl(in)->AclSize);
        off += sd_get_sacl(in)->AclSize;
    } else
        sd->Sacl = 0;

    *out = sd;

    return STATUS_SUCCESS;
}

NTSTATUS muwine_create_sd2(SECURITY_DESCRIPTOR_RELATIVE* parent_sd,
                           SECURITY_DESCRIPTOR_RELATIVE* creator,
                           token_object* token, GENERIC_MAPPING* generic_mapping,
                           unsigned int flags, bool is_container,
                           SECURITY_DESCRIPTOR_RELATIVE** ret, size_t* retlen) {
    NTSTATUS Status;
    SID* owner;
    SID* group;
    ACL* dacl;
    ACL* sacl;
    SECURITY_DESCRIPTOR_CONTROL ctrl1 = 0, ctrl2 = 0;
    size_t size;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    DWORD off;

    if (token)
        spin_lock(&token->lock);

    // owner

    if (!creator || creator->Owner == 0) {
        if (parent_sd && parent_sd->Owner != 0 && flags & SEF_DEFAULT_OWNER_FROM_PARENT)
            owner = sd_get_owner(parent_sd);
        else if (!token)
            owner = NULL;
        else
            owner = token->owner;
    } else
        owner = sd_get_owner(creator);

    // group

    if (!creator || creator->Group == 0) {
        if (parent_sd && parent_sd->Group != 0 && flags & SEF_DEFAULT_GROUP_FROM_PARENT)
            group = sd_get_group(parent_sd);
        else if (!token)
            group = NULL;
        else
            group = token->primary_group;
    } else
        group = sd_get_group(creator);

    // DACL

    Status = compute_acl(parent_sd && parent_sd->Dacl != 0 ? sd_get_dacl(parent_sd) : NULL, creator,
                         token ? token->default_dacl : NULL, true, owner, group,
                         generic_mapping, flags, is_container, &ctrl1, &dacl);

    if (token)
        spin_unlock(&token->lock);

    if (!NT_SUCCESS(Status))
        return Status;

    // SACL

    Status = compute_acl(parent_sd && parent_sd->Sacl != 0 ? sd_get_sacl(parent_sd) : NULL, creator,
                         NULL, false, owner, group, generic_mapping,
                         flags, is_container, &ctrl2, &sacl);
    if (!NT_SUCCESS(Status)) {
        if (dacl)
            kfree(dacl);

        return Status;
    }

    // assemble SD

    size = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    size += owner ? sid_length(owner) : 0;
    size += group ? sid_length(group) : 0;
    size += dacl ? dacl->AclSize : 0;
    size += sacl ? sacl->AclSize : 0;

    sd = kmalloc(size, GFP_KERNEL);
    if (!sd) {
        if (sacl)
            kfree(sacl);

        if (dacl)
            kfree(dacl);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE | ctrl1 | ctrl2;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (owner) {
        sd->Owner = off;
        memcpy(sd_get_owner(sd), owner, sid_length(owner));
        off += sid_length(owner);
    } else
        sd->Owner = 0;

    if (group) {
        sd->Group = off;
        memcpy(sd_get_group(sd), group, sid_length(group));
        off += sid_length(group);
    } else
        sd->Group = 0;

    if (dacl) {
        sd->Dacl = off;
        memcpy(sd_get_dacl(sd), dacl, dacl->AclSize);
        off += dacl->AclSize;

        kfree(dacl);
    } else
        sd->Dacl = 0;

    if (sacl) {
        sd->Sacl = off;
        memcpy(sd_get_sacl(sd), sacl, sacl->AclSize);
        off += sacl->AclSize;

        kfree(sacl);
    } else
        sd->Sacl = 0;

    *ret = sd;

    if (retlen)
        *retlen = size;

    return STATUS_SUCCESS;
}

NTSTATUS muwine_create_sd(object_header* parent, SECURITY_DESCRIPTOR_RELATIVE* creator,
                          token_object* token, GENERIC_MAPPING* generic_mapping,
                          unsigned int flags, bool is_container,
                          SECURITY_DESCRIPTOR_RELATIVE** ret, size_t* retlen) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR_RELATIVE* parent_sd;

    if (parent) {
        // take a copy of the parent SD to avoid locking issues later
        spin_lock(&parent->header_lock);

        if (parent->sd)
            Status = copy_sd(parent->sd, &parent_sd);
        else {
            parent_sd = NULL;
            Status = STATUS_SUCCESS;
        }

        spin_unlock(&parent->header_lock);

        if (!NT_SUCCESS(Status))
            return Status;
    } else
        parent_sd = NULL;

    Status = muwine_create_sd2(parent_sd, creator, token, generic_mapping, flags, is_container,
                               ret, retlen);

    if (parent_sd)
        kfree(parent_sd);

    return Status;
}

token_object* duplicate_token(token_object* tok) {
    NTSTATUS Status;
    token_object* obj;
    SECURITY_DESCRIPTOR_RELATIVE* sd;

    spin_lock(&tok->header.header_lock);
    Status = copy_sd(tok->header.sd, &sd);
    spin_unlock(&tok->header.header_lock);

    if (!NT_SUCCESS(Status))
        return NULL;

    obj = (token_object*)muwine_alloc_object(sizeof(token_object), token_type, sd);

    if (!obj) {
        kfree(sd);
        return NULL;
    }

    spin_lock_init(&obj->lock);

    spin_lock(&tok->lock);

    if (tok->user) {
        obj->user = kmalloc(sid_length(tok->user), GFP_KERNEL);
        if (!obj->user) {
            spin_unlock(&tok->lock);
            dec_obj_refcount(&obj->header);
            return NULL;
        }

        memcpy(obj->user, tok->user, sid_length(tok->user));

        if (tok->owner && !memcmp(tok->owner, obj->user, sid_length(obj->user)))
            obj->owner = tok->user;

        if (tok->primary_group && !memcmp(tok->primary_group, obj->user, sid_length(obj->user)))
            obj->primary_group = tok->user;
    }

    if (tok->privs) {
        size_t size;

        size = offsetof(TOKEN_PRIVILEGES, Privileges) + (tok->privs->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES));

        obj->privs = kmalloc(size, GFP_KERNEL);
        if (!obj->privs) {
            spin_unlock(&tok->lock);
            dec_obj_refcount(&obj->header);
            return NULL;
        }

        memcpy(obj->privs, tok->privs, size);
    }

    obj->expiry = tok->expiry;
    obj->auth_id = tok->auth_id;

    if (tok->groups) {
        unsigned int i;
        size_t size;

        size = offsetof(TOKEN_GROUPS, Groups) + (tok->groups->GroupCount * sizeof(SID_AND_ATTRIBUTES));

        obj->groups = kmalloc(size, GFP_KERNEL);
        if (!obj->groups) {
            spin_unlock(&tok->lock);
            dec_obj_refcount(&obj->header);
            return NULL;
        }

        obj->groups->GroupCount = tok->groups->GroupCount;

        for (i = 0; i < obj->groups->GroupCount; i++) {
            obj->groups->Groups[i].Attributes = tok->groups->Groups[i].Attributes;

            obj->groups->Groups[i].Sid = kmalloc(sid_length(tok->groups->Groups[i].Sid), GFP_KERNEL);

            if (!obj->groups->Groups[i].Sid) {
                unsigned int j;

                spin_unlock(&tok->lock);

                for (j = 0; j < i; j++) {
                    kfree(obj->groups->Groups[j].Sid);
                }
                kfree(obj->groups);
                obj->groups = NULL;

                dec_obj_refcount(&obj->header);
                return NULL;
            }

            memcpy(obj->groups->Groups[i].Sid, tok->groups->Groups[i].Sid, sid_length(tok->groups->Groups[i].Sid));

            if (!obj->owner && tok->owner && !memcmp(obj->groups->Groups[i].Sid, tok->owner, sid_length(tok->owner)))
                obj->owner = obj->groups->Groups[i].Sid;

            if (!obj->primary_group && tok->primary_group && !memcmp(obj->groups->Groups[i].Sid, tok->primary_group, sid_length(tok->primary_group)))
                obj->primary_group = obj->groups->Groups[i].Sid;
        }
    }

    obj->source = tok->source;

    if (tok->default_dacl) {
        obj->default_dacl = kmalloc(tok->default_dacl->AclSize, GFP_KERNEL);
        if (!obj->default_dacl) {
            spin_unlock(&tok->lock);
            dec_obj_refcount(&obj->header);
            return NULL;
        }

        memcpy(obj->default_dacl, tok->default_dacl, tok->default_dacl->AclSize);
    }

    obj->type = tok->type;
    obj->impersonation_level = tok->impersonation_level;
    obj->token_id = tok->token_id;
    obj->modified_id = tok->modified_id;

    spin_unlock(&tok->lock);

    return obj;
}

static bool valid_acl(ACL* acl, unsigned int len) {
    ACE_HEADER* ace;
    unsigned int i;

    // FIXME - also a revision 4?
    if (acl->AclRevision != ACL_REVISION)
        return false;

    if (acl->Sbz1 != 0)
        return false;

    if (acl->AclSize > len)
        return false;

    if (acl->Sbz2 != 0)
        return false;

    len -= sizeof(ACL);

    ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < acl->AceCount; i++) {
        if (len < sizeof(ACE_HEADER))
            return false;

        if (len < ace->AceSize)
            return false;

        len -= ace->AceSize;

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }

    return true;
}

NTSTATUS check_sd(SECURITY_DESCRIPTOR_RELATIVE* sd, unsigned int len) {
    if (len < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        return STATUS_INVALID_SECURITY_DESCR;

    if (sd->Revision != 1)
        return STATUS_UNKNOWN_REVISION;

    if (sd->Sbz1 != 0)
        return STATUS_INVALID_SECURITY_DESCR;

    if (!(sd->Control & SE_SELF_RELATIVE))
        return STATUS_INVALID_SECURITY_DESCR;

    if (sd->Owner != 0) {
        SID* owner = sd_get_owner(sd);

        if (sd->Owner + offsetof(SID, SubAuthority) > len)
            return STATUS_INVALID_SID;

        if (owner->Revision != 1)
            return STATUS_INVALID_SID;

        if (sd->Owner + sid_length(owner) > len)
            return STATUS_INVALID_SID;
    }

    if (sd->Group != 0) {
        SID* group = sd_get_group(sd);

        if (sd->Group + offsetof(SID, SubAuthority) > len)
            return STATUS_INVALID_SID;

        if (group->Revision != 1)
            return STATUS_INVALID_SID;

        if (sd->Group + sid_length(group) > len)
            return STATUS_INVALID_SID;
    }

    if (sd->Sacl != 0) {
        ACL* sacl = sd_get_sacl(sd);

        if (sd->Sacl + sizeof(ACL) > len)
            return STATUS_INVALID_ACL;

        if (!valid_acl(sacl, len - sd->Sacl))
            return STATUS_INVALID_ACL;
    }

    if (sd->Dacl != 0) {
        ACL* dacl = sd_get_dacl(sd);

        if (sd->Dacl + sizeof(ACL) > len)
            return STATUS_INVALID_ACL;

        if (!valid_acl(dacl, len - sd->Dacl))
            return STATUS_INVALID_ACL;
    }

    return STATUS_SUCCESS;
}

static bool sid_in_token(token_object* tok, SID* sid, bool denying) {
    unsigned int i;
    size_t sidlen = sid_length(sid);

    if (tok->user && !memcmp(tok->user, sid, sidlen))
        return true;

    if (!tok->groups)
        return false;

    for (i = 0; i < tok->groups->GroupCount; i++) {
        if (denying || !(tok->groups->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY)) {
            if (!memcmp(tok->groups->Groups[i].Sid, sid, sidlen))
                return true;
        }
    }

    return false;
}

static NTSTATUS access_check(token_object* tok, SECURITY_DESCRIPTOR_RELATIVE* sd,
                             ACCESS_MASK desired, PGENERIC_MAPPING mapping,
                             PPRIVILEGE_SET privs_required, PULONG privreqlen,
                             ACCESS_MASK* granted) {
    NTSTATUS Status;
    ACCESS_MASK remaining, denied;
    bool max_allowed;
    ACL* dacl;
    ACE_HEADER* ace;
    unsigned int i;

    // See [MS-DTYP] 2.5.3.2

    if (desired & GENERIC_READ) {
        desired |= mapping->GenericRead;
        desired &= ~GENERIC_READ;
    }

    if (desired & GENERIC_WRITE) {
        desired |= mapping->GenericWrite;
        desired &= ~GENERIC_WRITE;
    }

    if (desired & GENERIC_EXECUTE) {
        desired |= mapping->GenericExecute;
        desired &= ~GENERIC_EXECUTE;
    }

    if (desired & GENERIC_ALL) {
        desired |= mapping->GenericAll;
        desired &= ~GENERIC_ALL;
    }

    remaining = desired;
    denied = 0;
    *granted = 0;

    if (tok)
        spin_lock(&tok->lock);

    if (remaining & ACCESS_SYSTEM_SECURITY) {
        if (!tok || check_privilege_token(tok, SE_SECURITY_PRIVILEGE)) {
            remaining &= ~ACCESS_SYSTEM_SECURITY;
            *granted |= ACCESS_SYSTEM_SECURITY;

            if (remaining == 0) {
                Status = STATUS_SUCCESS;
                goto end;
            }
        } else {
            if (privs_required) {
                // assuming there will only ever be one privilege required

                if (*privreqlen < sizeof(PRIVILEGE_SET)) {
                    *privreqlen = sizeof(PRIVILEGE_SET);
                    Status = STATUS_BUFFER_TOO_SMALL;
                    goto end;
                }

                *privreqlen = sizeof(PRIVILEGE_SET);

                privs_required->PrivilegeCount = 1;
                privs_required->Control = 0;
                privs_required->Privilege[0].Luid.LowPart = SE_SECURITY_PRIVILEGE;
                privs_required->Privilege[0].Luid.HighPart = 0;
                privs_required->Privilege[0].Attributes = 0;
            }

            *granted = 0;
            Status = STATUS_PRIVILEGE_NOT_HELD;
            goto end;
        }
    }

    if (remaining & WRITE_OWNER) {
        if (!tok || check_privilege_token(tok, SE_TAKE_OWNERSHIP_PRIVILEGE)) {
            remaining &= ~WRITE_OWNER;
            *granted |= WRITE_OWNER;
        }
    }

    // owner always granted READ_CONTROL and WRITE_DAC
    if (!sd || !tok || (sd->Owner != 0 && sid_in_token(tok, sd_get_owner(sd), false))) {
        remaining &= ~(READ_CONTROL | WRITE_DAC);
        *granted |= READ_CONTROL | WRITE_DAC;

        if (remaining == 0) {
            Status = STATUS_SUCCESS;
            goto end;
        }
    }

    if (!sd || !tok || sd->Dacl == 0) {
        *granted |= remaining;
        Status = STATUS_SUCCESS;
        goto end;
    }

    max_allowed = remaining & MAXIMUM_ALLOWED;

    dacl = sd_get_dacl(sd);
    ace = (ACE_HEADER*)&dacl[1];

    for (i = 0; i < dacl->AceCount; i++) {
        if (ace->AceFlags & INHERIT_ONLY_ACE) {
            ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
            continue;
        }

        switch (ace->AceType) {
            case ACCESS_ALLOWED_ACE_TYPE: {
                ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)ace;

                if (sid_in_token(tok, (SID*)&aaa->SidStart, false)) {
                    if (max_allowed)
                        *granted |= aaa->Mask;
                    else {
                        *granted |= remaining & aaa->Mask;
                        remaining &= ~aaa->Mask;

                        if (remaining == 0) {
                            Status = STATUS_SUCCESS;
                            goto end;
                        }
                    }
                }

                break;
            }

            case ACCESS_DENIED_ACE_TYPE: {
                ACCESS_DENIED_ACE* ada = (ACCESS_DENIED_ACE*)ace;

                if (sid_in_token(tok, (SID*)&ada->SidStart, true)) {
                    if (max_allowed)
                        denied |= ada->Mask;
                    else {
                        if (remaining & ada->Mask) {
                            *granted = 0;
                            Status = STATUS_ACCESS_DENIED;
                            goto end;
                        }
                    }
                }

                break;
            }
        }

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }

    if (max_allowed) {
        *granted &= ~denied;

        if (granted == 0)
            Status = STATUS_ACCESS_DENIED;
        else
            Status = STATUS_SUCCESS;

        goto end;
    }

    if (remaining == 0)
        Status = STATUS_SUCCESS;
    else
        Status = STATUS_ACCESS_DENIED;

end:
    if (tok)
        spin_unlock(&tok->lock);

    return Status;
}

NTSTATUS access_check_type(type_object* type, ACCESS_MASK desired, ACCESS_MASK* granted) {
    NTSTATUS Status;
    token_object* tok;

    tok = muwine_get_current_token();

    Status = access_check(tok, NULL, desired, &type->generic_mapping, NULL, NULL, granted);

    if (tok)
        dec_obj_refcount(&tok->header);

    return Status;
}

NTSTATUS access_check_object(object_header* obj, ACCESS_MASK desired, ACCESS_MASK* granted) {
    NTSTATUS Status;
    token_object* tok;
    SECURITY_DESCRIPTOR_RELATIVE* sd;

    // take a copy of the parent SD to avoid locking issues
    spin_lock(&obj->header_lock);

    if (obj->sd)
        Status = copy_sd(obj->sd, &sd);
    else {
        sd = NULL;
        Status = STATUS_SUCCESS;
    }

    spin_unlock(&obj->header_lock);

    if (!NT_SUCCESS(Status))
        return Status;

    tok = muwine_get_current_token();
    if (!tok) {
        kfree(sd);
        return STATUS_INTERNAL_ERROR;
    }

    Status = access_check(tok, sd, desired, &obj->type->generic_mapping, NULL, NULL, granted);

    dec_obj_refcount(&tok->header);

    kfree(sd);

    return Status;
}

static NTSTATUS NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken,
                              ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping,
                              PPRIVILEGE_SET RequiredPrivilegesBuffer, PULONG BufferLength,
                              PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {
    NTSTATUS Status;
    token_object* tok;
    ACCESS_MASK access;

    // FIXME - check SD is valid(?)

    tok = (token_object*)get_object_from_handle(ClientToken, &access);
    if (!tok)
        return STATUS_INVALID_HANDLE;

    if (tok->header.type != token_type) {
        dec_obj_refcount(&tok->header);
        return STATUS_INVALID_HANDLE;
    }

    if (!(access & TOKEN_QUERY)) {
        dec_obj_refcount(&tok->header);
        return STATUS_ACCESS_DENIED;
    }

    Status = access_check(tok, SecurityDescriptor, DesiredAccess, GenericMapping,
                          RequiredPrivilegesBuffer, BufferLength, GrantedAccess);

    if (Status != STATUS_INVALID_SECURITY_DESCR && Status != STATUS_BUFFER_TOO_SMALL) {
        *AccessStatus = Status;
        Status = STATUS_SUCCESS;
    } else if (Status == STATUS_PRIVILEGE_NOT_HELD) {
        *AccessStatus = Status;
        Status = STATUS_ACCESS_DENIED;
    }

    dec_obj_refcount(&tok->header);

    return Status;
}

static bool get_user_security_descriptor(SECURITY_DESCRIPTOR_RELATIVE** ks,
                                         const __user PSECURITY_DESCRIPTOR us) {
    SECURITY_DESCRIPTOR_CONTROL control;
    SECURITY_DESCRIPTOR_RELATIVE base;
    SID* owner = NULL;
    SID* group = NULL;
    ACL* sacl = NULL;
    ACL* dacl = NULL;
    SECURITY_DESCRIPTOR_RELATIVE* sd;
    size_t size;
    DWORD off;

    if (get_user(control, &((SECURITY_DESCRIPTOR_RELATIVE*)us)->Control) < 0)
        return false;

    // FIXME - support absolute SDs
    if (!(control & SE_SELF_RELATIVE))
        return false;

    if (copy_from_user(&base, us, sizeof(SECURITY_DESCRIPTOR_RELATIVE)) != 0)
        return false;

    if (base.Owner != 0) {
        SID* us_owner = (SID*)((uint8_t*)us + base.Owner);
        uint8_t subauth_count;
        size_t len;

        if (get_user(subauth_count, &us_owner->SubAuthorityCount) < 0)
            return false;

        len = offsetof(SID, SubAuthority[0]) + (subauth_count * sizeof(uint32_t));

        owner = kmalloc(len, GFP_KERNEL);
        if (!owner)
            return false;

        if (copy_from_user(owner, us_owner, len) != 0) {
            kfree(owner);
            return false;
        }
    }

    if (base.Group != 0) {
        SID* us_group = (SID*)((uint8_t*)us + base.Group);
        uint8_t subauth_count;
        size_t len;

        if (get_user(subauth_count, &us_group->SubAuthorityCount) < 0) {
            if (owner)
                kfree(owner);

            return false;
        }

        len = offsetof(SID, SubAuthority[0]) + (subauth_count * sizeof(uint32_t));

        group = kmalloc(len, GFP_KERNEL);
        if (!group) {
            if (owner)
                kfree(owner);

            return false;
        }

        if (copy_from_user(group, us_group, len) != 0) {
            if (owner)
                kfree(owner);

            kfree(group);
            return false;
        }
    }

    if (base.Sacl != 0) {
        ACL* us_sacl = (ACL*)((uint8_t*)us + base.Sacl);
        uint16_t len;

        if (get_user(len, &us_sacl->AclSize) < 0 || len == 0) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            return false;
        }

        sacl = kmalloc(len, GFP_KERNEL);
        if (!sacl) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            return false;
        }

        if (copy_from_user(sacl, us_sacl, len) != 0) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            return false;
        }
    }

    if (base.Dacl != 0) {
        ACL* us_dacl = (ACL*)((uint8_t*)us + base.Dacl);
        uint16_t len;

        if (get_user(len, &us_dacl->AclSize) < 0 || len == 0) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            if (sacl)
                kfree(sacl);

            return false;
        }

        dacl = kmalloc(len, GFP_KERNEL);
        if (!dacl) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            if (sacl)
                kfree(sacl);

            return false;
        }

        if (copy_from_user(dacl, us_dacl, len) != 0) {
            if (owner)
                kfree(owner);

            if (group)
                kfree(group);

            if (sacl)
                kfree(sacl);

            return false;
        }
    }

    // assemble

    size = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (owner)
        size += sid_length(owner);

    if (group)
        size += sid_length(group);

    if (sacl)
        size += sacl->AclSize;

    if (dacl)
        size += dacl->AclSize;

    sd = kmalloc(size, GFP_KERNEL);
    if (!sd) {
        if (owner)
            kfree(owner);

        if (group)
            kfree(group);

        if (sacl)
            kfree(sacl);

        if (dacl)
            kfree(dacl);

        return false;
    }

    memcpy(sd, &base, sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    base.Control |= SE_SELF_RELATIVE;

    off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);

    if (owner) {
        sd->Owner = off;
        memcpy(sd_get_owner(sd), owner, sid_length(owner));
        off += sid_length(owner);
        kfree(owner);
    }

    if (group) {
        sd->Group = off;
        memcpy(sd_get_group(sd), group, sid_length(group));
        off += sid_length(group);
        kfree(group);
    }

    if (sacl) {
        sd->Sacl = off;
        memcpy(sd_get_sacl(sd), sacl, sacl->AclSize);
        off += sacl->AclSize;
        kfree(sacl);
    }

    if (dacl) {
        sd->Dacl = off;
        memcpy(sd_get_dacl(sd), dacl, dacl->AclSize);
        kfree(dacl);
    }

    *ks = sd;

    return true;
}

NTSTATUS user_NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken,
                            ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping,
                            PPRIVILEGE_SET RequiredPrivilegesBuffer, PULONG BufferLength,
                            PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {
    NTSTATUS Status, access_status;
    GENERIC_MAPPING mapping;
    ULONG privbuflen, origlen;
    PRIVILEGE_SET* privs;
    ACCESS_MASK granted;
    SECURITY_DESCRIPTOR_RELATIVE* sd;

    if (!SecurityDescriptor || !RequiredPrivilegesBuffer || !BufferLength ||
        !GrantedAccess || !AccessStatus) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((uintptr_t)ClientToken & KERNEL_HANDLE_MASK)
        return STATUS_INVALID_HANDLE;

    if (GenericMapping && copy_from_user(&mapping, GenericMapping, sizeof(GENERIC_MAPPING)) != 0)
        return STATUS_ACCESS_VIOLATION;

    if (get_user(privbuflen, BufferLength) < 0)
        return STATUS_ACCESS_VIOLATION;

    if (!get_user_security_descriptor(&sd, SecurityDescriptor))
        return STATUS_ACCESS_VIOLATION;

    if (privbuflen > 0) {
        privs = kmalloc(privbuflen, GFP_KERNEL);
        if (!privs) {
            kfree(sd);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else
        privs = NULL;

    origlen = privbuflen;

    Status = NtAccessCheck(sd, ClientToken, DesiredAccess, GenericMapping ? &mapping : NULL,
                           privs, &privbuflen, &granted, &access_status);

    kfree(sd);

    if (privs) {
        ULONG to_copy = privbuflen;

        if (to_copy > origlen)
            to_copy = origlen;

        if (copy_to_user(RequiredPrivilegesBuffer, privs, to_copy) != 0)
            Status = STATUS_ACCESS_VIOLATION;

        kfree(privs);
    }

    if (put_user(privbuflen, BufferLength) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(granted, GrantedAccess) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    if (put_user(access_status, AccessStatus) < 0)
        Status = STATUS_ACCESS_VIOLATION;

    return Status;
}

NTSTATUS NtPrivilegeCheck(HANDLE TokenHandle, PPRIVILEGE_SET RequiredPrivileges,
                          PBOOLEAN Result) {
    printk(KERN_INFO "NtPrivilegeCheck(%lx, %px, %px): stub\n", (uintptr_t)TokenHandle,
           RequiredPrivileges, Result);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
                          POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
                          TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {
    printk(KERN_INFO "NtDuplicateToken(%lx, %x, %px, %x, %x, %px): stub\n",
           (uintptr_t)ExistingTokenHandle, DesiredAccess, ObjectAttributes,
           EffectiveOnly, TokenType, NewTokenHandle);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
}

static void sid_to_string(SID* sid, char* s) {
    uint64_t auth;
    unsigned int i;

    static const char prefix[] = "S-1-";

    memcpy(s, prefix, sizeof(prefix));

    auth = ((uint64_t)sid->IdentifierAuthority[0] << 40) |
        ((uint64_t)sid->IdentifierAuthority[1] << 32) |
        ((uint64_t)sid->IdentifierAuthority[2] << 24) |
        ((uint64_t)sid->IdentifierAuthority[3] << 16) |
        ((uint64_t)sid->IdentifierAuthority[4] << 8) |
        (uint64_t)sid->IdentifierAuthority[5];

    sprintf(s, "%s%llu", s, auth);

    for (i = 0; i < sid->SubAuthorityCount; i++) {
        sprintf(s, "%s-%u", s, sid->SubAuthority[i]);
    }
}

static void dump_acl(ACL* acl) {
    ACE_HEADER* ace;
    unsigned int i;

    printk(KERN_INFO "    AclRevision: %x\n", acl->AclRevision);
    printk(KERN_INFO "    Sbz1: %x\n", acl->Sbz1);
    printk(KERN_INFO "    AclSize: %x\n", acl->AclSize);
    printk(KERN_INFO "    AceCount: %x\n", acl->AceCount);
    printk(KERN_INFO "    Sbz2: %x\n", acl->Sbz2);

    ace = (ACE_HEADER*)&acl[1];

    for (i = 0; i < acl->AceCount; i++) {
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* aaa = (ACCESS_ALLOWED_ACE*)ace;
            char s[255];

            sid_to_string((SID*)&aaa->SidStart, s);

            printk(KERN_INFO "    ACE (flags = %x, size = %u): allow %s (mask = %x)\n",
                   aaa->Header.AceFlags, aaa->Header.AceSize, s, aaa->Mask);
        } else if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            ACCESS_DENIED_ACE* ada = (ACCESS_DENIED_ACE*)ace;
            char s[255];

            sid_to_string((SID*)&ada->SidStart, s);

            printk(KERN_INFO "    ACE (flags = %x, size = %u): deny %s (mask = %x)\n",
                   ada->Header.AceFlags, ada->Header.AceSize, s, ada->Mask);
        } else {
            printk(KERN_INFO "    ACE (flags = %x, size = %u): unhandled type %u\n",
                   ace->AceFlags, ace->AceSize, ace->AceType);
        }

        ace = (ACE_HEADER*)((uint8_t*)ace + ace->AceSize);
    }
}

void dump_sd(SECURITY_DESCRIPTOR_RELATIVE* sd) {
    SID* owner = sd->Owner != 0 ? sd_get_owner(sd) : NULL;
    SID* group = sd->Group != 0 ? sd_get_group(sd) : NULL;
    ACL* dacl = sd->Dacl != 0 ? sd_get_dacl(sd) : NULL;
    ACL* sacl = sd->Sacl != 0 ? sd_get_sacl(sd) : NULL;

    if (!owner)
        printk(KERN_INFO "Owner: (none)\n");
    else {
        char s[255];

        sid_to_string(owner, s);

        printk(KERN_INFO "Owner: %s\n", s);
    }

    if (!group)
        printk(KERN_INFO "Group: (none)\n");
    else {
        char s[255];

        sid_to_string(group, s);

        printk(KERN_INFO "Group: %s\n", s);
    }

    if (!dacl)
        printk(KERN_INFO "DACL: (none)\n");
    else {
        printk(KERN_INFO "DACL:\n");
        dump_acl(dacl);
    }

    if (!sacl)
        printk(KERN_INFO "SACL: (none)\n");
    else {
        printk(KERN_INFO "SACL:\n");
        dump_acl(sacl);
    }
}
