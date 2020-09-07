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

static void token_object_close(object_header* obj) {
    token_object* tok = (token_object*)obj;

    if (tok->owner)
        kfree(tok->owner);

    if (tok->group)
        kfree(tok->group);

    kfree(tok->privs);

    free_object(&tok->header);
}

static unsigned int sid_length(SID* sid) {
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

NTSTATUS muwine_create_inherited_sd(const SECURITY_DESCRIPTOR* parent_sd, unsigned int parent_sd_len, bool container,
                                    token_object* tok, SECURITY_DESCRIPTOR** out, unsigned int* outlen) {
    unsigned int len = sizeof(SECURITY_DESCRIPTOR);
    SECURITY_DESCRIPTOR* sd;
    uint8_t* ptr;
    unsigned int sacl_length = 0, dacl_length = 0;

    // FIXME - check parent_sd is valid

    if (tok && tok->owner)
        len += sid_length(tok->owner);

    if (tok && tok->group)
        len += sid_length(tok->group);

    if (parent_sd->OffsetSacl != 0) {
        sacl_length = inherited_acl_length((ACL*)((uint8_t*)parent_sd + parent_sd->OffsetSacl), container);
        len += sacl_length;
    }

    if (parent_sd->OffsetDacl != 0) {
        dacl_length = inherited_acl_length((ACL*)((uint8_t*)parent_sd + parent_sd->OffsetDacl), container);
        len += dacl_length;
    }

    sd = kmalloc(len, GFP_KERNEL);

    if (!sd)
        return STATUS_INSUFFICIENT_RESOURCES;

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE;

    if (parent_sd->OffsetSacl != 0)
        sd->Control |= SE_SACL_PRESENT;

    if (parent_sd->OffsetDacl != 0)
        sd->Control |= SE_DACL_PRESENT;

    ptr = (uint8_t*)&sd[1];

    if (tok && tok->owner) {
        unsigned int sidlen = sid_length(tok->owner);

        sd->OffsetOwner = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, tok->owner, sidlen);
        ptr += sidlen;
    } else
        sd->OffsetOwner = 0;

    if (tok && tok->group) {
        unsigned int sidlen = sid_length(tok->group);

        sd->OffsetGroup = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, tok->group, sidlen);
        ptr += sidlen;
    } else
        sd->OffsetGroup = 0;

    if (parent_sd->OffsetSacl != 0) {
        sd->OffsetSacl = (uint32_t)(ptr - (uint8_t*)sd);

        get_inherited_acl((ACL*)((uint8_t*)parent_sd + parent_sd->OffsetSacl),
                          (ACL*)((uint8_t*)sd + sd->OffsetSacl), container);

        ptr += sacl_length;
    } else
        sd->OffsetSacl = 0;

    if (parent_sd->OffsetDacl != 0) {
        sd->OffsetDacl = (uint32_t)(ptr - (uint8_t*)sd);

        get_inherited_acl((ACL*)((uint8_t*)parent_sd + parent_sd->OffsetDacl),
                          (ACL*)((uint8_t*)sd + sd->OffsetDacl), container);

        ptr += dacl_length;
    } else
        sd->OffsetDacl = 0;

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

void muwine_make_process_token(token_object** t) {
    token_object* tok;
    unsigned int priv_count, i;
    const default_privilege* def_privs;

    tok = kzalloc(sizeof(token_object), GFP_KERNEL);
    // FIXME - handle malloc failure

    tok->header.refcount = 1;

    tok->header.type = token_type;
    inc_obj_refcount(&token_type->header);

    spin_lock_init(&tok->header.path_lock);

    init_rwsem(&tok->sem);

    uid_to_sid(&tok->owner, current_euid());
    gid_to_sid(&tok->group, current_egid());

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

    *t = tok;
}

void muwine_registry_root_sd(SECURITY_DESCRIPTOR** out, unsigned int* sdlen) {
    SECURITY_DESCRIPTOR* sd;
    unsigned int len = sizeof(SECURITY_DESCRIPTOR);
    unsigned int dacl_len;
    ACL* sacl;
    ACL* dacl;
    ACCESS_ALLOWED_ACE* aaa;

    len += sizeof(sid_administrators); // owner
    len += sizeof(sid_local_system); // group
    len += sizeof(ACL); // SACL

    // DACL
    dacl_len = sizeof(ACL);
    dacl_len += 4 * sizeof(ACCESS_ALLOWED_ACE);
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
    sd->OffsetOwner = sizeof(SECURITY_DESCRIPTOR);
    sd->OffsetGroup = sd->OffsetOwner + sizeof(sid_administrators);
    sd->OffsetSacl = sd->OffsetGroup + sizeof(sid_local_system);
    sd->OffsetDacl = sd->OffsetSacl + sizeof(ACL);

    memcpy((uint8_t*)sd + sd->OffsetOwner, sid_administrators, sizeof(sid_administrators));
    memcpy((uint8_t*)sd + sd->OffsetGroup, sid_local_system, sizeof(sid_local_system));

    sacl = (ACL*)((uint8_t*)sd + sd->OffsetSacl);
    dacl = (ACL*)((uint8_t*)sd + sd->OffsetDacl);

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
    aaa->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(sid_users);
    aaa->Mask = READ_CONTROL | KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE;
    memcpy(&aaa[1], sid_users, sizeof(sid_users));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa[1] + sizeof(sid_users));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(sid_administrators);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa[1], sid_administrators, sizeof(sid_administrators));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa[1] + sizeof(sid_administrators));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(sid_local_system);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa[1], sid_local_system, sizeof(sid_local_system));

    aaa = (ACCESS_ALLOWED_ACE*)((uint8_t*)&aaa[1] + sizeof(sid_local_system));
    aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    aaa->Header.AceFlags = CONTAINER_INHERIT_ACE;
    aaa->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) + sizeof(sid_creator_owner);
    aaa->Mask = WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE | KEY_CREATE_LINK | KEY_NOTIFY |
                KEY_ENUMERATE_SUB_KEYS | KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_QUERY_VALUE;
    memcpy(&aaa[1], sid_creator_owner, sizeof(sid_creator_owner));

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

static NTSTATUS NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess,
                              POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType,
                              PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime,
                              PTOKEN_USER TokenUser, PTOKEN_GROUPS TokenGroups,
                              PTOKEN_PRIVILEGES TokenPrivileges, PTOKEN_OWNER TokenOwner,
                              PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                              PTOKEN_DEFAULT_DACL TokenDefaultDacl, PTOKEN_SOURCE TokenSource) {
    printk(KERN_INFO "NtCreateToken(%px, %x, %px, %x, %px, %px, %px, %px, %px, %px, %px, %px, %px): stub\n",
           TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId,
           ExpirationTime, TokenUser, TokenGroups, TokenPrivileges, TokenOwner,
           TokenPrimaryGroup, TokenDefaultDacl, TokenSource);

    // FIXME

    return STATUS_NOT_IMPLEMENTED;
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
    if (ObjectAttributes && oa.ObjectName) {
        if (oa.ObjectName->Buffer)
            kfree(oa.ObjectName->Buffer);

        kfree(oa.ObjectName);
    }

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
