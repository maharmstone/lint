#include "muwine.h"
#include "sec.h"

static const uint8_t sid_users[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x21, 0x2, 0, 0 }; // S-1-5-32-545
static const uint8_t sid_administrators[] = { 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 0x2, 0, 0 }; // S-1-5-32-544
static const uint8_t sid_local_system[] = { 1, 1, 0, 0, 0, 0, 0, 5, 0x12, 0, 0, 0 }; // S-1-5-18
static const uint8_t sid_creator_owner[] = { 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0 }; // S-1-3-0

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
                                    token* tok, SECURITY_DESCRIPTOR** out, unsigned int* outlen) {
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

#if 0 // Samba's scheme
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

void muwine_make_process_token(token** t) {
    token* tok;

    tok = kzalloc(sizeof(token), GFP_KERNEL);
    // FIXME - handle malloc failure

    uid_to_sid(&tok->owner, current_euid());
    gid_to_sid(&tok->group, current_egid());

    *t = tok;
}

static void duplicate_sid(SID* old, SID** new) {
    unsigned int len = sid_length(old);
    SID* s = kmalloc(len, GFP_KERNEL); // FIXME - handle malloc failure

    memcpy(s, old, len);

    *new = s;
}

void muwine_duplicate_token(token* old, token** new) {
    token* tok;

    tok = kzalloc(sizeof(token), GFP_KERNEL);
    // FIXME - handle malloc failure

    if (old->owner)
        duplicate_sid(old->owner, &tok->owner);

    if (old->group)
        duplicate_sid(old->group, &tok->group);

    *new = tok;
}

void muwine_free_token(token* token) {
    if (token->owner)
        kfree(token->owner);

    if (token->group)
        kfree(token->group);

    kfree(token);
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
