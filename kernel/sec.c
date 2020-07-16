#include "muwine.h"
#include "sec.h"

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
                                    SID* owner, SID* group, SECURITY_DESCRIPTOR** out, unsigned int* outlen) {
    unsigned int len = sizeof(SECURITY_DESCRIPTOR);
    SECURITY_DESCRIPTOR* sd;
    uint8_t* ptr;
    unsigned int sacl_length = 0, dacl_length = 0;

    // FIXME - check parent_sd is valid

    if (owner)
        len += sid_length(owner);

    if (group)
        len += sid_length(group);

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

    if (owner) {
        unsigned int sidlen = sid_length(owner);

        sd->OffsetOwner = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, owner, sidlen);
        ptr += sidlen;
    } else
        sd->OffsetOwner = 0;

    if (group) {
        unsigned int sidlen = sid_length(group);

        sd->OffsetGroup = (uint32_t)(ptr - (uint8_t*)sd);
        memcpy(ptr, group, sidlen);
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
