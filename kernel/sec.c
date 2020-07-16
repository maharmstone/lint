#include "muwine.h"
#include "sec.h"

static unsigned int sid_length(SID* sid) {
    return offsetof(SID, SubAuthority[0]) + (sid->SubAuthorityCount * sizeof(uint32_t));
}

NTSTATUS muwine_create_inherited_sd(const SECURITY_DESCRIPTOR* parent_sd, unsigned int parent_sd_len,
                                    SID* owner, SID* group, SECURITY_DESCRIPTOR** out, unsigned int* outlen) {
    unsigned int len = sizeof(SECURITY_DESCRIPTOR);
    SECURITY_DESCRIPTOR* sd;
    uint8_t* ptr;

    // FIXME - check parent_sd is valid

    if (owner)
        len += sid_length(owner);

    if (group)
        len += sid_length(group);

    // FIXME - SACL
    // FIXME - DACL

    sd = kmalloc(len, GFP_KERNEL);

    if (!sd)
        return STATUS_INSUFFICIENT_RESOURCES;

    sd->Revision = 1;
    sd->Sbz1 = 0;
    sd->Control = SE_SELF_RELATIVE;

    // FIXME - SE_DACL_PRESENT
    // FIXME - SE_SACL_PRESENT

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

    sd->OffsetSacl = 0; // FIXME
    sd->OffsetDacl = 0; // FIXME

    *out = sd;
    *outlen = len;

    return STATUS_SUCCESS;
}
