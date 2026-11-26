#include "adapter_iptc/mappers/hashlimit_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstdint>
#include <cstring>
#include <linux/netfilter/xt_hashlimit.h>

template <>
struct PayloadIdentity<xt_hashlimit_mtinfo1>
{
    static constexpr const char* NAME = "hashlimit";
    static constexpr uint8_t REVISION = 1;
};

namespace {

/* LEARN: mode is what an entry of the hash table is keyed on, and every distinct key gets its own
   rate limit (its own avg and burst). XT_HASHLIMIT_HASH_SIP, _DIP, _SPT and _DPT add the source
   address, destination address, source port and destination port to the key. With SIP | DIP | DPT
   the limit is per source host, per destination host and per destination port: one client hitting
   one service is limited on its own, not together with the other clients. Source port is left out
   on purpose: a client opens each connection from a new one, so keying on it would give every
   connection a fresh bucket and never limit anything. A mode of 0 keys on nothing, so every packet
   would share one entry: a single global limit, which is why 0 is read as "not set" and replaced.
   Inherited from the previous HashlimitMatch; no other rationale is recorded in the repo.
*/
constexpr uint32_t DEFAULT_MODE =
    XT_HASHLIMIT_HASH_SIP | XT_HASHLIMIT_HASH_DIP | XT_HASHLIMIT_HASH_DPT;

} // namespace

ExtensionParam HashlimitMapper::toExtension(const HashlimitParam& hashlimit)
{
    xt_hashlimit_mtinfo1 info{};
    const char* name = hashlimit.name.c_str();
    std::strncpy(info.name, name, sizeof(info.name) - 1);

    const bool usesDefaultMode = hashlimit.mode == 0U;
    const uint32_t mode = usesDefaultMode ? DEFAULT_MODE : hashlimit.mode;

    /* LEARN: cfg is the hashlimit_cfg1 nested in the match payload: the rate limit itself, as
       opposed to name, which only labels the hash table the kernel keeps for it. mode (a bitmask
       of XT_HASHLIMIT_HASH_*) picks what an entry is keyed on: source address, destination
       address, ports. avg is not a rate but the average time between packets times the kernel's
       scale, and burst multiplies it into the upper limit. expire and gc_interval age idle
       entries out, and srcmask and dstmask cut the addresses to a prefix before keying. size
       (buckets) and max (entries) are not set: zero asks the kernel for its defaults. The hinfo
       pointer after cfg is kernel-private and stays zero.
    */
    info.cfg.mode = mode;
    info.cfg.avg = hashlimit.average;
    info.cfg.burst = hashlimit.burst;
    info.cfg.expire = hashlimit.expire;
    info.cfg.gc_interval = hashlimit.garbageCollectionInterval;
    info.cfg.srcmask = hashlimit.sourceMask;
    info.cfg.dstmask = hashlimit.destinationMask;
    ExtensionParam extension = PayloadMapper::toExtension(info);
    return extension;
}
