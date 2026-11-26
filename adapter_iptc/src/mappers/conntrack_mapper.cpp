#include "adapter_iptc/mappers/conntrack_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstdint>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_conntrack.h>

template <>
struct PayloadIdentity<xt_conntrack_mtinfo3>
{
    static constexpr const char* NAME = "conntrack";
    static constexpr uint8_t REVISION = 3;
};

ExtensionParam ConntrackMapper::toExtension(ConntrackState state)
{
    xt_conntrack_mtinfo3 info{};

    /* LEARN: match_flags says which fields of xt_conntrack_mtinfo3 the kernel compares: a field
       whose XT_CONNTRACK_* flag is not set is ignored, whatever it holds. XT_CONNTRACK_STATE turns
       on the check of state_mask, the "--ctstate" of iptables. invert_flags (left 0) would negate
       each checked field ("! --ctstate").
       state_mask is the set of connection states the rule accepts, one bit per state. A packet
       matches when the bit of its own state is set. NF_CT_STATE_BIT(ctinfo) maps NEW,
       ESTABLISHED and RELATED to one bit each (a reply to an established connection shares the bit
       of ESTABLISHED); INVALID has a bit of its own, NF_CT_STATE_INVALID_BIT, that is not a ctinfo.
       The default below is INVALID: a state the switch does not know never accepts a good packet.
    */
    info.match_flags = XT_CONNTRACK_STATE;
    info.state_mask = NF_CT_STATE_INVALID_BIT;
    switch (state)
    {
        case ConntrackState::NEW:
            /* LEARN: XT_CONNTRACK_DIRECTION adds a second check: only packets travelling in the
               original direction, from the side that opened the connection, match. Together with
               the NEW bit the rule sees the first packet of a connection and nothing that comes
               back on it.
            */
            info.match_flags = XT_CONNTRACK_STATE | XT_CONNTRACK_DIRECTION;
            info.state_mask = NF_CT_STATE_BIT(IP_CT_NEW);
            break;
        case ConntrackState::ESTABLISHED_RELATED:
            // LEARN: both states in one mask: a packet of either one matches, in both directions.
            info.state_mask = NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED);
            break;
        case ConntrackState::INVALID:
            // LEARN: the defaults above are already INVALID: only the STATE check, the INVALID bit.
            break;
    }
    ExtensionParam extension = PayloadMapper::toExtension(info);
    return extension;
}
