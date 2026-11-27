#include "adapter_iptc/mappers/udp_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstdint>
#include <linux/netfilter/xt_tcpudp.h>

template <>
struct PayloadIdentity<xt_udp>
{
    static constexpr const char* NAME = "udp";
    static constexpr uint8_t REVISION = 0;
};

namespace {

constexpr uint16_t FIRST_PORT = 0;
constexpr uint16_t LAST_PORT = 65535;

} // namespace

ExtensionParam UdpMapper::toExtension(PortRange destinationPorts)
{
    xt_udp info{};
    info.spts[0] = FIRST_PORT;
    info.spts[1] = LAST_PORT;
    info.dpts[0] = destinationPorts.min;
    info.dpts[1] = destinationPorts.max;
    ExtensionParam extension = PayloadMapper::toExtension(info);
    return extension;
}
