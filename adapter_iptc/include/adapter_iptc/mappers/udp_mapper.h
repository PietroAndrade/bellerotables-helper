#ifndef UDP_MAPPER_H
#define UDP_MAPPER_H

#include "adapter_iptc/dtos/port_range.h"
#include "adapter_iptc/dtos/rule.h"

/* LEARN: the "-m udp" match as data: destination ports only, the source bounds always span every
   port. A single port is a range whose two ends are equal.
*/
struct UdpMapper
{
    [[nodiscard]] static ExtensionParam toExtension(PortRange destinationPorts);
};

#endif
