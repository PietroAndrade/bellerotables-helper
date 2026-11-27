#ifndef TCP_MAPPER_H
#define TCP_MAPPER_H

#include "adapter_iptc/dtos/port_range.h"
#include "adapter_iptc/dtos/rule.h"

/* LEARN: the "-m tcp" match as data: destination ports only, the source bounds always span every
   port. A single port is a range whose two ends are equal.
*/
struct TcpMapper
{
    [[nodiscard]] static ExtensionParam toExtension(PortRange destinationPorts);
};

#endif
