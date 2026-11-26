#ifndef HASHLIMIT_MAPPER_H
#define HASHLIMIT_MAPPER_H

#include "adapter_iptc/dtos/hashlimit.h"
#include "adapter_iptc/dtos/rule.h"

/* LEARN: the "-m hashlimit" match as data: a HashlimitParam becomes the named rate config of
   xt_hashlimit_mtinfo1. A mode of 0 means the default: hash on source address, destination address
   and destination port.
*/
struct HashlimitMapper
{
    [[nodiscard]] static ExtensionParam toExtension(const HashlimitParam& hashlimit);
};

#endif
