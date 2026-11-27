#ifndef CONNTRACK_MAPPER_H
#define CONNTRACK_MAPPER_H

#include "adapter_iptc/dtos/conntrack.h"
#include "adapter_iptc/dtos/rule.h"

/* LEARN: the "-m conntrack --ctstate" match as data: a ConntrackState becomes the match flags and
   the state mask of xt_conntrack_mtinfo3.
*/
struct ConntrackMapper
{
    [[nodiscard]] static ExtensionParam toExtension(ConntrackState state);
};

#endif
