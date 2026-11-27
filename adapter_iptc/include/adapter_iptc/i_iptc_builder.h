#ifndef I_IPTC_BUILDER_H
#define I_IPTC_BUILDER_H

#include "adapter_iptc/dtos/rule.h"

class IBuilder
{
public:
    virtual ~IBuilder() = default;
    [[nodiscard]] virtual RuleParam build() const = 0;
};

#endif
