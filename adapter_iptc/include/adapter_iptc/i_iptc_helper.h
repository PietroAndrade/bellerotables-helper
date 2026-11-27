#ifndef I_IPTC_HELPER_H
#define I_IPTC_HELPER_H

#include "adapter_iptc/dtos/rule.h"

#include <vector>

class IIptcHelper
{
public:
    virtual ~IIptcHelper() = default;
    virtual void createChain() = 0;
    virtual void flushEntries() = 0;
    virtual void appendRule(const RuleParam& rule) = 0;
    virtual void commit() = 0;

    /* LEARN: the read side. Both look at the handle's snapshot: after commit() the next call takes
       a fresh snapshot, so what they return is what the kernel holds, not what was appended.
       listRules() returns the rules in order, as data, so they outlive the handle; it throws when
       the chain does not exist, which chainExists() lets the caller check first.
    */
    virtual bool chainExists() = 0;
    virtual std::vector<RuleParam> listRules() = 0;
};

#endif
