#include "adapter_iptc/builder/rule_builder.h"

#include <cstdint>
#include <stdexcept>

RuleBuilder& RuleBuilder::setProtocol(uint8_t protocol)
{
    m_rule.protocol = protocol;
    return *this;
}

RuleBuilder& RuleBuilder::addMatch(const ExtensionParam& match)
{
    m_rule.matches.push_back(match);
    return *this;
}

RuleBuilder& RuleBuilder::setTarget(const ExtensionParam& target)
{
    m_rule.target = target;
    return *this;
}

RuleParam RuleBuilder::build() const
{
    const bool hasTarget = m_rule.target.has_value();
    if (!hasTarget)
    {
        throw std::invalid_argument("a rule needs a target");
    }
    return m_rule;
}
