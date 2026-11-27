#ifndef RULE_BUILDER_H
#define RULE_BUILDER_H

#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/i_iptc_builder.h"

#include <cstdint>

/* LEARN: assembles a RuleParam from extensions the mappers already produced. It knows nothing of
   the kernel layout: RuleMapper::toEntry() turns the finished rule into the ipt_entry buffer.
*/
class RuleBuilder final : public IBuilder
{
public:
    /* TODO: the kernel requires the rule protocol (ipt_entry.ip.proto, "-p tcp") to match the
       protocol a match is bound to: xt_check_match() rejects "-m tcp" / "-m udp" in a rule without
       it, and since iptc_commit() sends the whole table, the error only surfaces at commit as
       EINVAL, far from its cause. Today the caller sets the protocol by hand, and nothing checks it
       against the matches, so a tcp match under protocol 0 is only caught by the kernel. Planned:
       stateless mappers that each produce a RuleBody (protocol, matches, target), e.g.
       TcpMapper::toBody(ports) yields protocol = IPPROTO_TCP plus the "tcp" match, and the builder
       merges the bodies and throws on two different protocols, two targets or no target. Not
       needed until the redirection DNAT (--dport) reaches this adapter.
    */
    RuleBuilder& setProtocol(uint8_t protocol);
    RuleBuilder& addMatch(const ExtensionParam& match);
    RuleBuilder& setTarget(const ExtensionParam& target);

    // Throws std::invalid_argument without a target.
    [[nodiscard]] RuleParam build() const override;

private:
    RuleParam m_rule;
};

#endif
