#include "adapter_iptc/builder/rule_builder.h"

#include "adapter_iptc/ipt_entry_ptr.h"
#include "adapter_iptc/rule_layout.h"

#include <cstdlib>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <new>

RuleBuilder& RuleBuilder::setMatch(const std::shared_ptr<TemplateMatch>& match)
{
    matches_.push_back(match);
    return *this;
}

RuleBuilder& RuleBuilder::setTarget(const std::shared_ptr<ITargetStrategy>& target)
{
    target_ = target;
    return *this;
}

IptEntryPtr RuleBuilder::build() const
{
    std::size_t matchesSize = 0;
    for (const auto& match : matches_)
        matchesSize += match->size();

    auto targetOffset = sizeof(ipt_entry) + matchesSize;
    auto total = targetOffset + target_->size();

    IptEntryPtr entry = RuleLayout::allocateEntry(total);
    entry->target_offset = targetOffset;
    entry->next_offset = total;
    entry->ip.proto = resolveProtocol();

    auto* ptr = entry->elems;
    for (const auto& match : matches_)
    {
        match->write(ptr);
        ptr += match->size();
    }

    target_->write(ptr);
    return entry;
}

/* TODO: the kernel requires the rule protocol (ipt_entry.ip.proto, "-p tcp") to match the
   protocol a match is bound to: xt_check_match() rejects "-m tcp" / "-m udp" in a rule without it,
   and since iptc_commit() sends the whole table, the error only surfaces at commit as EINVAL, far
   from its cause. Today the first non-zero protocol() wins, so a rule holding both tcp and udp
   matches silently takes the first one and the kernel rejects the other. Planned: stateless
   mappers that each produce a RuleBody (protocol, matches, target), e.g. TcpMapper::toBody(ports)
   yields protocol = IPPROTO_TCP plus the "tcp" match, and the builder merges the bodies and throws
   on two different protocols, two targets or no target. Not needed until the redirection DNAT
   (--dport) reaches this adapter.
*/
uint8_t RuleBuilder::resolveProtocol() const
{
    for (const auto& match : matches_)
    {
        auto proto = match->protocol();
        if (proto != 0)
            return proto;
    }
    return 0;
}
