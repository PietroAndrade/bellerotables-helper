#ifndef ADAPTER_IPTC_TEST_LEGACY_RULE_BUILDER_H
#define ADAPTER_IPTC_TEST_LEGACY_RULE_BUILDER_H

#include "adapter_iptc/i_target_strategy.h"
#include "adapter_iptc/ipt_entry_ptr.h"
#include "adapter_iptc/rule_layout.h"
#include "adapter_iptc/template_match.h"

#include <cstddef>
#include <cstdint>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <memory>
#include <vector>

/* LEARN: the RuleBuilder as it was before the boundary became RuleParam: it writes the old
   TemplateMatch and ITargetStrategy straight into an ipt_entry. The tests of the old match and
   target classes (match_test.cpp, nflog_target_test.cpp) still build their rules with it; it goes
   away with them when the old hierarchy is deleted.
*/
class LegacyRuleBuilder
{
public:
    LegacyRuleBuilder& setMatch(const std::shared_ptr<TemplateMatch>& match)
    {
        m_matches.push_back(match);
        return *this;
    }

    LegacyRuleBuilder& setTarget(const std::shared_ptr<ITargetStrategy>& target)
    {
        m_target = target;
        return *this;
    }

    [[nodiscard]] IptEntryPtr build() const
    {
        std::size_t matchesSize = 0;
        for (const std::shared_ptr<TemplateMatch>& match : m_matches)
        {
            matchesSize += match->size();
        }

        const std::size_t targetOffset = sizeof(ipt_entry) + matchesSize;
        const std::size_t total = targetOffset + m_target->size();

        IptEntryPtr entry = RuleLayout::allocateEntry(total);
        entry->target_offset = targetOffset;
        entry->next_offset = total;
        entry->ip.proto = protocol();

        unsigned char* position = entry->elems;
        for (const std::shared_ptr<TemplateMatch>& match : m_matches)
        {
            match->write(position);
            position += match->size();
        }
        m_target->write(position);
        return entry;
    }

private:
    [[nodiscard]] uint8_t protocol() const
    {
        for (const std::shared_ptr<TemplateMatch>& match : m_matches)
        {
            const uint8_t proto = match->protocol();
            if (proto != 0)
            {
                return proto;
            }
        }
        return 0;
    }

    std::vector<std::shared_ptr<TemplateMatch>> m_matches;
    std::shared_ptr<ITargetStrategy> m_target;
};

#endif // ADAPTER_IPTC_TEST_LEGACY_RULE_BUILDER_H
