#include "adapter_iptc/adapters/mangle_adapter.h"

#include "adapter_iptc/builder/rule_builder.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"
#include "adapter_iptc/mappers/conntrack_mapper.h"
#include "adapter_iptc/mappers/mark_mapper.h"
#include "adapter_iptc/mappers/nflog_mapper.h"
#include "adapter_iptc/mappers/verdict_mapper.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

MangleAdapter::MangleAdapter(const std::string& chain)
    : m_helper(std::make_shared<IptcHelper>("mangle", chain))
{
}

/* LEARN: every activation re-applies the desired state, so the chain may already exist;
   creating it only when missing makes createChain() safe to repeat.
*/
void MangleAdapter::createChain()
{
    if (!m_helper->chainExists())
    {
        m_helper->createChain();
    }
}

void MangleAdapter::flush()
{
    m_helper->flushEntries();
}

void MangleAdapter::addConntrackRule(MarkParam mark, ConntrackParam conntrack)
{
    const ExtensionParam markMatch = MarkMapper::toExtension(mark);
    const ExtensionParam conntrackMatch = ConntrackMapper::toExtension(conntrack.state);
    const ExtensionParam acceptTarget = VerdictMapper::toExtension(Verdict::ACCEPT);

    RuleBuilder builder;
    builder.addMatch(markMatch);
    builder.addMatch(conntrackMatch);
    builder.setTarget(acceptTarget);
    const RuleParam rule = builder.build();

    m_helper->appendRule(rule);
}

void MangleAdapter::addNflogRule(MarkParam mark, NflogParam nflog)
{
    const ExtensionParam markMatch = MarkMapper::toExtension(mark);
    const ExtensionParam nflogTarget = NflogMapper::toExtension(nflog);

    RuleBuilder builder;
    builder.addMatch(markMatch);
    builder.setTarget(nflogTarget);
    const RuleParam rule = builder.build();

    m_helper->appendRule(rule);
}

void MangleAdapter::setHelper(std::shared_ptr<IIptcHelper> helper)
{
    m_helper = std::move(helper);
}

void MangleAdapter::commit()
{
    m_helper->commit();
}

std::vector<NflogRuleParam> MangleAdapter::readNflogRules()
{
    std::vector<NflogRuleParam> rules;
    if (!m_helper->chainExists())
    {
        return rules;
    }

    const std::vector<RuleParam> listed = m_helper->listRules();
    for (const RuleParam& rule : listed)
    {
        std::optional<NflogParam> nflog = NflogMapper::fromRule(rule);
        const bool isNflog = nflog.has_value();
        if (!isNflog)
        {
            continue;
        }

        std::optional<MarkParam> mark = MarkMapper::fromRule(rule);
        rules.push_back(NflogRuleParam{.mark = mark, .nflog = std::move(*nflog)});
    }
    return rules;
}
