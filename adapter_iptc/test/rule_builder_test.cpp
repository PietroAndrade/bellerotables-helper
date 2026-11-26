#include "adapter_iptc/builder/rule_builder.h"

#include "adapter_iptc/dtos/conntrack.h"
#include "adapter_iptc/dtos/mark.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"
#include "adapter_iptc/mappers/conntrack_mapper.h"
#include "adapter_iptc/mappers/mark_mapper.h"
#include "adapter_iptc/mappers/verdict_mapper.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <linux/in.h>
#include <stdexcept>
#include <vector>

namespace {

constexpr uint32_t SAMPLE_MARK = 0x1234;
constexpr uint8_t NO_PROTOCOL = 0;

ExtensionParam markMatch()
{
    return MarkMapper::toExtension(MarkParam{.mark = SAMPLE_MARK});
}

ExtensionParam conntrackMatch()
{
    return ConntrackMapper::toExtension(ConntrackState::NEW);
}

ExtensionParam target(Verdict verdict)
{
    return VerdictMapper::toExtension(verdict);
}

} // namespace

TEST(RuleBuilderTest, MatchesKeepInsertionOrder)
{
    RuleBuilder builder;
    builder.addMatch(markMatch());
    builder.addMatch(conntrackMatch());
    builder.setTarget(target(Verdict::ACCEPT));

    const RuleParam rule = builder.build();

    EXPECT_EQ(rule.matches, (std::vector<ExtensionParam>{markMatch(), conntrackMatch()}));
}

TEST(RuleBuilderTest, TargetIsTheOneSet)
{
    RuleBuilder builder;
    builder.setTarget(target(Verdict::ACCEPT));
    builder.setTarget(target(Verdict::DROP));

    const RuleParam rule = builder.build();

    EXPECT_EQ(rule.target, target(Verdict::DROP));
}

TEST(RuleBuilderTest, ProtocolIsTheOneSet)
{
    RuleBuilder unset;
    unset.setTarget(target(Verdict::ACCEPT));
    RuleBuilder tcp;
    tcp.setProtocol(IPPROTO_TCP);
    tcp.setTarget(target(Verdict::ACCEPT));

    const RuleParam unsetRule = unset.build();
    const RuleParam tcpRule = tcp.build();

    EXPECT_EQ(unsetRule.protocol, NO_PROTOCOL);
    EXPECT_EQ(tcpRule.protocol, IPPROTO_TCP);
}

// LEARN: Review Focus 4: a rule without a target never reaches libiptc.
TEST(RuleBuilderTest, BuildWithoutTargetThrows)
{
    RuleBuilder builder;
    builder.addMatch(markMatch());

    EXPECT_THROW(static_cast<void>(builder.build()), std::invalid_argument);
}
