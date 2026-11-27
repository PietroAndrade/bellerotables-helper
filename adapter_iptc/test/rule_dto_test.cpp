#include "adapter_iptc/dtos/conntrack.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

constexpr uint8_t MARK_REVISION = 1;
constexpr uint8_t NFLOG_REVISION = 0;

ExtensionParam markMatchWithPayload(std::vector<unsigned char> payload)
{
    return ExtensionParam{.name = "mark", .revision = MARK_REVISION, .payload = std::move(payload)};
}

RuleParam ruleWith(const ExtensionParam& match)
{
    return RuleParam{.protocol = 0,
                     .matches = {match},
                     .target = ExtensionParam{.name = "NFLOG", .revision = NFLOG_REVISION}};
}

} // namespace

TEST(RuleDtoTest, DefaultRuleHasNoProtocolNoMatchesNoTarget)
{
    const RuleParam rule{};

    EXPECT_EQ(rule.protocol, 0);
    EXPECT_TRUE(rule.matches.empty());
    EXPECT_FALSE(rule.target.has_value());
}

TEST(RuleDtoTest, RulesWithEqualFieldsAreEqual)
{
    const RuleParam rule = ruleWith(markMatchWithPayload({1, 2}));
    const RuleParam same = ruleWith(markMatchWithPayload({1, 2}));
    const RuleParam otherPayload = ruleWith(markMatchWithPayload({1, 3}));

    EXPECT_EQ(rule, same);
    EXPECT_NE(rule, otherPayload);
}

/* LEARN: the DTO headers carry data only. This file includes no match or target header, so
   building the conntrack and verdict DTOs here proves their enums no longer live in a class.
*/
TEST(RuleDtoTest, DtoHeadersPullNoClass)
{
    static_assert(std::is_aggregate_v<ConntrackParam>);

    const ConntrackParam conntrack{.state = ConntrackState::NEW};
    const Verdict verdict = Verdict::ACCEPT;

    EXPECT_EQ(conntrack.state, ConntrackState::NEW);
    EXPECT_EQ(verdict, Verdict::ACCEPT);
}
