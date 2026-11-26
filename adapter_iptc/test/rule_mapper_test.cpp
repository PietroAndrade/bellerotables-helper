#include "adapter_iptc/mappers/rule_mapper.h"

#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/ipt_entry_ptr.h"
#include "parameterized_case.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_NFLOG.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr const char* MARK_NAME = "mark";
constexpr const char* TCP_NAME = "tcp";
constexpr const char* UDP_NAME = "udp";
constexpr const char* NFLOG_NAME = "NFLOG";
constexpr uint8_t MARK_REVISION = 1;
constexpr uint8_t PORT_MATCH_REVISION = 0;
constexpr uint8_t NO_PROTOCOL = 0;
constexpr int ACCEPT_VERDICT = -NF_ACCEPT - 1;

constexpr std::size_t MARK_MATCH_BYTES = XT_ALIGN(sizeof(xt_entry_match) + sizeof(xt_mark_mtinfo1));
constexpr std::size_t TCP_MATCH_BYTES = XT_ALIGN(sizeof(xt_entry_match) + sizeof(xt_tcp));
constexpr std::size_t UDP_MATCH_BYTES = XT_ALIGN(sizeof(xt_entry_match) + sizeof(xt_udp));
constexpr std::size_t STANDARD_TARGET_BYTES = XT_ALIGN(sizeof(xt_standard_target));

std::vector<unsigned char> bytes(std::size_t count, unsigned char first = 1)
{
    std::vector<unsigned char> result(count);
    for (std::size_t index = 0; index < count; ++index)
        result[index] = static_cast<unsigned char>(first + index);
    return result;
}

ExtensionParam markMatch()
{
    return ExtensionParam{
        .name = MARK_NAME, .revision = MARK_REVISION, .payload = bytes(sizeof(xt_mark_mtinfo1))};
}

ExtensionParam tcpMatch()
{
    return ExtensionParam{
        .name = TCP_NAME, .revision = PORT_MATCH_REVISION, .payload = bytes(sizeof(xt_tcp))};
}

ExtensionParam udpMatch()
{
    return ExtensionParam{
        .name = UDP_NAME, .revision = PORT_MATCH_REVISION, .payload = bytes(sizeof(xt_udp))};
}

ExtensionParam acceptTarget()
{
    std::vector<unsigned char> verdict(sizeof(int));
    std::memcpy(verdict.data(), &ACCEPT_VERDICT, sizeof(int));
    return ExtensionParam{.name = "", .revision = 0, .payload = verdict};
}

ExtensionParam nflogTarget()
{
    return ExtensionParam{
        .name = NFLOG_NAME, .revision = 0, .payload = bytes(sizeof(xt_nflog_info))};
}

RuleParam ruleOf(std::vector<ExtensionParam> matches, ExtensionParam target)
{
    return RuleParam{.protocol = NO_PROTOCOL, .matches = std::move(matches), .target = target};
}

unsigned char* bytesOf(ipt_entry& entry)
{
    return reinterpret_cast<unsigned char*>(&entry);
}

xt_entry_match* matchAt(ipt_entry& entry, std::size_t offsetInMatches)
{
    return reinterpret_cast<xt_entry_match*>(bytesOf(entry) + sizeof(ipt_entry) + offsetInMatches);
}

xt_entry_target* targetOf(ipt_entry& entry)
{
    return reinterpret_cast<xt_entry_target*>(bytesOf(entry) + entry.target_offset);
}

} // namespace

/* LEARN: one rule shape and the offsets toEntry must give it: the matches fill the space between
   the rule header and target_offset, the target the space up to next_offset.
*/
struct RuleShapeCase
{
    std::vector<ExtensionParam> (*matches)();
    std::size_t expectedMatchesBytes;
    const char* name;
};

const std::vector<RuleShapeCase> RULE_SHAPE_CASES{
    {[]() { return std::vector<ExtensionParam>{}; }, 0, "NoMatch"},
    {[]() { return std::vector<ExtensionParam>{markMatch()}; }, MARK_MATCH_BYTES, "MarkOnly"},
    {[]() { return std::vector<ExtensionParam>{markMatch(), tcpMatch()}; },
     MARK_MATCH_BYTES + TCP_MATCH_BYTES, "MarkTcp"},
    {[]() { return std::vector<ExtensionParam>{tcpMatch(), udpMatch()}; },
     TCP_MATCH_BYTES + UDP_MATCH_BYTES, "TcpUdp"},
};

class RuleMapperToEntryShape : public ::testing::TestWithParam<RuleShapeCase>
{
};

TEST_P(RuleMapperToEntryShape, TargetOffsetCoversHeaderAndEveryMatch)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf(GetParam().matches(), acceptTarget()));
    const std::size_t expectedTargetOffset = sizeof(ipt_entry) + GetParam().expectedMatchesBytes;

    EXPECT_EQ(static_cast<std::size_t>(entry->target_offset), expectedTargetOffset);
}

TEST_P(RuleMapperToEntryShape, NextOffsetIsTargetOffsetPlusTargetSize)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf(GetParam().matches(), acceptTarget()));
    const std::size_t targetOffset = entry->target_offset;

    EXPECT_EQ(static_cast<std::size_t>(entry->next_offset), targetOffset + STANDARD_TARGET_BYTES);
}

INSTANTIATE_TEST_SUITE_P(RuleMapperToEntry, RuleMapperToEntryShape,
                         ::testing::ValuesIn(RULE_SHAPE_CASES), caseName<RuleShapeCase>);

TEST(RuleMapperToEntry, MatchHeadersLandInInsertionOrder)
{
    const IptEntryPtr entry =
        RuleMapper::toEntry(ruleOf({markMatch(), tcpMatch()}, acceptTarget()));

    const xt_entry_match* mark = matchAt(*entry, 0);
    const xt_entry_match* tcp = matchAt(*entry, MARK_MATCH_BYTES);

    EXPECT_STREQ(mark->u.user.name, MARK_NAME);
    EXPECT_EQ(mark->u.user.revision, MARK_REVISION);
    EXPECT_EQ(static_cast<std::size_t>(mark->u.user.match_size), MARK_MATCH_BYTES);
    EXPECT_STREQ(tcp->u.user.name, TCP_NAME);
    EXPECT_EQ(tcp->u.user.revision, PORT_MATCH_REVISION);
    EXPECT_EQ(static_cast<std::size_t>(tcp->u.user.match_size), TCP_MATCH_BYTES);
}

TEST(RuleMapperToEntry, MatchPayloadFollowsItsHeader)
{
    const ExtensionParam mark = markMatch();
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({mark}, acceptTarget()));

    const unsigned char* payload = matchAt(*entry, 0)->data;

    EXPECT_EQ(std::vector<unsigned char>(payload, payload + mark.payload.size()), mark.payload);
}

TEST(RuleMapperToEntry, StandardTargetVerdictLandsAtTargetOffset)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({markMatch()}, acceptTarget()));

    const auto* standard = reinterpret_cast<const xt_standard_target*>(targetOf(*entry));

    EXPECT_EQ(static_cast<std::size_t>(standard->target.u.user.target_size), STANDARD_TARGET_BYTES);
    EXPECT_EQ(standard->verdict, ACCEPT_VERDICT);
    EXPECT_STREQ(standard->target.u.user.name, "");
}

TEST(RuleMapperToEntry, ProtocolLandsInTheRuleHeader)
{
    RuleParam rule = ruleOf({tcpMatch()}, acceptTarget());
    rule.protocol = IPPROTO_TCP;

    const IptEntryPtr entry = RuleMapper::toEntry(rule);

    EXPECT_EQ(entry->ip.proto, IPPROTO_TCP);
}

TEST(RuleMapperToEntry, RuleWithoutTargetThrows)
{
    const RuleParam rule{.protocol = NO_PROTOCOL, .matches = {markMatch()}, .target = std::nullopt};

    EXPECT_THROW((void)RuleMapper::toEntry(rule), std::invalid_argument);
}

/* LEARN: target_offset, next_offset and match_size are 16-bit fields; a rule larger than they can
   hold must be refused, never written with a truncated offset.
*/
TEST(RuleMapperToEntry, RuleTooLargeForTheOffsetsThrows)
{
    ExtensionParam huge = markMatch();
    huge.payload.resize(UINT16_MAX);

    EXPECT_THROW((void)RuleMapper::toEntry(ruleOf({huge}, acceptTarget())), std::length_error);
}

TEST(RuleMapperToEntry, LongNameIsCutToTheField)
{
    constexpr uint8_t GIVEN_REVISION = 7;
    const std::string longName(40, 'x');
    ExtensionParam match = markMatch();
    match.name = longName;
    match.revision = GIVEN_REVISION;

    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({match}, acceptTarget()));
    const xt_entry_match* header = matchAt(*entry, 0);

    EXPECT_EQ(std::string(header->u.user.name), longName.substr(0, XT_EXTENSION_MAXNAMELEN - 1));
    EXPECT_EQ(header->u.user.revision, GIVEN_REVISION);
}

TEST(RuleMapperFromEntry, RoundTripsAnAlignedRule)
{
    constexpr uint8_t TARGET_REVISION = 2;
    const RuleParam rule{
        .protocol = IPPROTO_UDP,
        .matches = {ExtensionParam{
            .name = MARK_NAME, .revision = MARK_REVISION, .payload = bytes(8)}},
        .target =
            ExtensionParam{.name = NFLOG_NAME, .revision = TARGET_REVISION, .payload = bytes(16)},
    };

    EXPECT_EQ(RuleMapper::fromEntry(*RuleMapper::toEntry(rule)), rule);
}

TEST(RuleMapperFromEntry, PayloadKeepsAlignmentPadding)
{
    constexpr std::size_t PAYLOAD_BYTES = 12;
    const std::vector<unsigned char> payload = bytes(PAYLOAD_BYTES);
    const RuleParam rule =
        ruleOf({ExtensionParam{.name = MARK_NAME, .revision = MARK_REVISION, .payload = payload}},
               acceptTarget());

    const RuleParam readBack = RuleMapper::fromEntry(*RuleMapper::toEntry(rule));

    ASSERT_EQ(readBack.matches.size(), 1U);
    const std::vector<unsigned char>& readPayload = readBack.matches[0].payload;
    ASSERT_EQ(readPayload.size(),
              XT_ALIGN(sizeof(xt_entry_match) + PAYLOAD_BYTES) - sizeof(xt_entry_match));
    EXPECT_EQ(std::vector<unsigned char>(readPayload.begin(), readPayload.begin() + PAYLOAD_BYTES),
              payload);
}

/* LEARN: a rule of one mark match and ACCEPT, edited after toEntry to play a buffer the kernel or
   another tool could hand back; fromEntry must stop the matches walk without losing the target.
*/
struct MalformedMatchesCase
{
    void (*edit)(ipt_entry& entry);
    std::size_t expectedMatches;
    bool expectedTarget;
    const char* name;
};

const std::vector<MalformedMatchesCase> MALFORMED_MATCHES_CASES{
    {[](ipt_entry& entry) { matchAt(entry, 0)->u.user.match_size = 0; }, 0, true,
     "ZeroMatchSizeStopsTheWalk"},
    {[](ipt_entry& entry) { matchAt(entry, 0)->u.user.match_size = MARK_MATCH_BYTES + 8; }, 0, true,
     "MatchRunningIntoTheTargetStops"},
    {[](ipt_entry& entry) { matchAt(entry, 0)->u.user.match_size = sizeof(xt_entry_match); }, 1,
     true, "HeaderOnlyMatchIsKeptWithAnEmptyPayload"},
    {[](ipt_entry& entry) { entry.target_offset = entry.next_offset + 8; }, 0, false,
     "TargetOffsetPastTheEntry"},
};

class RuleMapperMalformedMatches : public ::testing::TestWithParam<MalformedMatchesCase>
{
};

TEST_P(RuleMapperMalformedMatches, StopsTheWalkAndKeepsWhatIsSound)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({markMatch()}, acceptTarget()));
    GetParam().edit(*entry);

    const RuleParam rule = RuleMapper::fromEntry(*entry);

    ASSERT_EQ(rule.matches.size(), GetParam().expectedMatches);
    EXPECT_EQ(rule.target.has_value(), GetParam().expectedTarget);
    for (const ExtensionParam& match : rule.matches)
        EXPECT_TRUE(match.payload.empty());
}

INSTANTIATE_TEST_SUITE_P(RuleMapperFromEntry, RuleMapperMalformedMatches,
                         ::testing::ValuesIn(MALFORMED_MATCHES_CASES),
                         caseName<MalformedMatchesCase>);

/* LEARN: a rule with an NFLOG target, edited after toEntry so the target can no longer be
   trusted; fromEntry must leave the target empty instead of reading out of the rule.
*/
struct MalformedTargetCase
{
    void (*edit)(ipt_entry& entry);
    const char* name;
};

const std::vector<MalformedTargetCase> MALFORMED_TARGET_CASES{
    {[](ipt_entry& entry) { entry.next_offset = entry.target_offset + sizeof(xt_entry_target); },
     "TargetRunningPastTheEntry"},
    {[](ipt_entry& entry) {
         /* LEARN: a well-formed NFLOG target is copied to offset 0, over the rule header, and
            target_offset points at it. Its name and size are sound, so only the "target starts
            after the rule header" check can reject it.
         */
         static_assert(
             XT_ALIGN(sizeof(xt_entry_target) + sizeof(xt_nflog_info)) <= sizeof(ipt_entry),
             "the NFLOG target must fit over the rule header");
         const std::size_t entryEnd = entry.next_offset;
         const unsigned char* realTarget = bytesOf(entry) + entry.target_offset;
         const std::size_t targetBytes = targetOf(entry)->u.user.target_size;
         const std::vector<unsigned char> targetCopy(realTarget, realTarget + targetBytes);

         std::memcpy(bytesOf(entry), targetCopy.data(), targetBytes);
         entry.target_offset = 0;
         entry.next_offset = entryEnd;
     },
     "TargetOffsetInsideTheHeader"},
    {[](ipt_entry& entry) { targetOf(entry)->u.user.target_size = sizeof(xt_entry_target) - 1; },
     "TargetSizeSmallerThanItsHeader"},
};

class RuleMapperMalformedTarget : public ::testing::TestWithParam<MalformedTargetCase>
{
};

TEST_P(RuleMapperMalformedTarget, LeavesTheTargetEmpty)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({}, nflogTarget()));
    GetParam().edit(*entry);

    EXPECT_FALSE(RuleMapper::fromEntry(*entry).target.has_value());
}

INSTANTIATE_TEST_SUITE_P(RuleMapperFromEntry, RuleMapperMalformedTarget,
                         ::testing::ValuesIn(MALFORMED_TARGET_CASES),
                         caseName<MalformedTargetCase>);

TEST(RuleMapperFromEntry, HeaderOnlyTargetIsKeptWithAnEmptyPayload)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({}, nflogTarget()));
    targetOf(*entry)->u.user.target_size = sizeof(xt_entry_target);

    const RuleParam rule = RuleMapper::fromEntry(*entry);

    ASSERT_TRUE(rule.target.has_value());
    EXPECT_EQ(rule.target->name, NFLOG_NAME);
    EXPECT_TRUE(rule.target->payload.empty());
}

TEST(RuleMapperFromEntry, BrokenMatchStillLeavesTheTarget)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({markMatch()}, nflogTarget()));
    matchAt(*entry, 0)->u.user.match_size = 0;

    const RuleParam rule = RuleMapper::fromEntry(*entry);

    EXPECT_TRUE(rule.matches.empty());
    ASSERT_TRUE(rule.target.has_value());
    EXPECT_EQ(rule.target->name, NFLOG_NAME);
    const std::vector<unsigned char> written = nflogTarget().payload;
    ASSERT_GE(rule.target->payload.size(), written.size());
    EXPECT_TRUE(std::equal(written.begin(), written.end(), rule.target->payload.begin()));
}

TEST(RuleMapperFromEntry, NameWithoutTerminatorIsBounded)
{
    const IptEntryPtr entry = RuleMapper::toEntry(ruleOf({markMatch()}, acceptTarget()));
    std::memset(matchAt(*entry, 0)->u.user.name, 'm', XT_EXTENSION_MAXNAMELEN);

    const RuleParam rule = RuleMapper::fromEntry(*entry);

    ASSERT_EQ(rule.matches.size(), 1U);
    EXPECT_EQ(rule.matches[0].name, std::string(XT_EXTENSION_MAXNAMELEN, 'm'));
}

TEST(RuleMapperFromEntry, TargetRevisionIsRead)
{
    constexpr uint8_t TARGET_REVISION = 3;
    ExtensionParam target = nflogTarget();
    target.revision = TARGET_REVISION;

    const RuleParam rule = RuleMapper::fromEntry(*RuleMapper::toEntry(ruleOf({}, target)));

    ASSERT_TRUE(rule.target.has_value());
    EXPECT_EQ(rule.target->revision, TARGET_REVISION);
}

TEST(RuleMapperFromEntry, ProtocolIsRead)
{
    RuleParam rule = ruleOf({}, acceptTarget());
    rule.protocol = IPPROTO_TCP;

    EXPECT_EQ(RuleMapper::fromEntry(*RuleMapper::toEntry(rule)).protocol, IPPROTO_TCP);
}
