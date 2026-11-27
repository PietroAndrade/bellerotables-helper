#include "adapter_iptc/dtos/conntrack.h"
#include "adapter_iptc/dtos/hashlimit.h"
#include "adapter_iptc/dtos/mark.h"
#include "adapter_iptc/dtos/port_range.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/mappers/conntrack_mapper.h"
#include "adapter_iptc/mappers/hashlimit_mapper.h"
#include "adapter_iptc/mappers/mark_mapper.h"
#include "adapter_iptc/mappers/tcp_mapper.h"
#include "adapter_iptc/mappers/udp_mapper.h"
#include "extension_bytes.h"
#include "parameterized_case.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/xt_hashlimit.h>
#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr uint32_t SAMPLE_MARK = 0x1234;
constexpr uint32_t OTHER_MARK = 0x5678;
constexpr uint32_t SAMPLE_MARK_MASK = 0xff00;
constexpr uint32_t FULL_MARK_MASK = 0xffffffff;
constexpr const char* MARK_NAME = "mark";
constexpr uint8_t MARK_REVISION = 1;

constexpr uint16_t SAMPLE_PORT = 8080;
constexpr uint16_t SAMPLE_PORT_RANGE_MIN = 1000;
constexpr uint16_t SAMPLE_PORT_RANGE_MAX = 2000;
constexpr uint16_t FULL_PORT_RANGE_MIN = 0;
constexpr uint16_t FULL_PORT_RANGE_MAX = 65535;
constexpr const char* TCP_NAME = "tcp";
constexpr const char* UDP_NAME = "udp";
constexpr uint8_t PORT_MATCH_REVISION = 0;

constexpr const char* CONNTRACK_NAME = "conntrack";
constexpr uint8_t CONNTRACK_REVISION = 3;

constexpr const char* HASHLIMIT_NAME = "hashlimit";
constexpr uint8_t HASHLIMIT_REVISION = 1;
constexpr const char* SAMPLE_HASHLIMIT_NAME = "limit-ssh";
constexpr uint32_t SAMPLE_HASHLIMIT_AVERAGE = 300;
constexpr uint32_t SAMPLE_HASHLIMIT_BURST = 5;
constexpr uint32_t SAMPLE_HASHLIMIT_EXPIRE = 60000;
constexpr uint32_t DEFAULT_GARBAGE_COLLECTION_INTERVAL = 1000;
constexpr uint8_t DEFAULT_HOST_MASK = 32;
constexpr uint32_t DEFAULT_HASHLIMIT_MODE =
    XT_HASHLIMIT_HASH_SIP | XT_HASHLIMIT_HASH_DIP | XT_HASHLIMIT_HASH_DPT;
constexpr uint32_t EXPLICIT_HASHLIMIT_MODE = XT_HASHLIMIT_HASH_DIP;

HashlimitParam sampleHashlimit()
{
    return HashlimitParam{.name = SAMPLE_HASHLIMIT_NAME,
                          .average = SAMPLE_HASHLIMIT_AVERAGE,
                          .burst = SAMPLE_HASHLIMIT_BURST,
                          .expire = SAMPLE_HASHLIMIT_EXPIRE};
}

RuleParam ruleWith(std::vector<ExtensionParam> matches)
{
    return RuleParam{.matches = std::move(matches)};
}

ExtensionParam markExtension(uint32_t mark)
{
    return MarkMapper::toExtension(MarkParam{.mark = mark});
}

/* LEARN: xt_tcp and xt_udp are different structs that both start with the source and the
   destination port bounds; each case reads them through its own struct.
*/
struct PortBounds
{
    uint16_t sourceMin;
    uint16_t sourceMax;
    uint16_t destinationMin;
    uint16_t destinationMax;
};

PortBounds tcpPortsOf(const ExtensionParam& extension)
{
    const auto info = ExtensionBytes::read<xt_tcp>(extension);
    return {info.spts[0], info.spts[1], info.dpts[0], info.dpts[1]};
}

PortBounds udpPortsOf(const ExtensionParam& extension)
{
    const auto info = ExtensionBytes::read<xt_udp>(extension);
    return {info.spts[0], info.spts[1], info.dpts[0], info.dpts[1]};
}

} // namespace

// LEARN: the case structs stay outside the anonymous namespace: parameterized_case.h's PrintTo
// is found by argument-dependent lookup only for types in the global namespace.
/* LEARN: what every match mapper must produce: the name and revision the kernel looks the match
   up by, and a payload as large as its kernel struct.
*/
struct MatchIdentityCase
{
    ExtensionParam (*makeExtension)();
    const char* expectedName;
    uint8_t expectedRevision;
    std::size_t expectedPayloadBytes;
    const char* name;
};

const std::vector<MatchIdentityCase> MATCH_IDENTITY_CASES{
    {[]() { return markExtension(SAMPLE_MARK); }, MARK_NAME, MARK_REVISION, sizeof(xt_mark_mtinfo1),
     "Mark"},
    {[]() { return TcpMapper::toExtension(PortRange{SAMPLE_PORT, SAMPLE_PORT}); }, TCP_NAME,
     PORT_MATCH_REVISION, sizeof(xt_tcp), "Tcp"},
    {[]() { return UdpMapper::toExtension(PortRange{SAMPLE_PORT, SAMPLE_PORT}); }, UDP_NAME,
     PORT_MATCH_REVISION, sizeof(xt_udp), "Udp"},
    {[]() { return ConntrackMapper::toExtension(ConntrackState::NEW); }, CONNTRACK_NAME,
     CONNTRACK_REVISION, sizeof(xt_conntrack_mtinfo3), "Conntrack"},
    {[]() { return HashlimitMapper::toExtension(sampleHashlimit()); }, HASHLIMIT_NAME,
     HASHLIMIT_REVISION, sizeof(xt_hashlimit_mtinfo1), "Hashlimit"},
};

class MatchIdentityTest : public ::testing::TestWithParam<MatchIdentityCase>
{
};

struct MarkMapperCase
{
    ExtensionParam extension;
    uint32_t expectedMark;
    uint32_t expectedMask;
    const char* name;
};

const std::vector<MarkMapperCase> MARK_WRITE_CASES{
    {MarkMapper::toExtension(MaskedMark{.mark = SAMPLE_MARK, .mask = SAMPLE_MARK_MASK}),
     SAMPLE_MARK, SAMPLE_MARK_MASK, "ExplicitMask"},
    {MarkMapper::toExtension(MarkParam{.mark = SAMPLE_MARK}), SAMPLE_MARK, FULL_MARK_MASK,
     "DefaultMaskCoversAllMarkBits"},
};

class MarkMapperTest : public ::testing::TestWithParam<MarkMapperCase>
{
};

/* LEARN: tcp and udp match only destination ports; the source bounds always span every port.
   A single port is a range whose two ends are equal.
*/
struct PortMapperCase
{
    ExtensionParam extension;
    PortBounds (*portsOf)(const ExtensionParam& extension);
    uint16_t expectedDestinationMin;
    uint16_t expectedDestinationMax;
    const char* name;
};

const std::vector<PortMapperCase> PORT_CASES{
    {TcpMapper::toExtension(PortRange{SAMPLE_PORT, SAMPLE_PORT}), tcpPortsOf, SAMPLE_PORT,
     SAMPLE_PORT, "TcpSinglePort"},
    {TcpMapper::toExtension(PortRange{SAMPLE_PORT_RANGE_MIN, SAMPLE_PORT_RANGE_MAX}), tcpPortsOf,
     SAMPLE_PORT_RANGE_MIN, SAMPLE_PORT_RANGE_MAX, "TcpPortRange"},
    {UdpMapper::toExtension(PortRange{SAMPLE_PORT, SAMPLE_PORT}), udpPortsOf, SAMPLE_PORT,
     SAMPLE_PORT, "UdpSinglePort"},
    {UdpMapper::toExtension(PortRange{SAMPLE_PORT_RANGE_MIN, SAMPLE_PORT_RANGE_MAX}), udpPortsOf,
     SAMPLE_PORT_RANGE_MIN, SAMPLE_PORT_RANGE_MAX, "UdpPortRange"},
};

class PortMapperTest : public ::testing::TestWithParam<PortMapperCase>
{
};

struct ConntrackMapperCase
{
    ConntrackState state;
    uint16_t expectedFlags;
    uint16_t expectedStateMask;
    const char* name;
};

const std::vector<ConntrackMapperCase> CONNTRACK_STATE_CASES{
    {ConntrackState::NEW, XT_CONNTRACK_STATE | XT_CONNTRACK_DIRECTION, NF_CT_STATE_BIT(IP_CT_NEW),
     "NewWithDirectionFlag"},
    {ConntrackState::ESTABLISHED_RELATED, XT_CONNTRACK_STATE,
     NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED), "EstablishedRelated"},
    {ConntrackState::INVALID, XT_CONNTRACK_STATE, NF_CT_STATE_INVALID_BIT, "Invalid"},
};

class ConntrackMapperTest : public ::testing::TestWithParam<ConntrackMapperCase>
{
};

/* LEARN: one rule and what MarkMapper::fromRule must make of it. expected is nullopt when the rule
   has no plain mark match. The buffer-level cases (zero size, running into the target, target
   offset past the entry) belong to RuleMapper, not here.
*/
struct MarkFromRuleCase
{
    RuleParam (*makeRule)();
    std::optional<MarkParam> expected;
    const char* name;
};

const std::vector<MarkFromRuleCase> MARK_DECODED_CASES{
    {[]() { return ruleWith({markExtension(SAMPLE_MARK)}); }, MarkParam{SAMPLE_MARK},
     "MarkWrittenByMarkMapperRoundTrips"},
    {[]() {
         return ruleWith(
             {ConntrackMapper::toExtension(ConntrackState::NEW), markExtension(SAMPLE_MARK)});
     },
     MarkParam{SAMPLE_MARK}, "MarkAfterAnotherMatchIsFound"},
    {[]() { return ruleWith({markExtension(SAMPLE_MARK), markExtension(OTHER_MARK)}); },
     MarkParam{SAMPLE_MARK}, "FirstOfTwoMarkMatchesIsRead"},
};

const std::vector<MarkFromRuleCase> MARK_REJECTED_CASES{
    {[]() { return ruleWith({ConntrackMapper::toExtension(ConntrackState::NEW)}); }, std::nullopt,
     "RuleWithoutMarkMatchHasNoMark"},
    {[]() { return ruleWith({}); }, std::nullopt, "RuleWithoutMatchesHasNoMark"},
    {[]() {
         return ruleWith(
             {MarkMapper::toExtension(MaskedMark{.mark = SAMPLE_MARK, .mask = SAMPLE_MARK_MASK})});
     },
     std::nullopt, "PartialMaskIsNotAPlainMark"},
    {[]() {
         const xt_mark_mtinfo1 inverted{.mark = SAMPLE_MARK, .mask = FULL_MARK_MASK, .invert = 1};
         return ruleWith({ExtensionBytes::make(MARK_NAME, MARK_REVISION, inverted)});
     },
     std::nullopt, "InvertedMarkIsNotAPlainMark"},
    {[]() {
         const xt_mark_mtinfo1 info{.mark = SAMPLE_MARK, .mask = FULL_MARK_MASK, .invert = 0};
         return ruleWith({ExtensionBytes::make(MARK_NAME, 0, info)});
     },
     std::nullopt, "OtherRevisionHasAnotherLayoutAndIsNotRead"},
    {[]() {
         ExtensionParam extension = markExtension(SAMPLE_MARK);
         extension.payload.resize(sizeof(xt_mark_mtinfo1) - 1);
         return ruleWith({extension});
     },
     std::nullopt, "PayloadSmallerThanMarkInfoIsRejected"},
    {[]() {
         ExtensionParam extension = markExtension(SAMPLE_MARK);
         extension.name = "other";
         return ruleWith({extension});
     },
     std::nullopt, "OtherNameIsNotMark"},
};

class MarkFromRuleTest : public ::testing::TestWithParam<MarkFromRuleCase>
{
};

TEST_P(MatchIdentityTest, ExtensionCarriesNameRevisionAndPayloadOfItsKernelStruct)
{
    const ExtensionParam extension = GetParam().makeExtension();

    EXPECT_EQ(extension.name, GetParam().expectedName);
    EXPECT_EQ(extension.revision, GetParam().expectedRevision);
    EXPECT_EQ(extension.payload.size(), GetParam().expectedPayloadBytes);
}

INSTANTIATE_TEST_SUITE_P(Match, MatchIdentityTest, ::testing::ValuesIn(MATCH_IDENTITY_CASES),
                         caseName<MatchIdentityCase>);

TEST_P(MarkMapperTest, StoresMarkAndMask)
{
    const auto info = ExtensionBytes::read<xt_mark_mtinfo1>(GetParam().extension);

    EXPECT_EQ(info.mark, GetParam().expectedMark);
    EXPECT_EQ(info.mask, GetParam().expectedMask);
}

INSTANTIATE_TEST_SUITE_P(MarkMapper, MarkMapperTest, ::testing::ValuesIn(MARK_WRITE_CASES),
                         caseName<MarkMapperCase>);

TEST_P(PortMapperTest, WritesDestinationBoundsAndEverySourcePort)
{
    const PortBounds ports = GetParam().portsOf(GetParam().extension);

    EXPECT_EQ(ports.destinationMin, GetParam().expectedDestinationMin);
    EXPECT_EQ(ports.destinationMax, GetParam().expectedDestinationMax);
    EXPECT_EQ(ports.sourceMin, FULL_PORT_RANGE_MIN);
    EXPECT_EQ(ports.sourceMax, FULL_PORT_RANGE_MAX);
}

INSTANTIATE_TEST_SUITE_P(PortMapper, PortMapperTest, ::testing::ValuesIn(PORT_CASES),
                         caseName<PortMapperCase>);

TEST_P(ConntrackMapperTest, WritesFlagsAndStateBits)
{
    const ExtensionParam extension = ConntrackMapper::toExtension(GetParam().state);
    const auto info = ExtensionBytes::read<xt_conntrack_mtinfo3>(extension);

    EXPECT_EQ(info.match_flags, GetParam().expectedFlags);
    EXPECT_EQ(info.state_mask, GetParam().expectedStateMask);
}

INSTANTIATE_TEST_SUITE_P(ConntrackMapper, ConntrackMapperTest,
                         ::testing::ValuesIn(CONNTRACK_STATE_CASES), caseName<ConntrackMapperCase>);

TEST(HashlimitMapperTest, WriteFillsNamedRateConfigWithDefaults)
{
    const ExtensionParam extension = HashlimitMapper::toExtension(sampleHashlimit());
    const auto info = ExtensionBytes::read<xt_hashlimit_mtinfo1>(extension);

    EXPECT_STREQ(info.name, SAMPLE_HASHLIMIT_NAME);
    EXPECT_EQ(info.cfg.avg, SAMPLE_HASHLIMIT_AVERAGE);
    EXPECT_EQ(info.cfg.burst, SAMPLE_HASHLIMIT_BURST);
    EXPECT_EQ(info.cfg.expire, SAMPLE_HASHLIMIT_EXPIRE);
    EXPECT_EQ(info.cfg.gc_interval, DEFAULT_GARBAGE_COLLECTION_INTERVAL);
    EXPECT_EQ(info.cfg.srcmask, DEFAULT_HOST_MASK);
    EXPECT_EQ(info.cfg.dstmask, DEFAULT_HOST_MASK);
    EXPECT_EQ(info.cfg.mode, DEFAULT_HASHLIMIT_MODE);
}

TEST(HashlimitMapperTest, ExplicitModeIsWrittenVerbatim)
{
    HashlimitParam hashlimit = sampleHashlimit();
    hashlimit.mode = EXPLICIT_HASHLIMIT_MODE;

    const ExtensionParam extension = HashlimitMapper::toExtension(hashlimit);
    const auto info = ExtensionBytes::read<xt_hashlimit_mtinfo1>(extension);

    EXPECT_EQ(info.cfg.mode, EXPLICIT_HASHLIMIT_MODE);
}

TEST_P(MarkFromRuleTest, DecodesWhatTheRuleHolds)
{
    const RuleParam rule = GetParam().makeRule();

    EXPECT_EQ(MarkMapper::fromRule(rule), GetParam().expected);
}

INSTANTIATE_TEST_SUITE_P(Decoded, MarkFromRuleTest, ::testing::ValuesIn(MARK_DECODED_CASES),
                         caseName<MarkFromRuleCase>);

INSTANTIATE_TEST_SUITE_P(Rejected, MarkFromRuleTest, ::testing::ValuesIn(MARK_REJECTED_CASES),
                         caseName<MarkFromRuleCase>);
