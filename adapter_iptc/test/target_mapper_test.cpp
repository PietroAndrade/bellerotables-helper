#include "adapter_iptc/dtos/nflog.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"
#include "adapter_iptc/mappers/nflog_mapper.h"
#include "adapter_iptc/mappers/verdict_mapper.h"
#include "extension_bytes.h"
#include "parameterized_case.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_NFLOG.h>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr int ACCEPT_VERDICT = -NF_ACCEPT - 1;
constexpr int DROP_VERDICT = -NF_DROP - 1;
constexpr int RETURN_VERDICT = XT_RETURN;
constexpr const char* EMPTY_TARGET_NAME = "";
constexpr uint8_t STANDARD_TARGET_REVISION = 0;

constexpr const char* NFLOG_NAME = "NFLOG";
constexpr uint8_t NFLOG_REVISION = 0;
constexpr uint16_t SAMPLE_NFLOG_GROUP = 7;
constexpr const char* SAMPLE_NFLOG_PREFIX = "DNAT ";
constexpr uint32_t SAMPLE_NFLOG_RANGE = 128;
constexpr uint16_t SAMPLE_NFLOG_THRESHOLD = 10;
constexpr std::size_t KERNEL_PREFIX_BYTES = 63;
constexpr std::size_t KERNEL_PREFIX_FIELD_BYTES = 64;
constexpr const char* TWO_BYTE_CHARACTER = "\xC3\xA9";
constexpr const char* THREE_BYTE_CHARACTER = "\xE2\x82\xAC";
constexpr const char* FOUR_BYTE_CHARACTER = "\xF0\x9F\x98\x80";

std::string repeated(const std::string& unit, std::size_t times)
{
    std::string result;
    for (std::size_t index = 0; index < times; ++index)
    {
        result += unit;
    }
    return result;
}

NflogParam fullNflog()
{
    return NflogParam{.prefix = SAMPLE_NFLOG_PREFIX,
                      .group = SAMPLE_NFLOG_GROUP,
                      .range = SAMPLE_NFLOG_RANGE,
                      .threshold = SAMPLE_NFLOG_THRESHOLD};
}

NflogParam withoutRange(NflogParam nflog)
{
    nflog.range.reset();
    return nflog;
}

NflogParam withThreshold(NflogParam nflog, std::optional<uint16_t> threshold)
{
    nflog.threshold = threshold;
    return nflog;
}

NflogParam withPrefix(NflogParam nflog, std::string prefix)
{
    nflog.prefix = std::move(prefix);
    return nflog;
}

RuleParam ruleWithTarget(ExtensionParam target)
{
    return RuleParam{.target = std::move(target)};
}

xt_nflog_info nflogInfoOf(const NflogParam& nflog)
{
    const ExtensionParam extension = NflogMapper::toExtension(nflog);
    return ExtensionBytes::read<xt_nflog_info>(extension);
}

bool isValidUtf8(const std::string& text)
{
    std::size_t index = 0;
    while (index < text.size())
    {
        const auto lead = static_cast<unsigned char>(text[index]);
        std::size_t length = 0;
        if (lead < 0x80U)
            length = 1;
        else if ((lead & 0xE0U) == 0xC0U)
            length = 2;
        else if ((lead & 0xF0U) == 0xE0U)
            length = 3;
        else if ((lead & 0xF8U) == 0xF0U)
            length = 4;
        else
            return false;
        if (index + length > text.size())
            return false;
        for (std::size_t next = 1; next < length; ++next)
        {
            if ((static_cast<unsigned char>(text[index + next]) & 0xC0U) != 0x80U)
                return false;
        }
        index += length;
    }
    return true;
}

} // namespace

// LEARN: the case structs stay outside the anonymous namespace: parameterized_case.h's PrintTo
// is found by argument-dependent lookup only for types in the global namespace.

/* LEARN: the kernel encodes ACCEPT/DROP as -(verdict) - 1 so they never collide with a jump
   offset (>= 0); RETURN has its own negative constant.
*/
struct VerdictMapperCase
{
    Verdict verdict;
    int expectedKernelVerdict;
    const char* name;
};

const std::vector<VerdictMapperCase> VERDICT_MAPPER_CASES{
    {Verdict::ACCEPT, ACCEPT_VERDICT, "Accept"},
    {Verdict::DROP, DROP_VERDICT, "Drop"},
    {Verdict::RETURN, RETURN_VERDICT, "Return"},
};

class VerdictMapperTest : public ::testing::TestWithParam<VerdictMapperCase>
{
};

struct NflogMapperPrefixCase
{
    std::string prefix;
    std::string expectedInKernel;
    const char* name;
};

const std::vector<NflogMapperPrefixCase> NFLOG_MAPPER_PREFIX_CASES{
    {"", "", "Empty"},
    {SAMPLE_NFLOG_PREFIX, SAMPLE_NFLOG_PREFIX, "ShortWithTrailingSpace"},
    {repeated("a", KERNEL_PREFIX_BYTES), repeated("a", KERNEL_PREFIX_BYTES), "Exactly63Bytes"},
    {repeated("a", 64), repeated("a", KERNEL_PREFIX_BYTES), "AsciiCutAt63Bytes"},
    {repeated(TWO_BYTE_CHARACTER, 64), repeated(TWO_BYTE_CHARACTER, 31),
     "TwoByteCharactersCutBeforeTheSplitOne"},
    {repeated(THREE_BYTE_CHARACTER, 30), repeated(THREE_BYTE_CHARACTER, 21),
     "ThreeByteCharactersEndingExactlyAt63"},
    {repeated(FOUR_BYTE_CHARACTER, 20), repeated(FOUR_BYTE_CHARACTER, 15),
     "FourByteCharactersCutBeforeTheSplitOne"},
    {repeated("a", 62) + TWO_BYTE_CHARACTER, repeated("a", 62), "LastCharacterWouldStraddle63"},
};

class NflogMapperPrefixTest : public ::testing::TestWithParam<NflogMapperPrefixCase>
{
};

/* LEARN: how each NflogParam lands in xt_nflog_info. An unset range leaves len 0 without the
   XT_NFLOG_F_COPY_LEN flag, and an unset threshold leaves the kernel default: both mean "not set"
   to the kernel.
*/
struct NflogMapperWriteCase
{
    NflogParam nflog;
    uint32_t expectedLength;
    uint16_t expectedFlags;
    uint16_t expectedThreshold;
    const char* name;
};

const std::vector<NflogMapperWriteCase> NFLOG_MAPPER_WRITE_CASES{
    {NflogParam{.prefix = SAMPLE_NFLOG_PREFIX, .group = SAMPLE_NFLOG_GROUP}, 0, 0,
     XT_NFLOG_DEFAULT_THRESHOLD, "GroupAndPrefixOnly"},
    {fullNflog(), SAMPLE_NFLOG_RANGE, XT_NFLOG_F_COPY_LEN, SAMPLE_NFLOG_THRESHOLD, "EveryKnob"},
    {withThreshold(fullNflog(), std::nullopt), SAMPLE_NFLOG_RANGE, XT_NFLOG_F_COPY_LEN,
     XT_NFLOG_DEFAULT_THRESHOLD, "RangeOnly"},
    {withoutRange(fullNflog()), 0, 0, SAMPLE_NFLOG_THRESHOLD, "ThresholdOnly"},
};

class NflogMapperTest : public ::testing::TestWithParam<NflogMapperWriteCase>
{
};

/* LEARN: one rule and what NflogMapper::fromRule must make of its target. expected is nullopt when
   the target must not be decoded as NFLOG at all. The buffer-level cases (a target running past
   the entry, an offset inside the header) belong to RuleMapper, not here.
*/
struct NflogFromRuleCase
{
    RuleParam (*makeRule)();
    std::optional<NflogParam> expected;
    const char* name;
};

const std::vector<NflogFromRuleCase> NFLOG_DECODED_CASES{
    {[]() { return ruleWithTarget(NflogMapper::toExtension(fullNflog())); }, fullNflog(),
     "EveryFieldRoundTrips"},
    {[]() {
         return ruleWithTarget(NflogMapper::toExtension(NflogParam{.prefix = "", .group = 0}));
     },
     NflogParam{.prefix = "", .group = 0}, "UnsetRangeAndThresholdReadBackUnset"},
    {[]() { return ruleWithTarget(NflogMapper::toExtension(withThreshold(fullNflog(), 0))); },
     withThreshold(fullNflog(), std::nullopt), "ZeroThresholdIsTheKernelDefaultAndReadsBackUnset"},
    {[]() {
         xt_nflog_info info = nflogInfoOf(fullNflog());
         info.flags = 0;
         return ruleWithTarget(ExtensionBytes::make(NFLOG_NAME, NFLOG_REVISION, info));
     },
     withoutRange(fullNflog()), "LengthWithoutCopyLenFlagIsNotInEffectAndReadsBackUnset"},
    {[]() {
         xt_nflog_info info = nflogInfoOf(fullNflog());
         std::memset(info.prefix, 'x', KERNEL_PREFIX_FIELD_BYTES);
         return ruleWithTarget(ExtensionBytes::make(NFLOG_NAME, NFLOG_REVISION, info));
     },
     withPrefix(fullNflog(), repeated("x", KERNEL_PREFIX_FIELD_BYTES)),
     "PrefixFillingTheWholeFieldIsReadWithoutOverrun"},
};

const std::vector<NflogFromRuleCase> NFLOG_REJECTED_CASES{
    {[]() { return ruleWithTarget(VerdictMapper::toExtension(Verdict::ACCEPT)); }, std::nullopt,
     "StandardVerdictIsNotNflog"},
    {[]() {
         ExtensionParam extension = NflogMapper::toExtension(fullNflog());
         extension.name = "NFQUEUE";
         return ruleWithTarget(extension);
     },
     std::nullopt, "OtherExtensionTargetIsNotNflog"},
    {[]() { return RuleParam{}; }, std::nullopt, "RuleWithoutTargetHasNoNflog"},
    {[]() {
         ExtensionParam extension = NflogMapper::toExtension(fullNflog());
         extension.payload.resize(sizeof(xt_nflog_info) - 1);
         return ruleWithTarget(extension);
     },
     std::nullopt, "PayloadSmallerThanNflogInfoIsRejected"},
};

class NflogFromRuleTest : public ::testing::TestWithParam<NflogFromRuleCase>
{
};

TEST_P(VerdictMapperTest, WritesTheKernelVerdict)
{
    const ExtensionParam extension = VerdictMapper::toExtension(GetParam().verdict);
    const auto verdict = ExtensionBytes::read<int>(extension);

    EXPECT_EQ(extension.name, EMPTY_TARGET_NAME);
    EXPECT_EQ(extension.revision, STANDARD_TARGET_REVISION);
    EXPECT_EQ(extension.payload.size(), sizeof(int));
    EXPECT_EQ(verdict, GetParam().expectedKernelVerdict);
}

INSTANTIATE_TEST_SUITE_P(VerdictMapper, VerdictMapperTest,
                         ::testing::ValuesIn(VERDICT_MAPPER_CASES), caseName<VerdictMapperCase>);

TEST(NflogMapperIdentityTest, ExtensionCarriesNameRevisionAndPayloadOfItsKernelStruct)
{
    const ExtensionParam extension = NflogMapper::toExtension(fullNflog());

    EXPECT_EQ(extension.name, NFLOG_NAME);
    EXPECT_EQ(extension.revision, NFLOG_REVISION);
    EXPECT_EQ(extension.payload.size(), sizeof(xt_nflog_info));
}

TEST_P(NflogMapperTest, WritesEveryKnobIntoTheKernelInfo)
{
    const NflogParam& nflog = GetParam().nflog;
    const xt_nflog_info info = nflogInfoOf(nflog);

    EXPECT_EQ(info.group, nflog.group);
    EXPECT_STREQ(info.prefix, nflog.prefix.c_str());
    EXPECT_EQ(info.len, GetParam().expectedLength);
    EXPECT_EQ(info.flags, GetParam().expectedFlags);
    EXPECT_EQ(info.threshold, GetParam().expectedThreshold);
}

INSTANTIATE_TEST_SUITE_P(NflogMapper, NflogMapperTest,
                         ::testing::ValuesIn(NFLOG_MAPPER_WRITE_CASES),
                         caseName<NflogMapperWriteCase>);

TEST_P(NflogMapperPrefixTest, KeepsWholeCharactersWithinTheKernelBudget)
{
    const NflogParam nflog{.prefix = GetParam().prefix, .group = SAMPLE_NFLOG_GROUP};
    const xt_nflog_info info = nflogInfoOf(nflog);

    const std::string written(info.prefix);

    EXPECT_EQ(written, GetParam().expectedInKernel);
    EXPECT_LE(written.size(), KERNEL_PREFIX_BYTES);
    EXPECT_TRUE(isValidUtf8(written));
}

INSTANTIATE_TEST_SUITE_P(NflogMapper, NflogMapperPrefixTest,
                         ::testing::ValuesIn(NFLOG_MAPPER_PREFIX_CASES),
                         caseName<NflogMapperPrefixCase>);

TEST_P(NflogFromRuleTest, DecodesWhatTheRuleHolds)
{
    const RuleParam rule = GetParam().makeRule();

    EXPECT_EQ(NflogMapper::fromRule(rule), GetParam().expected);
}

INSTANTIATE_TEST_SUITE_P(Decoded, NflogFromRuleTest, ::testing::ValuesIn(NFLOG_DECODED_CASES),
                         caseName<NflogFromRuleCase>);

INSTANTIATE_TEST_SUITE_P(Rejected, NflogFromRuleTest, ::testing::ValuesIn(NFLOG_REJECTED_CASES),
                         caseName<NflogFromRuleCase>);
