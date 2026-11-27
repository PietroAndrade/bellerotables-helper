#include "adapter_iptc/adapters/mangle_adapter.h"

#include "adapter_iptc/builder/rule_builder.h"
#include "adapter_iptc/dtos/conntrack.h"
#include "adapter_iptc/dtos/mark.h"
#include "adapter_iptc/dtos/nflog.h"
#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"
#include "adapter_iptc/exceptions/iptc_exception.h"
#include "adapter_iptc/mappers/conntrack_mapper.h"
#include "adapter_iptc/mappers/mark_mapper.h"
#include "adapter_iptc/mappers/nflog_mapper.h"
#include "adapter_iptc/mappers/verdict_mapper.h"
#include "adapter_iptc/mocks/mock_iptc_helper.h"
#include "parameterized_case.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace {

constexpr const char* CHAIN_NAME = "bb_mangle_redir_1";
constexpr uint32_t SAMPLE_MARK = 0x1234;
constexpr uint32_t OTHER_MARK = 0x5678;
constexpr uint16_t SAMPLE_NFLOG_GROUP = 5;
constexpr uint16_t OTHER_NFLOG_GROUP = 6;
constexpr const char* SAMPLE_NFLOG_PREFIX = "bb-log";
constexpr uint32_t SAMPLE_NFLOG_RANGE = 128;
constexpr uint16_t SAMPLE_NFLOG_THRESHOLD = 10;
constexpr std::size_t EXPECTED_CALL_COUNT = 1;

NflogParam fullNflog()
{
    return NflogParam{.prefix = SAMPLE_NFLOG_PREFIX,
                      .group = SAMPLE_NFLOG_GROUP,
                      .range = SAMPLE_NFLOG_RANGE,
                      .threshold = SAMPLE_NFLOG_THRESHOLD};
}

NflogParam minimalNflog()
{
    return NflogParam{.prefix = "", .group = OTHER_NFLOG_GROUP};
}

RuleParam nflogRule(uint32_t mark, const NflogParam& nflog)
{
    RuleBuilder builder;
    builder.addMatch(MarkMapper::toExtension(MarkParam{.mark = mark}));
    builder.setTarget(NflogMapper::toExtension(nflog));
    return builder.build();
}

RuleParam unmarkedNflogRule(const NflogParam& nflog)
{
    RuleBuilder builder;
    builder.setTarget(NflogMapper::toExtension(nflog));
    return builder.build();
}

RuleParam conntrackRule()
{
    RuleBuilder builder;
    builder.addMatch(MarkMapper::toExtension(MarkParam{.mark = SAMPLE_MARK}));
    builder.addMatch(ConntrackMapper::toExtension(ConntrackState::NEW));
    builder.setTarget(VerdictMapper::toExtension(Verdict::ACCEPT));
    return builder.build();
}

} // namespace

/* LEARN: every test drives one MangleAdapter whose libiptc helper is a mock, so it checks what
   the adapter asks of libiptc without a kernel. The mock verifies its expectations when the
   fixture is destroyed.
*/
class MangleAdapterTest : public ::testing::Test
{
protected:
    MangleAdapterTest()
        : m_adapter(CHAIN_NAME)
    {
        m_adapter.setHelper(m_helper);
    }

    std::shared_ptr<MockIptcHelper> m_helper = std::make_shared<MockIptcHelper>();
    MangleAdapter m_adapter;
};

TEST_F(MangleAdapterTest, CreateChainDelegatesToHelperExactlyOnce)
{
    EXPECT_CALL(*m_helper, chainExists()).WillOnce(testing::Return(false));
    EXPECT_CALL(*m_helper, createChain()).Times(testing::Exactly(EXPECTED_CALL_COUNT));

    m_adapter.createChain();
}

TEST_F(MangleAdapterTest, CreateChainSkipsAChainThatAlreadyExists)
{
    EXPECT_CALL(*m_helper, chainExists()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_helper, createChain()).Times(0);

    m_adapter.createChain();
}

TEST_F(MangleAdapterTest, FlushDelegatesToFlushEntriesExactlyOnce)
{
    EXPECT_CALL(*m_helper, flushEntries()).Times(testing::Exactly(EXPECTED_CALL_COUNT));

    m_adapter.flush();
}

TEST_F(MangleAdapterTest, CommitDelegatesToHelperExactlyOnce)
{
    EXPECT_CALL(*m_helper, commit()).Times(testing::Exactly(EXPECTED_CALL_COUNT));

    m_adapter.commit();
}

TEST_F(MangleAdapterTest, AddConntrackRuleAppendsMarkThenConntrackMatchWithAcceptTarget)
{
    RuleParam appended;
    EXPECT_CALL(*m_helper, appendRule(testing::_))
        .Times(testing::Exactly(EXPECTED_CALL_COUNT))
        .WillOnce(testing::SaveArg<0>(&appended));

    m_adapter.addConntrackRule(MarkParam{SAMPLE_MARK}, ConntrackParam{ConntrackState::NEW});

    EXPECT_EQ(appended, conntrackRule());
}

TEST_F(MangleAdapterTest, ReadNflogRulesIsEmptyWithoutListingWhenTheChainIsMissing)
{
    EXPECT_CALL(*m_helper, chainExists()).WillOnce(testing::Return(false));
    EXPECT_CALL(*m_helper, listRules()).Times(0);

    EXPECT_TRUE(m_adapter.readNflogRules().empty());
}

TEST_F(MangleAdapterTest, WhatAddNflogRuleAppendsReadsBackUnchanged)
{
    std::vector<RuleParam> kernel;

    EXPECT_CALL(*m_helper, appendRule(testing::_))
        .WillOnce(testing::Invoke([&kernel](const RuleParam& rule) { kernel.push_back(rule); }));
    EXPECT_CALL(*m_helper, chainExists()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_helper, listRules()).WillOnce(testing::Invoke([&kernel] { return kernel; }));

    m_adapter.addNflogRule(MarkParam{SAMPLE_MARK}, fullNflog());

    EXPECT_EQ(
        m_adapter.readNflogRules(),
        (std::vector<NflogRuleParam>{{.mark = MarkParam{SAMPLE_MARK}, .nflog = fullNflog()}}));
}

TEST_F(MangleAdapterTest, ReadNflogRulesLetsTheHelperErrorThrough)
{
    EXPECT_CALL(*m_helper, chainExists())
        .WillOnce(testing::Throw(IptcException("iptc_init(mangle): Table does not exist", ENOENT)));

    EXPECT_THROW(static_cast<void>(m_adapter.readNflogRules()), IptcException);
}

/* LEARN: addNflogRule() appends one rule: the mark match, then the NFLOG target carrying every
   knob of the NflogParam. The appended rule is decoded with the mappers' readers (tested on their
   own in match_mapper_test.cpp and target_mapper_test.cpp), so every field is compared at once.
*/
struct AddNflogCase
{
    NflogParam nflog;
    const char* name;
};

const std::vector<AddNflogCase> ADD_NFLOG_CASES{
    {NflogParam{.prefix = SAMPLE_NFLOG_PREFIX, .group = SAMPLE_NFLOG_GROUP}, "GroupAndPrefix"},
    {fullNflog(), "EveryKnob"},
};

class MangleAdapterAddNflogTest : public MangleAdapterTest,
                                  public ::testing::WithParamInterface<AddNflogCase>
{
};

TEST_P(MangleAdapterAddNflogTest, AppendsMarkMatchThenNflogTarget)
{
    RuleParam appended;
    EXPECT_CALL(*m_helper, appendRule(testing::_))
        .Times(testing::Exactly(EXPECTED_CALL_COUNT))
        .WillOnce(testing::SaveArg<0>(&appended));

    m_adapter.addNflogRule(MarkParam{SAMPLE_MARK}, GetParam().nflog);

    EXPECT_EQ(appended.matches.size(), 1U);
    EXPECT_EQ(MarkMapper::fromRule(appended), MarkParam{SAMPLE_MARK});
    EXPECT_EQ(NflogMapper::fromRule(appended), GetParam().nflog);
}

INSTANTIATE_TEST_SUITE_P(MangleAdapter, MangleAdapterAddNflogTest,
                         ::testing::ValuesIn(ADD_NFLOG_CASES), caseName<AddNflogCase>);

/* LEARN: what the chain holds (the rules listRules() hands over) and what readNflogRules()
   must report: only NFLOG rules, in rule order, each with the mark it matches.
*/
struct ReadNflogCase
{
    std::vector<RuleParam> (*kernel)();
    std::vector<NflogRuleParam> expected;
    const char* name;
};

const std::vector<ReadNflogCase> READ_NFLOG_CASES{
    {[]() { return std::vector<RuleParam>(); }, {}, "EmptyChain"},
    {[]() {
         return std::vector<RuleParam>{conntrackRule(), nflogRule(SAMPLE_MARK, fullNflog()),
                                       conntrackRule(), nflogRule(OTHER_MARK, minimalNflog())};
     },
     {{.mark = MarkParam{SAMPLE_MARK}, .nflog = fullNflog()},
      {.mark = MarkParam{OTHER_MARK}, .nflog = minimalNflog()}},
     "OnlyNflogRulesWithTheirMarkInRuleOrder"},
    {[]() { return std::vector<RuleParam>{unmarkedNflogRule(fullNflog())}; },
     {{.mark = std::nullopt, .nflog = fullNflog()}},
     "NflogRuleWithoutAMarkMatchReadsWithoutMark"},
};

class MangleAdapterReadNflogTest : public MangleAdapterTest,
                                   public ::testing::WithParamInterface<ReadNflogCase>
{
};

TEST_P(MangleAdapterReadNflogTest, ReportsTheNflogRulesOfTheChain)
{
    EXPECT_CALL(*m_helper, chainExists()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_helper, listRules()).WillOnce(testing::Return(GetParam().kernel()));

    EXPECT_EQ(m_adapter.readNflogRules(), GetParam().expected);
}

INSTANTIATE_TEST_SUITE_P(MangleAdapter, MangleAdapterReadNflogTest,
                         ::testing::ValuesIn(READ_NFLOG_CASES), caseName<ReadNflogCase>);
