#include "adapter_iptc/mappers/payload_mapper.h"

#include "adapter_iptc/dtos/rule.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace {

constexpr uint32_t FIRST = 0x11223344;
constexpr uint16_t SECOND = 0x5566;
constexpr uint8_t TEST_REVISION = 2;

struct TestPayload
{
    uint32_t first;
    uint16_t second;
};

struct NoIdentity
{
    int value;
};

} // namespace

template <>
struct PayloadIdentity<TestPayload>
{
    static constexpr const char* NAME = "test";
    static constexpr uint8_t REVISION = TEST_REVISION;
};

namespace {

ExtensionParam testExtension()
{
    return PayloadMapper::toExtension(TestPayload{.first = FIRST, .second = SECOND});
}

} // namespace

TEST(PayloadMapperTest, ToExtensionTakesNameAndRevisionFromTheIdentity)
{
    const ExtensionParam extension = testExtension();

    EXPECT_EQ(extension.name, "test");
    EXPECT_EQ(extension.revision, TEST_REVISION);
    EXPECT_EQ(extension.payload.size(), sizeof(TestPayload));
}

TEST(PayloadMapperTest, RoundTripsThePayload)
{
    const std::optional<TestPayload> payload =
        PayloadMapper::fromExtension<TestPayload>(testExtension());

    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(payload->first, FIRST);
    EXPECT_EQ(payload->second, SECOND);
}

TEST(PayloadMapperTest, OtherNameIsNotDecoded)
{
    ExtensionParam extension = testExtension();
    extension.name = "other";

    EXPECT_FALSE(PayloadMapper::fromExtension<TestPayload>(extension).has_value());
}

TEST(PayloadMapperTest, OtherRevisionIsNotDecoded)
{
    ExtensionParam extension = testExtension();
    extension.revision = TEST_REVISION + 1;

    EXPECT_FALSE(PayloadMapper::fromExtension<TestPayload>(extension).has_value());
}

TEST(PayloadMapperTest, ShortPayloadIsNotDecoded)
{
    ExtensionParam extension = testExtension();
    extension.payload.resize(sizeof(TestPayload) - 1);

    EXPECT_FALSE(PayloadMapper::fromExtension<TestPayload>(extension).has_value());
}

// LEARN: a payload read back from the kernel keeps its alignment padding after the struct.
TEST(PayloadMapperTest, LongerPayloadStillDecodes)
{
    ExtensionParam extension = testExtension();
    extension.payload.resize(sizeof(TestPayload) + 4, 0);

    const std::optional<TestPayload> payload = PayloadMapper::fromExtension<TestPayload>(extension);

    ASSERT_TRUE(payload.has_value());
    EXPECT_EQ(payload->first, FIRST);
    EXPECT_EQ(payload->second, SECOND);
}

/* LEARN: checked after the TestPayload specialization on purpose: the concept must not be checked
   for a type before its PayloadIdentity is visible.
*/
TEST(PayloadMapperTest, ConceptAcceptsOnlyMappableTypes)
{
    static_assert(KernelPayload<TestPayload>);
    static_assert(!KernelPayload<NoIdentity>);
    static_assert(!KernelPayload<std::string>);
}
