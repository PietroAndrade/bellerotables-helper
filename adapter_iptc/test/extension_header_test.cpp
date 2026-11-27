#include "adapter_iptc/mappers/extension_header.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <linux/netfilter/x_tables.h>
#include <string>

namespace {

constexpr std::size_t BUFFER_BYTES = 64;
constexpr uint8_t STALE_BYTE = 0xFF;

// LEARN: the header is read and written the same way for a match and for a target, so the
// same cases run for both.
template <typename Header>
class ExtensionHeaderTest : public ::testing::Test
{
protected:
    alignas(8) std::array<unsigned char, BUFFER_BYTES> m_buffer{};
};

using HeaderTypes = ::testing::Types<xt_entry_match, xt_entry_target>;
TYPED_TEST_SUITE(ExtensionHeaderTest, HeaderTypes);

TYPED_TEST(ExtensionHeaderTest, WrittenHeaderReadsBackTheSame)
{
    using Header = ExtensionHeader<TypeParam>;
    const std::string name = "mark";

    Header::write(this->m_buffer.data(), 40, name, 3);
    const Header header = Header::read(this->m_buffer.data());

    EXPECT_EQ(header.size, 40U);
    EXPECT_EQ(header.revision, 3U);
    EXPECT_STREQ(header.name.data(), "mark");
}

TYPED_TEST(ExtensionHeaderTest, WriteClearsWhatWasInTheNameField)
{
    using Header = ExtensionHeader<TypeParam>;
    this->m_buffer.fill(STALE_BYTE);

    Header::write(this->m_buffer.data(), 32, "ab", 0);
    const Header header = Header::read(this->m_buffer.data());

    const std::array<char, XT_EXTENSION_MAXNAMELEN> expected = {'a', 'b'};
    EXPECT_EQ(header.name, expected);
}

TYPED_TEST(ExtensionHeaderTest, WriteKeepsTheTerminatorOfALongName)
{
    using Header = ExtensionHeader<TypeParam>;
    const std::string tooLong(XT_EXTENSION_MAXNAMELEN + 10, 'n');

    Header::write(this->m_buffer.data(), 32, tooLong, 0);
    const Header header = Header::read(this->m_buffer.data());

    EXPECT_EQ(header.name[XT_EXTENSION_MAXNAMELEN - 1], '\0');
    EXPECT_EQ(header.name[XT_EXTENSION_MAXNAMELEN - 2], 'n');
}

TYPED_TEST(ExtensionHeaderTest, ReadKeepsANameWithoutTerminator)
{
    using Header = ExtensionHeader<TypeParam>;
    this->m_buffer.fill('m');

    const Header header = Header::read(this->m_buffer.data());

    for (const char letter : header.name)
    {
        EXPECT_EQ(letter, 'm');
    }
}

TYPED_TEST(ExtensionHeaderTest, SizeForCoversTheHeaderAndAlignsThePayload)
{
    using Header = ExtensionHeader<TypeParam>;

    EXPECT_EQ(Header::sizeFor(0), sizeof(TypeParam));
    EXPECT_EQ(Header::sizeFor(1), XT_ALIGN(sizeof(TypeParam) + 1));
    EXPECT_EQ(Header::sizeFor(1) % XT_ALIGN(1), 0U);
}

TYPED_TEST(ExtensionHeaderTest, PayloadStartsRightAfterTheHeader)
{
    using Header = ExtensionHeader<TypeParam>;
    unsigned char* start = this->m_buffer.data();
    const unsigned char* constStart = start;

    EXPECT_EQ(Header::payloadOf(start), start + offsetof(TypeParam, data));
    EXPECT_EQ(Header::payloadOf(constStart), constStart + offsetof(TypeParam, data));
}

} // namespace
