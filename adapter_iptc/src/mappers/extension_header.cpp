#include "adapter_iptc/mappers/extension_header.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

// LEARN: where each field sits in the header, from offsetof: the layout is the compiler's, and
// reading by offset avoids the u.user / u.kernel union. They differ per type only in the name of
// the size field.
template <typename Header>
struct HeaderLayout;

template <>
struct HeaderLayout<xt_entry_match>
{
    // LEARN: offsetof(Type, member) is the number of bytes from the start of Type to member, worked
    // out by the compiler at compile time. Adding it to the address of a header gives the address
    // of the field, without ever writing header.u.user.field.
    static constexpr std::size_t SIZE_AT = offsetof(xt_entry_match, u.user.match_size);
    static constexpr std::size_t NAME_AT = offsetof(xt_entry_match, u.user.name);
    static constexpr std::size_t REVISION_AT = offsetof(xt_entry_match, u.user.revision);
    static constexpr std::size_t PAYLOAD_AT = offsetof(xt_entry_match, data);
};

template <>
struct HeaderLayout<xt_entry_target>
{
    static constexpr std::size_t SIZE_AT = offsetof(xt_entry_target, u.user.target_size);
    static constexpr std::size_t NAME_AT = offsetof(xt_entry_target, u.user.name);
    static constexpr std::size_t REVISION_AT = offsetof(xt_entry_target, u.user.revision);
    static constexpr std::size_t PAYLOAD_AT = offsetof(xt_entry_target, data);
};

// LEARN: the kernel stores the size in a 16-bit field and the revision in an 8-bit one.
using SizeField = uint16_t;
using RevisionField = uint8_t;

template <typename Header>
constexpr bool fieldsFitTheHeader()
{
    using Layout = HeaderLayout<Header>;
    const bool sizeFits = Layout::SIZE_AT + sizeof(SizeField) <= sizeof(Header);
    const bool nameFits = Layout::NAME_AT + XT_EXTENSION_MAXNAMELEN <= sizeof(Header);
    const bool revisionFits = Layout::REVISION_AT + sizeof(RevisionField) <= sizeof(Header);
    return sizeFits && nameFits && revisionFits;
}

static_assert(fieldsFitTheHeader<xt_entry_match>());
static_assert(fieldsFitTheHeader<xt_entry_target>());

} // namespace

template <ExtensionHeaderType Header>
ExtensionHeader<Header> ExtensionHeader<Header>::read(const unsigned char* position)
{
    using Layout = HeaderLayout<Header>;

    SizeField size = 0;
    std::memcpy(&size, position + Layout::SIZE_AT, sizeof(size));

    ExtensionHeader result{.size = size, .revision = 0, .name = {}};
    std::memcpy(&result.revision, position + Layout::REVISION_AT, sizeof(result.revision));
    std::memcpy(result.name.data(), position + Layout::NAME_AT, result.name.size());
    return result;
}

template <ExtensionHeaderType Header>
void ExtensionHeader<Header>::write(unsigned char* position, std::size_t size,
                                    const std::string& name, uint8_t revision)
{
    using Layout = HeaderLayout<Header>;

    const auto sizeField = static_cast<SizeField>(size);
    std::memcpy(position + Layout::SIZE_AT, &sizeField, sizeof(sizeField));
    std::memcpy(position + Layout::REVISION_AT, &revision, sizeof(revision));

    // LEARN: the field is cleared first, so what the buffer held before never leaks into the name,
    // and the last byte stays zero as the terminator.
    unsigned char* nameField = position + Layout::NAME_AT;
    std::memset(nameField, 0, XT_EXTENSION_MAXNAMELEN);
    const std::size_t nameBytes = std::min(name.size(), std::size_t{XT_EXTENSION_MAXNAMELEN - 1});
    std::copy_n(name.begin(), nameBytes, nameField);
}

template <ExtensionHeaderType Header>
std::size_t ExtensionHeader<Header>::sizeFor(std::size_t payloadBytes)
{
    const std::size_t bytes = XT_ALIGN(sizeof(Header) + payloadBytes);
    return bytes;
}

template <ExtensionHeaderType Header>
const unsigned char* ExtensionHeader<Header>::payloadOf(const unsigned char* position)
{
    return position + HeaderLayout<Header>::PAYLOAD_AT;
}

template <ExtensionHeaderType Header>
unsigned char* ExtensionHeader<Header>::payloadOf(unsigned char* position)
{
    return position + HeaderLayout<Header>::PAYLOAD_AT;
}

template struct ExtensionHeader<xt_entry_match>;
template struct ExtensionHeader<xt_entry_target>;
