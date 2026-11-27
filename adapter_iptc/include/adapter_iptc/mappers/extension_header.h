#ifndef EXTENSION_HEADER_H
#define EXTENSION_HEADER_H

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <linux/netfilter/x_tables.h>
#include <string>

/* LEARN: what the header of a match (xt_entry_match) or of a target (xt_entry_target) says about
   the extension that follows it: the size, the revision and the name the kernel stored. Both
   headers have the same shape and differ only in the name of the size field, so one template
   serves them and Header picks which of the two is read or written:
   ExtensionHeader<xt_entry_match> and ExtensionHeader<xt_entry_target>.

   It is the only place that knows where each field sits in those headers. The fields are reached
   by offset, never through the u.user / u.kernel union, so nothing here touches the union. The
   definitions are in extension_header.cpp, which instantiates the two headers.

   The name field is fixed-size and may lack a terminator, which is why a name read from the
   kernel is kept whole in a std::array and bounded with strnlen where it becomes a string.
*/
// LEARN: the two header types of the kernel that ExtensionHeader is defined for. Any other type
// fails here, at the line that names it, and not as an undefined reference at link time: the
// members are defined in extension_header.cpp and instantiated only for these two.
template <typename T>
concept ExtensionHeaderType = std::same_as<T, xt_entry_match> || std::same_as<T, xt_entry_target>;

template <ExtensionHeaderType Header>
struct ExtensionHeader
{
    // The bytes of the header alone, before the payload.
    static constexpr std::size_t BYTES = sizeof(Header);

    std::size_t size;
    uint8_t revision;
    std::array<char, XT_EXTENSION_MAXNAMELEN> name;

    // The caller checks that BYTES bytes are readable at `position`.
    [[nodiscard]] static ExtensionHeader read(const unsigned char* position);

    // `position` must have room for BYTES bytes. A name longer than the field is cut, keeping a
    // terminator.
    static void write(unsigned char* position, std::size_t size, const std::string& name,
                      uint8_t revision);

    // Size of the header plus `payloadBytes`, padded to the alignment the kernel requires.
    [[nodiscard]] static std::size_t sizeFor(std::size_t payloadBytes);

    // Where the payload of the extension whose header starts at `position` begins.
    [[nodiscard]] static const unsigned char* payloadOf(const unsigned char* position);
    [[nodiscard]] static unsigned char* payloadOf(unsigned char* position);
};

using MatchHeader = ExtensionHeader<xt_entry_match>;
using TargetHeader = ExtensionHeader<xt_entry_target>;

#endif
