#ifndef RULE_MAPPER_H
#define RULE_MAPPER_H

#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/ipt_entry_buffer.h"
#include "adapter_iptc/mappers/extension_header.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

struct ipt_entry;

/* LEARN: the envelope of a rule: turns a RuleParam into the ipt_entry buffer libiptc takes, and
   a buffer libiptc hands back into a RuleParam. It owns headers, offsets, alignment and the
   allocation; the payload of each extension passes through as bytes. Only IptcHelper uses it.
   Layout and read tolerance: docs/adapter-iptc-rule-mapper.md ("Behaviour to keep").
   It is the one place that knows the byte layout of an ipt_entry, and everything that would trip
   clang-tidy lives in rule_mapper.cpp and nowhere else:
   - the rule buffer is a vector of ipt_entry (IptEntryBuffer), sized to cover the whole rule;
   - the headers of the matches and of the target are read and written by ExtensionHeader, which
     is the one that knows where each field sits, so the u.user / u.kernel union is not touched.
*/
struct RuleMapper
{
    // Throws std::invalid_argument without a target, std::length_error past the 16-bit offsets.
    [[nodiscard]] static IptEntryBuffer toEntry(const RuleParam& rule);

    // Every offset and size in `entry` is untrusted; what cannot be trusted is left out.
    [[nodiscard]] static RuleParam fromEntry(const ipt_entry& entry);

private:
    [[nodiscard]] static std::vector<ExtensionParam> readMatches(const ipt_entry& entry);
    [[nodiscard]] static std::optional<ExtensionParam> readTarget(const ipt_entry& entry);

    // LEARN: bounds the name with strnlen: the name field of a header may lack a terminator.
    template <ExtensionHeaderType Header>
    [[nodiscard]] static ExtensionParam extensionOf(const ExtensionHeader<Header>& header,
                                                    const unsigned char* payload,
                                                    std::size_t payloadBytes);

    // Allocates a zeroed rule buffer of `bytes`, owned by the returned pointer.
    [[nodiscard]] static IptEntryBuffer allocateEntry(std::size_t bytes);

    // The first byte of a rule, to walk it by offsets.
    [[nodiscard]] static const unsigned char* bytesOf(const ipt_entry& entry);
};

#endif
