#ifndef RULE_MAPPER_H
#define RULE_MAPPER_H

#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/ipt_entry_ptr.h"

#include <cstddef>
#include <optional>
#include <vector>

struct ipt_entry;
struct ExtensionHeader;

/* LEARN: the envelope of a rule: turns a RuleParam into the ipt_entry buffer libiptc takes, and
   a buffer libiptc hands back into a RuleParam. It owns headers, offsets, alignment and the
   allocation; the payload of each extension passes through as bytes. Only IptcHelper uses it.
   Layout and read tolerance: docs/adapter-iptc-rule-mapper.md ("Behaviour to keep").
*/
struct RuleMapper
{
    // Throws std::invalid_argument without a target, std::length_error past the 16-bit offsets.
    [[nodiscard]] static IptEntryPtr toEntry(const RuleParam& rule);

    // Every offset and size in `entry` is untrusted; what cannot be trusted is left out.
    [[nodiscard]] static RuleParam fromEntry(const ipt_entry& entry);

private:
    [[nodiscard]] static std::vector<ExtensionParam> readMatches(const ipt_entry& entry);
    [[nodiscard]] static std::optional<ExtensionParam> readTarget(const ipt_entry& entry);
    [[nodiscard]] static ExtensionParam extensionOf(const ExtensionHeader& header,
                                                    const unsigned char* payload,
                                                    std::size_t payloadBytes);
};

#endif
