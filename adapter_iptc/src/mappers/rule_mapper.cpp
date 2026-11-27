#include "adapter_iptc/mappers/rule_mapper.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

// LEARN: target_offset, next_offset and every extension size are 16-bit fields.
constexpr std::size_t MAX_RULE_BYTES = std::numeric_limits<decltype(ipt_entry::next_offset)>::max();

} // namespace

IptEntryBuffer RuleMapper::toEntry(const RuleParam& rule)
{
    const bool hasTarget = rule.target.has_value();
    if (!hasTarget)
    {
        throw std::invalid_argument("a rule needs a target");
    }

    std::size_t matchesBytes = 0;
    for (const ExtensionParam& match : rule.matches)
    {
        const std::size_t payloadBytes = match.payload.size();
        const std::size_t bytes = MatchHeader::sizeFor(payloadBytes);
        matchesBytes += bytes;
    }

    const ExtensionParam& target = *rule.target;
    const std::size_t targetOffset = sizeof(ipt_entry) + matchesBytes;
    const std::size_t targetPayloadBytes = target.payload.size();
    const std::size_t targetSize = TargetHeader::sizeFor(targetPayloadBytes);
    const std::size_t total = targetOffset + targetSize;

    const bool fitsTheOffsets = total <= MAX_RULE_BYTES;
    if (!fitsTheOffsets)
    {
        throw std::length_error("rule larger than the ipt_entry offsets can hold");
    }

    IptEntryBuffer entry = allocateEntry(total);
    ipt_entry& header = entry[0];
    header.target_offset = targetOffset;
    header.next_offset = total;
    header.ip.proto = rule.protocol;

    unsigned char* position = header.elems;
    for (const ExtensionParam& match : rule.matches)
    {
        const std::size_t payloadBytes = match.payload.size();
        const std::size_t bytes = MatchHeader::sizeFor(payloadBytes);
        MatchHeader::write(position, bytes, match.name, match.revision);

        unsigned char* payload = MatchHeader::payloadOf(position);
        /* LEARN: that's equivalent to
           std::copy(match.payload.begin(), match.payload.end(), payload);
        */
        std::ranges::copy(match.payload, payload);

        position += bytes;
    }

    TargetHeader::write(position, targetSize, target.name, target.revision);

    unsigned char* targetPayloadStart = TargetHeader::payloadOf(position);
    std::ranges::copy(target.payload, targetPayloadStart);
    return entry;
}

RuleParam RuleMapper::fromEntry(const ipt_entry& entry)
{
    // LEARN: ip.proto is a 16-bit field, but an IP protocol number is one byte.
    const auto protocol = static_cast<uint8_t>(entry.ip.proto);
    std::vector<ExtensionParam> matches = readMatches(entry);
    std::optional<ExtensionParam> target = readTarget(entry);

    RuleParam rule{
        .protocol = protocol,
        .matches = std::move(matches),
        .target = std::move(target),
    };
    return rule;
}

/* LEARN: the matches of a rule sit one after another between the rule header and the target:

   sizeof(ipt_entry)                                                      target_offset
   | xt_entry_match | payload | padding | xt_entry_match | payload | padding | target ...
   |<------------- match_size -------->|<------------- match_size -------->|

   No index says where each match starts: every match records its own size (match_size), so the
   walk jumps match_size bytes to reach the next one. Those sizes come from the buffer itself and
   are checked before use: a match_size smaller than its header (0 would loop forever) or one
   running into the target ends the walk, keeping the matches already read.
*/
std::vector<ExtensionParam> RuleMapper::readMatches(const ipt_entry& entry)
{
    const std::size_t matchesStart = sizeof(ipt_entry);
    const std::size_t matchesEnd = entry.target_offset;
    const std::size_t entryEnd = entry.next_offset;

    std::vector<ExtensionParam> matches;

    // LEARN: the matches area must lie inside the rule: after its header, before its end.
    if (matchesEnd < matchesStart || matchesEnd > entryEnd)
    {
        return matches;
    }

    const unsigned char* entryStart = bytesOf(entry);
    std::size_t matchOffset = matchesStart;
    while (matchOffset + MatchHeader::BYTES <= matchesEnd)
    {
        const unsigned char* matchStart = entryStart + matchOffset;
        const MatchHeader header = MatchHeader::read(matchStart);

        // LEARN: match_size counts the match header plus its payload (and padding).
        const std::size_t matchEnd = matchOffset + header.size;
        const bool coversItsHeader = header.size >= MatchHeader::BYTES;
        const bool endsBeforeTheTarget = matchEnd <= matchesEnd;
        if (!coversItsHeader || !endsBeforeTheTarget)
        {
            break;
        }
        const std::size_t payloadBytes = header.size - MatchHeader::BYTES;
        const unsigned char* payload = MatchHeader::payloadOf(matchStart);
        ExtensionParam match = extensionOf(header, payload, payloadBytes);
        matches.push_back(std::move(match));
        matchOffset = matchEnd;
    }
    return matches;
}

/* LEARN: one rule (ipt_entry) is a single buffer, laid out as toEntry writes it and as the kernel
   hands it back:

   0            sizeof(ipt_entry)     target_offset                                   next_offset
   | ipt_entry  | matches (0..n)      | xt_entry_target | payload        | padding    |
                                      |<------------------ target_size ------------->|

   Every offset and size used below is read from the buffer itself, so none is trusted: each one
   is checked against the others before it is used to read memory. The target is read on its own,
   so a malformed matches area never hides it.
*/
std::optional<ExtensionParam> RuleMapper::readTarget(const ipt_entry& entry)
{
    const std::size_t targetOffset = entry.target_offset;
    const std::size_t entryEnd = entry.next_offset;

    // LEARN: the target starts after the rule header, and its own header must fit in the rule.
    const std::size_t targetHeaderEnd = targetOffset + TargetHeader::BYTES;
    if (targetOffset < sizeof(ipt_entry) || targetHeaderEnd > entryEnd)
    {
        return std::nullopt;
    }

    const unsigned char* targetStart = bytesOf(entry) + targetOffset;
    const TargetHeader header = TargetHeader::read(targetStart);

    // LEARN: target_size counts the target header plus its payload (and padding).
    const std::size_t targetEnd = targetOffset + header.size;
    const bool coversItsHeader = header.size >= TargetHeader::BYTES;
    const bool endsInsideTheRule = targetEnd <= entryEnd;
    if (!coversItsHeader || !endsInsideTheRule)
    {
        return std::nullopt;
    }

    const std::size_t payloadBytes = header.size - TargetHeader::BYTES;
    const unsigned char* payload = TargetHeader::payloadOf(targetStart);
    ExtensionParam target = extensionOf(header, payload, payloadBytes);
    return target;
}

template <ExtensionHeaderType Header>
ExtensionParam RuleMapper::extensionOf(const ExtensionHeader<Header>& header,
                                       const unsigned char* payload, std::size_t payloadBytes)
{
    const char* nameField = header.name.data();
    const std::size_t nameFieldBytes = header.name.size();

    // LEARN: the name field is fixed-size and may lack a terminator; strnlen never reads past it.
    const std::size_t nameBytes = strnlen(nameField, nameFieldBytes);
    std::string name(nameField, nameBytes);
    std::vector<unsigned char> payloadCopy(payload, payload + payloadBytes);

    ExtensionParam extension{
        .name = std::move(name),
        .revision = header.revision,
        .payload = std::move(payloadCopy),
    };
    return extension;
}

IptEntryBuffer RuleMapper::allocateEntry(std::size_t bytes)
{
    // LEARN: rounded up to whole ipt_entry elements; the vector value-initializes them, so it is
    // zeroed.
    const std::size_t count = (bytes + sizeof(ipt_entry) - 1) / sizeof(ipt_entry);
    return IptEntryBuffer(count);
}

const unsigned char* RuleMapper::bytesOf(const ipt_entry& entry)
{
    // LEARN: an object viewed as bytes. NOLINTNEXTLINE(bugprone-casting-through-void)
    return static_cast<const unsigned char*>(static_cast<const void*>(&entry));
}
