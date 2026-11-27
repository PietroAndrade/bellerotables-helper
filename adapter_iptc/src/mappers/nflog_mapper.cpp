#include "adapter_iptc/mappers/nflog_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/netfilter/xt_NFLOG.h>
#include <optional>
#include <string>
#include <utility>

template <>
struct PayloadIdentity<xt_nflog_info>
{
    static constexpr const char* NAME = "NFLOG";
    static constexpr uint8_t REVISION = 0;
};

namespace {

constexpr unsigned char UTF8_CONTINUATION_MASK = 0xC0;
constexpr unsigned char UTF8_CONTINUATION_BITS = 0x80;

bool isUtf8Continuation(char byte)
{
    return (static_cast<unsigned char>(byte) & UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_BITS;
}

/* LEARN: the contract bounds the prefix in characters, the kernel in bytes (63 + NUL). A plain
   byte cut can split a multi-byte character and leave invalid UTF-8 in the kernel, so the cut
   moves back to the start of the character it would split.
*/
std::size_t prefixBytesThatFit(const std::string& prefix, std::size_t maxBytes)
{
    if (prefix.size() <= maxBytes)
    {
        return prefix.size();
    }
    std::size_t cut = maxBytes;
    while (cut > 0 && isUtf8Continuation(prefix[cut]))
    {
        --cut;
    }
    return cut;
}

} // namespace

ExtensionParam NflogMapper::toExtension(const NflogParam& nflog)
{
    xt_nflog_info info{};
    info.group = nflog.group;

    // LEARN: one byte of the field is kept for the terminator.
    const std::size_t prefixCapacity = sizeof(info.prefix) - 1;
    const std::size_t prefixBytes = prefixBytesThatFit(nflog.prefix, prefixCapacity);
    std::memcpy(info.prefix, nflog.prefix.data(), prefixBytes);

    if (nflog.range.has_value())
    {
        info.len = *nflog.range;
        info.flags |= XT_NFLOG_F_COPY_LEN;
    }
    if (nflog.threshold.has_value())
    {
        info.threshold = *nflog.threshold;
    }
    ExtensionParam extension = PayloadMapper::toExtension(info);
    return extension;
}

std::optional<NflogParam> NflogMapper::fromRule(const RuleParam& rule)
{
    const bool hasTarget = rule.target.has_value();
    if (!hasTarget)
    {
        return std::nullopt;
    }

    const std::optional<xt_nflog_info> info =
        PayloadMapper::fromExtension<xt_nflog_info>(*rule.target);
    const bool isNflog = info.has_value();
    if (!isNflog)
    {
        return std::nullopt;
    }

    // LEARN: bounded by the field: a prefix filling all 64 bytes has no terminator.
    const std::size_t prefixBytes = strnlen(info->prefix, sizeof(info->prefix));
    std::string prefix(info->prefix, prefixBytes);
    NflogParam nflog{.prefix = std::move(prefix), .group = info->group};

    const bool copiesLength = (info->flags & XT_NFLOG_F_COPY_LEN) != 0;
    if (copiesLength)
    {
        nflog.range = info->len;
    }
    const bool hasThreshold = info->threshold != XT_NFLOG_DEFAULT_THRESHOLD;
    if (hasThreshold)
    {
        nflog.threshold = info->threshold;
    }
    return nflog;
}
