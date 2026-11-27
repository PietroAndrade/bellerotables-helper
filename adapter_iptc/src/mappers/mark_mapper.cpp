#include "adapter_iptc/mappers/mark_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstdint>
#include <linux/netfilter/xt_mark.h>
#include <optional>

template <>
struct PayloadIdentity<xt_mark_mtinfo1>
{
    static constexpr const char* NAME = "mark";
    static constexpr uint8_t REVISION = 1;
};

namespace {

constexpr uint32_t EVERY_MARK_BIT = 0xffffffff;

} // namespace

ExtensionParam MarkMapper::toExtension(MarkParam mark)
{
    const MaskedMark maskedMark{.mark = mark.mark, .mask = EVERY_MARK_BIT};
    ExtensionParam extension = toExtension(maskedMark);
    return extension;
}

ExtensionParam MarkMapper::toExtension(MaskedMark mark)
{
    xt_mark_mtinfo1 info{};
    info.mark = mark.mark;
    info.mask = mark.mask;
    ExtensionParam extension = PayloadMapper::toExtension(info);
    return extension;
}

std::optional<MarkParam> MarkMapper::fromRule(const RuleParam& rule)
{
    for (const ExtensionParam& match : rule.matches)
    {
        const std::optional<xt_mark_mtinfo1> info =
            PayloadMapper::fromExtension<xt_mark_mtinfo1>(match);
        const bool isMark = info.has_value();
        if (!isMark)
        {
            continue;
        }

        const bool coversEveryBit = info->mask == EVERY_MARK_BIT;
        const bool notInverted = info->invert == 0;
        const bool isPlain = coversEveryBit && notInverted;
        if (!isPlain)
        {
            return std::nullopt;
        }

        MarkParam mark{.mark = info->mark};
        return mark;
    }
    return std::nullopt;
}
