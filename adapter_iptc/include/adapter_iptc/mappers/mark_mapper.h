#ifndef MARK_MAPPER_H
#define MARK_MAPPER_H

#include "adapter_iptc/dtos/mark.h"
#include "adapter_iptc/dtos/rule.h"

#include <optional>

/* LEARN: the "-m mark" match as data. Writes a mark (plain or with a mask) as the extension the
   kernel looks up by "mark" revision 1, and reads the plain mark back out of a rule.
*/
struct MarkMapper
{
    // LEARN: the whole mark compared: the mask covers every bit.
    [[nodiscard]] static ExtensionParam toExtension(MarkParam mark);
    [[nodiscard]] static ExtensionParam toExtension(MaskedMark mark);

    /* LEARN: the first match that decodes as a mark, empty when it has a partial mask or an
       inversion (MarkParam cannot express either) or when the rule has no mark match.
    */
    [[nodiscard]] static std::optional<MarkParam> fromRule(const RuleParam& rule);
};

#endif
