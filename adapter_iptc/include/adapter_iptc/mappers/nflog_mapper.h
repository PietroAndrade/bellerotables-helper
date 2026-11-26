#ifndef NFLOG_MAPPER_H
#define NFLOG_MAPPER_H

#include "adapter_iptc/dtos/nflog.h"
#include "adapter_iptc/dtos/rule.h"

#include <optional>

/* LEARN: "-j NFLOG" as data: an NflogParam becomes xt_nflog_info, and the target of a rule is read
   back into one. Knob semantics: dtos/nflog.h.
*/
struct NflogMapper
{
    [[nodiscard]] static ExtensionParam toExtension(const NflogParam& nflog);

    // LEARN: empty when the rule has no target, or its target is not a whole NFLOG one.
    [[nodiscard]] static std::optional<NflogParam> fromRule(const RuleParam& rule);
};

#endif
