#ifndef VERDICT_MAPPER_H
#define VERDICT_MAPPER_H

#include "adapter_iptc/dtos/rule.h"
#include "adapter_iptc/dtos/verdict.h"

/* LEARN: "-j ACCEPT" / "-j DROP" / "-j RETURN" as data: a target with an empty name and a
   StandardVerdict payload.
*/
struct VerdictMapper
{
    [[nodiscard]] static ExtensionParam toExtension(Verdict verdict);

private:
    [[nodiscard]] static int kernelVerdict(Verdict verdict);
};

#endif
