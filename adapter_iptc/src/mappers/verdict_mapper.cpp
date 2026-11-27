#include "adapter_iptc/mappers/verdict_mapper.h"

#include "adapter_iptc/mappers/payload_mapper.h"

#include <cstdint>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

namespace {

/* LEARN: the payload of a standard target: the verdict the kernel reads right after the target
   header (xt_standard_target is that header plus this int). A type of its own, so the identity
   "" / revision 0 is not attached to every int.
*/
struct StandardVerdict
{
    int verdict;
};

} // namespace

template <>
struct PayloadIdentity<StandardVerdict>
{
    static constexpr const char* NAME = "";
    static constexpr uint8_t REVISION = 0;
};

ExtensionParam VerdictMapper::toExtension(Verdict verdict)
{
    const int kernel = kernelVerdict(verdict);
    const StandardVerdict payload{.verdict = kernel};
    ExtensionParam extension = PayloadMapper::toExtension(payload);
    return extension;
}

/* LEARN: the kernel encodes ACCEPT/DROP as -(verdict) - 1 so they never collide with a jump
   offset (>= 0); RETURN has its own negative constant.
*/
int VerdictMapper::kernelVerdict(Verdict verdict)
{
    switch (verdict)
    {
        case Verdict::ACCEPT:
            return -NF_ACCEPT - 1;
        case Verdict::DROP:
            return -NF_DROP - 1;
        case Verdict::RETURN:
            return XT_RETURN;
    }
    return -NF_DROP - 1;
}
