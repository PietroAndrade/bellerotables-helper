#ifndef RULE_DTO_H
#define RULE_DTO_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/* LEARN: one match or target of a rule, as data: the name and revision the kernel looks the
   extension up by, and its payload (the xt_*_info struct as bytes, without the header the kernel
   puts in front of it). Read back from the kernel, the payload may be longer than the struct: it
   keeps the alignment padding.
*/
struct ExtensionParam
{
    std::string name;
    uint8_t revision = 0;
    std::vector<unsigned char> payload;

    bool operator==(const ExtensionParam&) const = default;
};

/* LEARN: one rule as data, what crosses into the layer that talks to libiptc: the protocol
   (ipt_entry.ip.proto, "-p"), the matches in rule order and the target. The target is empty only
   in a rule read back whose target could not be trusted; a rule written always has one.
*/
struct RuleParam
{
    uint8_t protocol = 0;
    std::vector<ExtensionParam> matches;
    std::optional<ExtensionParam> target;

    bool operator==(const RuleParam&) const = default;
};

#endif
