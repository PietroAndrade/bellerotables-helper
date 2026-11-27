#ifndef VERDICT_DTO_H
#define VERDICT_DTO_H

#include <cstdint>

/* LEARN: the verdict of a standard target, "-j ACCEPT" / "-j DROP" / "-j RETURN". */
enum class Verdict : uint8_t
{
    ACCEPT,
    DROP,
    RETURN
};

#endif
