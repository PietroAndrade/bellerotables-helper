#ifndef CONNTRACK_DTO_H
#define CONNTRACK_DTO_H

#include <cstdint>

/* LEARN: the connection states "-m conntrack --ctstate" is used with here. */
enum class ConntrackState : uint8_t
{
    NEW,
    ESTABLISHED_RELATED,
    INVALID
};

struct ConntrackParam
{
    ConntrackState state;
};

#endif
