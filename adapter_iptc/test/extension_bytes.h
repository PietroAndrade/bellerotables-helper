#ifndef ADAPTER_IPTC_TEST_EXTENSION_BYTES_H
#define ADAPTER_IPTC_TEST_EXTENSION_BYTES_H

#include "adapter_iptc/dtos/rule.h"

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

/* LEARN: the mappers never write some payloads (an inverted mark, flags 0, a full 64-byte prefix),
   so a test builds that ExtensionParam by hand, and reads a payload back as the kernel struct it
   holds. memcpy both ways: the bytes of a vector are never read through a cast.
*/
struct ExtensionBytes
{
    template <typename Payload>
    [[nodiscard]] static ExtensionParam make(const char* name, uint8_t revision,
                                             const Payload& payload)
    {
        static_assert(std::is_trivially_copyable_v<Payload>);
        ExtensionParam extension{
            .name = name,
            .revision = revision,
            .payload = std::vector<unsigned char>(sizeof(Payload)),
        };
        std::memcpy(extension.payload.data(), &payload, sizeof(Payload));
        return extension;
    }

    template <typename Payload>
    [[nodiscard]] static Payload read(const ExtensionParam& extension)
    {
        static_assert(std::is_trivially_copyable_v<Payload>);
        Payload payload{};
        std::memcpy(&payload, extension.payload.data(), sizeof(Payload));
        return payload;
    }
};

#endif // ADAPTER_IPTC_TEST_EXTENSION_BYTES_H
