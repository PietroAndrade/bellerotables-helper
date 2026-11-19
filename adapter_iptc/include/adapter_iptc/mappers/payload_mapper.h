#ifndef PAYLOAD_MAPPER_H
#define PAYLOAD_MAPPER_H

#include "adapter_iptc/dtos/rule.h"

#include <concepts>
#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>

/* LEARN: the name and revision the kernel looks this payload's extension up by. Left undefined, so
   a struct without a specialization does not compile; each specialization lives in the .cpp of the
   mapper that owns the struct. Details: docs/adapter-iptc-payload-mapper.md.
*/
template <typename Payload>
struct PayloadIdentity;

/* LEARN: a struct PayloadMapper can map: copyable as bytes (memcpy is valid only then) and with a
   PayloadIdentity. A specialization must be visible before the concept is first checked for its
   type. Details: docs/adapter-iptc-payload-mapper.md.
*/
template <typename Payload>
concept KernelPayload = std::is_trivially_copyable_v<Payload> && requires {
    { PayloadIdentity<Payload>::NAME } -> std::convertible_to<const char*>;
    { PayloadIdentity<Payload>::REVISION } -> std::convertible_to<uint8_t>;
};

struct PayloadMapper
{
    template <KernelPayload Payload>
    [[nodiscard]] static ExtensionParam toExtension(const Payload& payload)
    {
        ExtensionParam extension{
            .name = PayloadIdentity<Payload>::NAME,
            .revision = PayloadIdentity<Payload>::REVISION,
            .payload = std::vector<unsigned char>(sizeof(Payload)),
        };
        std::memcpy(extension.payload.data(), &payload, sizeof(Payload));
        return extension;
    }

    // LEARN: a payload read back keeps its alignment padding, so it may be longer than the struct.
    template <KernelPayload Payload>
    [[nodiscard]] static std::optional<Payload> fromExtension(const ExtensionParam& extension)
    {
        const bool sameName = extension.name == PayloadIdentity<Payload>::NAME;
        const bool sameRevision = extension.revision == PayloadIdentity<Payload>::REVISION;
        const bool longEnough = extension.payload.size() >= sizeof(Payload);
        if (!sameName || !sameRevision || !longEnough)
            return std::nullopt;

        // LEARN: copied, never read in place through reinterpret_cast (undefined behaviour).
        Payload value{};
        std::memcpy(&value, extension.payload.data(), sizeof(Payload));
        return value;
    }
};

#endif
