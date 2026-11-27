# adapter_iptc: ExtensionHeader

**Status:** accepted and implemented 2026-11-26, a refinement of `RuleMapper` after Task 6 of the
[plan](superpowers/plans/2026-11-15-adapter-iptc-rule-mapper.md), decided in review of
[adapter-iptc-rule-mapper.md](adapter-iptc-rule-mapper.md).
**Scope:** `adapter_iptc/include/adapter_iptc/mappers/extension_header.h` and
`src/mappers/extension_header.cpp`: how the header of a match (`xt_entry_match`) or of a target
(`xt_entry_target`) is read, written and measured.

## Problem

`RuleMapper` had four functions for the header alone (`readMatchHeader`, `readTargetHeader`,
`writeMatchHeader`, `writeTargetHeader`), four for the payload start (`matchPayload` and
`targetPayload`, const and non-const), and a `matchBytes` helper. Each pair repeated the same body for
a different kernel struct. All of them reached the fields through the `u.user` union, so a
`NOLINTBEGIN/END(cppcoreguidelines-pro-type-union-access)` wrapped the block.

## Decision

One template, `ExtensionHeader<Header>`, with `Header` being `xt_entry_match` or `xt_entry_target`
(aliases `MatchHeader` and `TargetHeader`):

```cpp
template <typename T>
concept ExtensionHeaderType = std::same_as<T, xt_entry_match> || std::same_as<T, xt_entry_target>;

template <ExtensionHeaderType Header>
struct ExtensionHeader
{
    static constexpr std::size_t BYTES = sizeof(Header);
    std::size_t size;
    uint8_t revision;
    std::array<char, XT_EXTENSION_MAXNAMELEN> name;

    static ExtensionHeader read(const unsigned char* position);
    static void write(unsigned char* position, std::size_t size, const std::string& name,
                      uint8_t revision);
    static std::size_t sizeFor(std::size_t payloadBytes);   // XT_ALIGN(sizeof(Header) + payload)
    static const unsigned char* payloadOf(const unsigned char* position);
    static unsigned char* payloadOf(unsigned char* position);
};
```

- **A concept restricts `Header`.** `ExtensionHeaderType` accepts only `xt_entry_match` and
  `xt_entry_target`. Without it a wrong type would still compile where it is named, because the
  members are only declared in the header, and fail later as `undefined reference` at link time,
  far from the cause (the "incomplete type" error of `HeaderLayout<Foo>` only shows up inside the
  `.cpp`). With it the error is "constraints not satisfied" on the line that names the type. It is
  the same idiom as `KernelPayload` in [adapter-iptc-payload-mapper.md](adapter-iptc-payload-mapper.md).
  `RuleMapper::extensionOf` is constrained with it too. The cost: the two types are listed twice, in
  the concept and in the `HeaderLayout` specializations, so a third type means touching both; the
  concept fails clearly if one is forgotten.
- **The fields are reached by offset, not through the union.** A `HeaderLayout<Header>` trait in the
  `.cpp` holds `SIZE_AT`, `NAME_AT`, `REVISION_AT` and `PAYLOAD_AT`, each an `offsetof`, and the
  fields are copied with `memcpy`. The check `pro-type-union-access` only matches member-access
  expressions on a union; `offsetof` is another node, so no `NOLINT` is needed. The trait is needed
  because the size field is named `match_size` in one struct and `target_size` in the other.
- **`static_assert`s tie the offsets to the struct.** Every field must fit in `sizeof(Header)`, so a
  kernel header that changes layout breaks the build instead of reading past the field. The name is
  copied with the explicit `XT_EXTENSION_MAXNAMELEN`, not the size of the destination.
- **The definitions live in the `.cpp`**, with an explicit instantiation for the two headers. The
  public header stays free of `offsetof` and only `extension_header.cpp` knows the layout.
- **`write` clears the name field first** and copies at most `XT_EXTENSION_MAXNAMELEN - 1` bytes, so
  what the buffer held before never leaks into the name and the terminator is always there. It does
  not rely on a zeroed buffer.
- **`read` keeps the whole name field** in a `std::array`, with no terminator assumed. It is bounded
  with `strnlen` where it becomes a `std::string` (`RuleMapper::extensionOf`, a template over the
  header type).

`RuleMapper` keeps what is about the rule itself: the `ipt_entry` header, offsets, the 16-bit limit,
the walk over the matches and the read of the target. It asks `MatchHeader` / `TargetHeader` for
everything that is about one extension header.

## Alternatives considered

| Option | Why not |
|--------|---------|
| One `ExtensionHeader` without a template | The two layouts are identical today, so a `static_assert` could compare them. It hides that there are two kernel types: if a later kernel tells them apart, the build breaks without pointing at the difference. The template keeps the distinction in the type. |
| A `static_assert` on the type instead of a concept | Same effect, but the restriction hides in the body of the class; the concept puts it in the signature, as `KernelPayload` does. |
| Move the union access to a C file | The check is C++ only, but it adds a second language to the lib, to CMake and to tidy, and takes the code out of sight of the mapper. |
| Switch the check off in `.clang-tidy` for the file | Still a suppression, only less visible than the `NOLINT` it replaces. |
| Split `RuleMapper` into a match mapper and a target mapper | After this change little is left duplicated: one loop (`readMatches`) and one single read (`readTarget`). The split would spread the byte layout of an `ipt_entry` over two or three types, against the point of the plan. Left for later, if it still bothers. |

## Consequences

- The `NOLINT` for the union is gone. The one left in `rule_mapper.cpp` is `bytesOf` (cast through
  `void*`).
- Reading and writing a header is by offset and `memcpy`, so it is lower level than naming the field
  (`header.u.user.match_size`); the `static_assert`s and the tests are what keep it honest.
- `ExtensionHeader` has its own tests (`test/extension_header_test.cpp`, six cases run for both
  headers): write then read, a stale name field, a name longer than the field, a name without a
  terminator, `sizeFor` alignment, and where the payload starts.
