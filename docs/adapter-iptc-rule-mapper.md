# adapter_iptc: rule DTOs and mappers, the byte layout behind RuleMapper

**Status:** accepted 2026-11-15, implemented 2026-11-26 (`mappers/rule_mapper.h`, `mappers/payload_mapper.h`,
the seven `mappers/*_mapper.h`, `builder/rule_builder.h`; tests `rule_mapper_test.cpp`,
`payload_mapper_test.cpp`, `match_mapper_test.cpp`, `target_mapper_test.cpp`, `rule_builder_test.cpp`).
`RuleLayout` folded into `RuleMapper`'s private members. The kernel tier (`mangle_kernel_test.cpp`) has
not run against the new path yet: it skips where `ip_tables` is not loaded.
**Scope:** `adapter_iptc`: how a rule crosses from `MangleAdapter` down to libiptc and back, and who
knows the byte layout of an `ipt_entry`.
**Vocabulary:** Fowler, *Patterns of Enterprise Application Architecture*: **Mapper** (translates
between two representations; neither side knows the other) and **Data Transfer Object** (data only,
crosses a boundary). The word "codec" is not used.

## Context

`RuleLayout` (`include/adapter_iptc/rule_layout.h`) is the one place that knows the `ipt_entry`
layout: headers, the `u.user` / `u.kernel` union, offsets, `XT_ALIGN`, ownership of the rule buffer. It should be
the lowest layer of the adapter, seen only by `IptcHelper`. Today it is used by ten translation units:

| User | Why it needs the layout |
|------|-------------------------|
| `TemplateMatch`, `ExtensionTargetTemplate` | write the match / target header and hand the payload pointer to `fillData()` |
| `MarkMatch`, `TcpMatch`, `UdpMatch`, `ConntrackMatch`, `HashlimitMatch`, `NflogTarget` | `store()` / `load()` of the `xt_*` payload |
| `MarkMatch::dataOf`, `NflogTarget::dataOf` | walk the entry by offsets, with bounds checks (written twice) |
| `StandardTarget` | `writeStandardTarget()` / `standardTargetSize()` |
| `RuleBuilder` | `allocateEntry()`, offsets |
| `IptcHelper` | `allocateEntry()` to copy what libiptc lists |

The root cause is the boundary: matches and targets serialize themselves into the rule buffer, and
`IIptcHelper` takes and returns `ipt_entry`. While the boundary is the kernel buffer, every layer above it
has to know the layout.

Two related smells:

- `dtos/conntrack.h` includes `matchs/conntrack_match.h`, because `ConntrackMatch::State` lives in the
  match. A DTO depends on a class.
- The matches mix two roles: state for writing (`MarkMatch(mark)`), a `static read()` for reading.

## Decision

1. **The boundary becomes a DTO.** `IIptcHelper` takes and returns `RuleParam`, never `ipt_entry`.
2. **`RuleLayout` becomes `RuleMapper`** (`RuleParam ⇄ ipt_entry`), used only by `IptcHelper`. The
   current static helpers become its private implementation. The entry walk with bounds checks is
   written once, in `RuleMapper::fromEntry`.
3. **`PayloadMapper` translates a kernel payload struct to and from `ExtensionParam.payload`** (option
   V1b below): a template whose type parameter carries its identity (name, revision) through a trait,
   constrained by the `KernelPayload` concept (trivially copyable, with an identity). Why a template, the
   trait and the concept: [adapter-iptc-payload-mapper.md](adapter-iptc-payload-mapper.md).
4. **Matches and targets become stateless mappers** (option B below): `MarkParam ⇄ ExtensionParam`, and
   so on. The `TemplateMatch` / `ExtensionTargetTemplate` / `ITargetStrategy` hierarchy goes away; why,
   and the boundary before and after: [adapter-iptc-hierarchy-removal.md](adapter-iptc-hierarchy-removal.md).
   The header of each match and target is read and written by `ExtensionHeader<Header>`, by offset and
   without the union: [adapter-iptc-extension-header.md](adapter-iptc-extension-header.md).
   The rule buffer is a `std::vector<ipt_entry>` (`IptEntryBuffer`, `ipt_entry_buffer.h`), sized in whole
   `ipt_entry` elements: it replaced `unique_ptr<ipt_entry, &std::free>` over `calloc` (2026-11-26) and
   needs no `malloc`, no `void*` and no cast. `unique_ptr<ipt_entry[]>` was tried first and clang-tidy
   rejects the array type (`avoid-c-arrays`); `vector<std::byte>` would have needed a cast to
   `ipt_entry*`. The buffer can be up to `sizeof(ipt_entry) - 1` bytes larger than the rule, which is
   harmless: `next_offset` holds the real size.
   Corner case: a rule is longer than one `ipt_entry`, so its matches and target spill past the first
   element into the next ones. Only element 0 is a real `ipt_entry`; the rest is storage, reached by
   offset from `elems` (a zero-length array at the end of the struct, as in the kernel). Strictly the
   language calls that an access past the end of the first element, but it stays inside the vector,
   which is contiguous, aligned for `ipt_entry` and zeroed, and the code only addresses it by offset
   (`bytesOf`, `elems`). Consequences: never read the elements as separate rules, never `push_back` or
   resize a buffer after `toEntry` (a reallocation keeps the bytes but any pointer taken before is
   stale), and always hand libiptc `entry.data()` as a whole, never `&entry[1]`.
5. **DTOs never compose a mapper.** Data is on one side, translators on the other; only services
   (`IptcHelper`, the mappers, `MangleAdapter`) use mappers.
6. **The enums move to `dtos/`.** `ConntrackMatch::State` and `StandardTarget::Verdict` become DTO
   enums, so no DTO header includes a match or target header.
7. **The rule protocol is set explicitly for now**; `RuleBody` (below) is the planned replacement.
8. **Mappers are structs of static member functions**: no state, no data members, no constructor, no
   interface. Not a class with a deleted constructor (what `RuleLayout` is today), and not an interface
   injected into their users: nothing needs to replace a mapper in a test, they are tested directly, and
   `IIptcHelper` stays the seam the `MangleAdapter` tests use. A DTO is a struct of data members; a
   mapper is a struct of static functions; neither holds the other.

### Layers

```
TODAY                                        DECIDED
MangleAdapter                                MangleAdapter
  ├ MarkMatch ── RuleLayout (bytes)            ├ MarkMapper ──── PayloadMapper ── ExtensionParam
  ├ NflogTarget ─ RuleLayout (bytes)           ├ NflogMapper ─── PayloadMapper ── ExtensionParam
  ├ RuleBuilder ─ RuleLayout (bytes)           ├ RuleBuilder ─→ RuleParam
  └ IIptcHelper(ipt_entry*)                    └ IIptcHelper(RuleParam)
       └ IptcHelper ─ RuleLayout                    └ IptcHelper ─ RuleMapper (ex-RuleLayout) ─ ipt_entry
```

Two levels of translation, each with its own mapper:

- **envelope**: headers, offsets, alignment, allocation, the walk: `RuleMapper`;
- **content**: the `xt_*` struct of one extension: the per-extension mapper, through `PayloadMapper`.

## Types

```cpp
// dtos/rule.h: data only, no kernel header.
struct ExtensionParam
{
    std::string name;
    uint8_t revision = 0;
    std::vector<unsigned char> payload;   // the xt_*_info struct, no header

    bool operator==(const ExtensionParam&) const = default;
};

struct RuleParam
{
    uint8_t protocol = 0;                  // ipt_entry.ip.proto
    std::vector<ExtensionParam> matches;   // in rule order
    std::optional<ExtensionParam> target;  // empty only when read back inconsistent

    bool operator==(const RuleParam&) const = default;
};
```

```cpp
// payload_mapper.h: no kernel header either; the trait is specialized where the struct is known.
template <typename Payload>
struct PayloadIdentity;   // primary template left undefined: a struct without identity does not compile

// trivially copyable (memcpy is valid) and with a PayloadIdentity giving NAME and REVISION
template <typename Payload>
concept KernelPayload = std::is_trivially_copyable_v<Payload> && requires {
    { PayloadIdentity<Payload>::NAME } -> std::convertible_to<const char*>;
    { PayloadIdentity<Payload>::REVISION } -> std::convertible_to<uint8_t>;
};

struct PayloadMapper
{

    template <KernelPayload Payload>
    [[nodiscard]] static ExtensionParam toExtension(const Payload& payload);   // name, revision from the trait

    // nullopt when the extension is not this payload's name and revision, or its payload is too small.
    template <KernelPayload Payload>
    [[nodiscard]] static std::optional<Payload> fromExtension(const ExtensionParam& extension);
};
```

```cpp
// mark_mapper.cpp
template <>
struct PayloadIdentity<xt_mark_mtinfo1>
{
    static constexpr const char* NAME = "mark";
    static constexpr uint8_t REVISION = 1;
};
```

```cpp
// rule_mapper.h: the only header that names ipt_entry besides ipt_entry_buffer.h and iptc_helper.cpp.
struct RuleMapper
{

    [[nodiscard]] static IptEntryBuffer toEntry(const RuleParam& rule);
    [[nodiscard]] static RuleParam fromEntry(const ipt_entry& entry);
};
```

```cpp
class IIptcHelper
{
public:
    virtual ~IIptcHelper() = default;
    virtual void createChain() = 0;
    virtual void flushEntries() = 0;
    virtual void appendRule(const RuleParam& rule) = 0;
    virtual void commit() = 0;
    virtual bool chainExists() = 0;
    virtual std::vector<RuleParam> listRules() = 0;
};
```

```cpp
// One stateless mapper per extension; the read side exists only where it exists today.
struct MarkMapper
{
    [[nodiscard]] static ExtensionParam toExtension(MarkParam mark);
    [[nodiscard]] static ExtensionParam toExtension(MaskedMark mark);
    [[nodiscard]] static std::optional<MarkParam> fromRule(const RuleParam& rule);   // first "mark" match
};

struct NflogMapper
{
    [[nodiscard]] static ExtensionParam toExtension(const NflogParam& nflog);
    [[nodiscard]] static std::optional<NflogParam> fromRule(const RuleParam& rule);   // the target
};
// ConntrackMapper, TcpMapper, UdpMapper, HashlimitMapper, VerdictMapper: toExtension only.
```

```cpp
class RuleBuilder final : public IBuilder
{
public:
    RuleBuilder& setProtocol(uint8_t protocol);
    RuleBuilder& addMatch(ExtensionParam match);
    RuleBuilder& setTarget(ExtensionParam target);
    [[nodiscard]] RuleParam build() const override;   // throws when no target was set
};
```

`MangleAdapter` after the change:

```cpp
void MangleAdapter::addNflogRule(MarkParam mark, NflogParam nflog)
{
    const RuleParam rule = RuleBuilder()
                               .addMatch(MarkMapper::toExtension(mark))
                               .setTarget(NflogMapper::toExtension(nflog))
                               .build();
    m_helper->appendRule(rule);
}

// readNflogRules(): for each rule of listRules(), NflogMapper::fromRule() and MarkMapper::fromRule().
```

## Behaviour to keep

- **Write.** `RuleMapper::toEntry` lays out exactly what `RuleBuilder::build()` lays out today: each
  extension takes `XT_ALIGN(sizeof header + payload.size())` bytes, `target_offset` and `next_offset` as
  today. The standard target is an ordinary extension: name `""`, revision 0, payload the `int` verdict
  (`XT_ALIGN(sizeof(xt_entry_target) + sizeof(int))` equals today's `XT_ALIGN(sizeof(xt_standard_target))`).
- **Read.** Every offset and size in a buffer read back is untrusted, as today. `fromEntry` copies each
  match while its header fits before `target_offset`, its `match_size` covers at least its header and it
  ends before the target; the first one that fails ends the matches. The target is decoded on its own:
  it is empty when its header or its `target_size` does not fit in the entry. This is the same tolerance
  `MarkMatch::dataOf` and `NflogTarget::dataOf` have today, so a malformed match never hides the NFLOG
  target, and a rule never reads as one the adapter wrote. The target's revision is read from its header
  (today `readTargetHeader` reports 0).
- **Listing.** `IptcHelper::listRules()` maps each rule libiptc hands over with `RuleMapper::fromEntry`
  while the handle is open; the `RuleParam` owns its data, so the `copyOf` buffer copy goes away.
- **Payload read back.** `payload` holds `size − header` bytes, padding included, so it can be longer
  than the struct. `fromExtension` requires `payload.size() >= sizeof(Payload)`, name and revision equal
  to the trait; another revision is never decoded with this struct.
- **The name** is compared within its fixed field and may lack a terminator, as `ExtensionHeader::hasName`
  does today. `ExtensionParam.name` is built from at most `XT_EXTENSION_MAXNAMELEN` bytes up to the first
  NUL.
- Every translation now in the matches and targets moves unchanged into the mappers: hashlimit's
  default `mode`, conntrack's `State` → flags, `Verdict` → kernel verdict, the NFLOG prefix cut on a UTF-8
  boundary, `range` written as `len` + `XT_NFLOG_F_COPY_LEN`, threshold 0 read back as unset, a mark with
  a partial mask or inversion read back as `nullopt`.

## Protocol

The kernel rejects `-m tcp` / `-m udp` in a rule without the matching `-p` (`xt_check_match()`); since
`iptc_commit()` sends the whole table, the error only shows at commit as `EINVAL`. Today
`RuleBuilder::resolveProtocol()` takes the first non-zero `TemplateMatch::protocol()`, which silently
picks the first protocol of a rule holding both tcp and udp.

With stateless mappers there is no virtual `protocol()`. For now the caller sets it with
`RuleBuilder::setProtocol()`. No production path needs it yet: `MangleAdapter` builds only mark,
conntrack and NFLOG rules; the redirection DNAT (`--dport`) is the first that will.

The `TODO` now above `RuleBuilder::resolveProtocol()` moves to `setProtocol()` and keeps the plan:
**`RuleBody`**, a DTO of protocol, matches and target that each mapper produces
(`TcpMapper::toBody(ports)` yields `protocol = IPPROTO_TCP` plus the `tcp` match); the builder merges the
bodies and throws on two different protocols, two targets or no target; `TcpMapper::fromRule` checks the
protocol and the match together. Not part of this change.

## Approaches considered

### Payload: how the `xt_*` struct reaches `ExtensionParam`

| | V1: plain template | **V1b: template + identity trait** (chosen) | V2: `std::variant` of kernel structs |
|---|---|---|---|
| Wrong struct on read | compiles, reads garbage | `nullopt` | `nullptr` from `get_if` |
| A new extension touches | its mapper | its mapper | the variant and `RuleMapper` (name → type switch in the lowest layer) |
| `xt_*.h` in public headers | no | no | yes: `dtos/rule.h` pulls them all into `MangleAdapter` |
| Rule someone else wrote (`comment`, …) | bytes | bytes | needs an `UnknownPayload` of bytes anyway |
| Variable-length payload (later) | fits | fits | does not fit a fixed struct |

V2 buys typing by leaking the kernel layout through the DTO, the thing this change removes. V1b keeps
V2's type safety without that coupling.

### Role of matches and targets

- **A: stateful objects, as today**, writing through `extension()` and reading through a `static`. Less
  churn, but keeps the asymmetry.
- **B: stateless mappers** (chosen). Symmetric, tested by round trip (`fromRule` of a rule built from
  `toExtension(x)` gives `x`), and `RuleBuilder` takes data instead of `shared_ptr<TemplateMatch>`.

### Protocol

- **A: explicit, by the caller** (chosen for now). Symmetric on read; the requirement is a convention.
- **B: `requiredProtocol` in `ExtensionParam`** from the trait. Rejected: the kernel buffer has no such
  field, so a read-back extension differs from a written one, and the extension DTO carries a fact of the
  rule.
- **C: `RuleBody` per mapper** (planned, above).

### DTO composing a mapper

Rejected. It is Active Record: the DTO would depend on the format, `dtos/rule.h` would include the
mapper and `ip_tables.h`, and the layout would leak again through the DTO.

## Cost

Removed:

- `template_match.h/.cpp`, `extension_target_template.h/.cpp`, `i_target_strategy.h`;
- `rule_layout.h/.cpp` (absorbed by `rule_mapper`);
- `mock_template_match.h`, `mock_target_strategy.h`, `mock_builder.h`: no test uses them today.

Rewritten, mostly moved code:

- the seven matches and targets become mappers; each `fillData` body becomes a `toExtension` body;
- `MarkMatch::dataOf` and `NflogTarget::dataOf` (about 85 lines) go away, replaced by the one walk in
  `RuleMapper::fromEntry`;
- `RuleBuilder`, `IIptcHelper`, `MockIptcHelper`, `IptcHelper`, `MangleAdapter`;
- `dtos/conntrack.h` and the standard target's verdict enum.

Tests (the bulk of the work):

- `match_test` (435 lines), `target_test` (123), `nflog_target_test` (347) write into a buffer and inspect
  headers. They become mapper tests on `ExtensionParam`; size, alignment and header checks move to a new
  `rule_mapper_test`, with the malformed-buffer cases.
- `rule_builder_test` (193) splits between the builder and `rule_mapper_test`; the
  `ProtocolComesFromTheFirstProtocolMatch` case becomes a `setProtocol` case.
- `mangle_adapter_test` (306) gets simpler: `MockIptcHelper` receives `RuleParam`, so expectations
  compare fields instead of decoding buffers.
- `mangle_kernel_test` (320) is **not** untouched: it calls `IptcHelper::appendEntry` / `listEntries`
  directly and defines `UnknownTarget : ExtensionTargetTemplate` to make the kernel reject a commit. It
  moves to `appendRule` / `listRules`, and the unknown target becomes a plain
  `ExtensionParam{.name = "BBNOSUCHTARGET", .payload = 4 zero bytes}`.

## Goals, non-goals

Goals:

- `RuleLayout`'s successor is included by `IptcHelper` only; no public interface names `ipt_entry`.
- Every behaviour listed above is unchanged, and the release, unit, ASan, Valgrind and kernel tests pass.

Non-goals:

- `RuleBody` and protocol validation.
- New read sides (conntrack, tcp, udp, hashlimit have none today and get none).
- Moving `ipt_entry_buffer.h` / `rule_mapper.h` to a private include directory: headers stay under
  `include/adapter_iptc/`; encapsulation comes from no public interface needing them.
- Inverted matches (`ip.invflags`), source ports, any new extension.

## Calls made while writing this down

Settled here without a separate discussion; open to change:

- **`RuleParam.target` is optional** so a read-back rule with an inconsistent target can still carry its
  matches; `RuleBuilder::build()` refuses a rule without one.
- **`IBuilder::build()` returns `RuleParam`**; the interface stays.
- **File layout:** `dtos/rule.h`, `mappers/payload_mapper.h`, `mappers/rule_mapper.h`, one
  `mappers/<extension>_mapper.h/.cpp` per extension; `matchs/` and `targets/` go away. The trait
  specialization of each struct lives in that extension's `.cpp`, the only translation unit that uses it.
- **Standard target** is `VerdictMapper::toExtension(Verdict)`, payload struct `StandardVerdict { int
  verdict; }` so the trait has a type of its own.

## Left to the builder

- Migration order (new types next to the old ones, then the switch, or one cut) and how the commits are
  split.
- Test names and fixtures.
- Whether `PayloadMapper::toExtension` zero-fills or the mappers keep `xt_*{}` value-initialization (both
  yield zeroed fields the kernel defaults on).
