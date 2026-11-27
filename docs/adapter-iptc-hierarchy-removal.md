# adapter_iptc: removing the TemplateMatch / ExtensionTargetTemplate hierarchy

**Status:** accepted 2026-11-15 (decision 4 of [adapter-iptc-rule-mapper.md](adapter-iptc-rule-mapper.md)),
implemented 2026-11-26 in Tasks 4 to 6 of the [plan](superpowers/plans/2026-11-15-adapter-iptc-rule-mapper.md):
the old classes and `RuleLayout` are deleted, `RuleBuilder` and `IIptcHelper` speak `RuleParam`.
**Scope:** why the match and target class hierarchy goes away when the boundary becomes a DTO, and what
replaces each part of it.

## The hierarchy today

```
ITargetStrategy                 TemplateMatch
  size(), write(ptr)              size(), write(ptr), protocol()
  └ ExtensionTargetTemplate       ├ MarkMatch, TcpMatch, UdpMatch
      ├ NflogTarget               ├ ConntrackMatch
  └ StandardTarget                └ HashlimitMatch
```

Both bases are a **Template Method** (GoF): the base owns the fixed algorithm and the subclass fills hooks.

```cpp
std::size_t ExtensionTargetTemplate::size() const
{
    return XT_ALIGN(sizeof(xt_entry_target) + dataSize());
}

void ExtensionTargetTemplate::write(unsigned char* ptr) const
{
    RuleLayout::writeTargetHeader(ptr, size(), name());
    fillData(RuleLayout::targetPayload(ptr));
}
```

`TemplateMatch` is the same, with `revision()` and a virtual `protocol()` added. `RuleBuilder` holds a
`vector<shared_ptr<TemplateMatch>>` and a `shared_ptr<ITargetStrategy>`, adds up the virtual `size()`s,
allocates the `ipt_entry` and calls each `write(ptr)` at its offset.

## What the hooks actually vary

| Hook | What a subclass returns (`NflogTarget`) |
|------|-----------------------------------------|
| `name()` | a constant: `"NFLOG"` |
| `revision()` (matches only) | a constant |
| `dataSize()` | `sizeof(xt_nflog_info)` |
| `fillData(ptr)` | builds a `xt_nflog_info` from its parameter and copies its bytes to `ptr` |
| `protocol()` (matches only) | a constant: `IPPROTO_TCP` / `IPPROTO_UDP` for `TcpMatch` / `UdpMatch`, 0 otherwise |

None of the hooks is behaviour. They are constants, a `sizeof` and a byte copy. The one part that belongs
to each subclass is building the `xt_*` struct from the domain parameter.

## Where each part goes

| Today (virtual, at runtime) | With mappers |
|-----------------------------|--------------|
| `name()`, `revision()` | `PayloadIdentity<xt_nflog_info>::NAME` / `REVISION`, at compile time |
| `dataSize()` | `sizeof(Payload)` inside `PayloadMapper`, at compile time |
| `fillData()`: the byte copy | `PayloadMapper::toExtension`, the same for every extension |
| `fillData()`: building the struct | `NflogMapper::toExtension(NflogParam)`, **the only per-extension part** |
| base `size()` + `write()` | `RuleMapper::toEntry`, in one place |
| `protocol()` | `RuleBuilder::setProtocol()` for now; `RuleBody` later |

How `PayloadMapper` and the trait work: [adapter-iptc-payload-mapper.md](adapter-iptc-payload-mapper.md).

The output of every mapper is an `ExtensionParam`: name, revision, bytes. An NFLOG target, a standard
verdict and a mark match have the same type. `RuleParam` holds a homogeneous `vector<ExtensionParam>`, and
`RuleMapper` walks it without asking anyone for its name or size: the answers are in the data. With nothing
left to dispatch, there is no reason for `virtual`, for the bases or for `shared_ptr`.

## The boundary, before and after

The hierarchy is not removed for its own sake. It is what forces `RuleLayout` to be public.

**Before: the boundary is the kernel buffer.** Each match and target receives a pointer into the
`ipt_entry` and serializes itself there, so each one needs `RuleLayout` to find its header and payload.

```
MangleAdapter
  ├ make_shared<MarkMatch>(mark) ──┐
  ├ make_shared<NflogTarget>(nflog) ┤
  └ RuleBuilder ───────────────────┴─ write(ptr) ──▶ ipt_entry buffer
       │                                ▲  every class above knows the layout
       │                                └─ RuleLayout (public: ten translation units)
       └─ IptEntryPtr ──▶ IIptcHelper::appendEntry(ipt_entry*) ──▶ libiptc
```

```cpp
void MangleAdapter::addNflogRule(MarkParam mark, NflogParam nflog)
{
    auto markMatch = std::make_shared<MarkMatch>(mark.mark);
    auto nflogTarget = std::make_shared<NflogTarget>(std::move(nflog));

    auto entry = RuleBuilder().setMatch(markMatch).setTarget(nflogTarget).build();

    m_helper->appendEntry(entry.get());
}
```

**After: the boundary is a DTO.** The mappers return data, and only `RuleMapper`, behind `IptcHelper`,
touches the buffer.

```
MangleAdapter
  ├ MarkMapper::toExtension(mark)   ──▶ ExtensionParam ─┐
  ├ NflogMapper::toExtension(nflog) ──▶ ExtensionParam ─┤  data only, no layout
  └ RuleBuilder ──────────────────────▶ RuleParam ──────┘
       └─▶ IIptcHelper::appendRule(RuleParam)
              └ IptcHelper ── RuleMapper::toEntry ──▶ ipt_entry buffer ──▶ libiptc
                               ▲ the only code that knows the layout (ex-RuleLayout)
```

```cpp
void MangleAdapter::addNflogRule(MarkParam mark, NflogParam nflog)
{
    const RuleParam rule = RuleBuilder()
                               .addMatch(MarkMapper::toExtension(mark))
                               .setTarget(NflogMapper::toExtension(nflog))
                               .build();
    m_helper->appendRule(rule);
}
```

No mapper receives a pointer into the kernel buffer, so `RuleLayout` can become a private detail of
`RuleMapper`.

## What else changes

- **Reading becomes symmetric.** The hierarchy only writes. Reading lives elsewhere, in
  `MarkMatch::dataOf` and `NflogTarget::dataOf`, each repeating the same entry walk with bounds checks.
  With mappers, `fromRule` sits next to `toExtension`, and the walk is written once, in
  `RuleMapper::fromEntry`.
- **Tests compare values.** A mapper test compares an expected `ExtensionParam` with `==`, without a buffer
  or a mock. `MockTemplateMatch` and `MockTargetStrategy`, unused today, go away.
- **The target revision is carried.** `writeTargetHeader` takes no revision today, so every target is
  written as revision 0; `ExtensionParam.revision` carries it for targets as well.
- **The protocol leaves the matches.** `TemplateMatch::protocol()` is gone; the caller sets it, and the
  kernel requirement behind it is the `TODO` above `RuleBuilder` (the `Protocol` section of the rule-mapper
  doc).

## What is lost

Open extensibility at runtime: plugging in a new match or target without recompiling. The helper does not
need it: it is a closed binary with a known set of extensions. Adding one stays small: a mapper and a
`PayloadIdentity` specialization.

## What is removed

Task 6 of the plan deletes:

- `template_match.h/.cpp`, `extension_target_template.h/.cpp`, `i_target_strategy.h`;
- `matchs/` and `targets/`, headers and sources, once their bodies have moved into `mappers/`;
- `mock_template_match.h`, `mock_target_strategy.h`, `mock_builder.h`;
- `rule_layout.h/.cpp`, folded into `RuleMapper`;
- `match_test.cpp`, `target_test.cpp`, `nflog_target_test.cpp`, replaced by the mapper tests.
