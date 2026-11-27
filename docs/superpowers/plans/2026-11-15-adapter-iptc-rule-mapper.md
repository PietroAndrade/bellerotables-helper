# adapter_iptc rule DTOs and mappers: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confine the `ipt_entry` byte layout to `RuleMapper`, used only by `IptcHelper`, by making
`RuleParam`/`ExtensionParam` DTOs the boundary and turning matches and targets into stateless mappers.

**Architecture:** Additive first, then one switch, then deletion. Tasks 1–4 add the DTOs and mappers next
to the existing classes, so every commit builds and passes. Task 5 switches `RuleBuilder`, `IIptcHelper`,
`IptcHelper` and `MangleAdapter` to the new types in one cut, because their interfaces change together.
Task 6 deletes the old hierarchy and folds `RuleLayout` into `RuleMapper`.

**Tech Stack:** C++23, GCC 13, CMake (`GLOB_RECURSE`), GTest/GMock, libiptc (`ip4tc`), sandbox container
driven by the `Makefile`.

**Spec:** [docs/adapter-iptc-rule-mapper.md](../../adapter-iptc-rule-mapper.md). Read it first: the
"Behaviour to keep" section is the acceptance list.

## Where we stopped (2026-11-26)

- **Tasks 1 and 2:** done, committed and pushed (358b2e2, 9647e7f on `feat/adapter-iptc`).
- **Task 3 (`RuleMapper`):** done and committed. Full gate green (format-check, rebuild, tidy-check, test-unit 11/11,
  test-asan 11/11, test-valgrind 6/6). `matchBytes` is a free function in the anonymous namespace of
  `rule_mapper.cpp` (user's call, an exception to "no free functions"); `targetBytes` is inlined in `toEntry`.
- **Task 4 (per-extension mappers):** done and committed. Full gate green (format-check, rebuild, tidy-check, unit 11/11, asan 11/11, valgrind 6/6).
  Rulings in the ledger; the one Task 5 must honour: `TcpMapper`/`UdpMapper` do not set `RuleParam.protocol`.
- **Task 5 (`RuleParam` boundary):** done and committed; full gate green (unit 11/11, asan 11/11, valgrind 6/6)
  but the kernel tier **skipped all 15 tests** (the host has no `ip_tables`/`iptable_mangle` module): run it
  after `sudo modprobe ip_tables iptable_mangle` before trusting `appendRule`/`listRules` against the kernel.
  `LegacyRuleBuilder` (test/legacy_rule_builder.h) keeps the old-class tests building until Task 6.
- **Task 6 (delete the hierarchy):** done and committed (`41e7dd6` after the rebase, `84ed0a7` before it).
  `adapter_iptc_tests` 181 → 121. Not re-homed: `DeclaresItsProtocol` (5 cases; the protocol is now
  `RuleBuilder::setProtocol`, covered by `ProtocolIsTheOneSet`) and the `NflogTarget(group, prefix)`
  constructor test (the constructor is gone). Refined in review, same commit: `ExtensionHeader<Header>`
  ([adapter-iptc-extension-header.md](../../adapter-iptc-extension-header.md)) replaced the four header
  functions and the `NOLINT` for the union; the rule buffer is `std::vector<ipt_entry>` (`IptEntryBuffer`,
  `ipt_entry_buffer.h`) instead of `calloc` + `std::free`.
- **Rebase onto `develop` (2026-11-26):** done, no conflicts; 39 commits on top of `origin/develop`
  (`2b405db`). Full gate green after it (format-check, release, tidy-check, unit 11/11, ASan 11/11,
  Valgrind 6/6). The user pushed the rebased `feat/adapter-iptc`.
- **Squash-merge into `develop` (2026-11-26):** done and pushed, `develop` is at `1d44778`
  ("Squash merge feat/adapter-iptc into develop"; tree identical to the branch). H-201 to H-203 are closed.
  `feat/adapter-iptc` stays until the work reaches `master`.
- The final whole-branch review of the skill was replaced by the user's own review.

## Next session: where to pick up

Order (backlog E2, `docs/plan/backlog.md`). Steps 1 and 3 of the earlier list (push, squash-merge) are done.

1. **Kernel tier.** On the host: `sudo modprobe ip_tables iptable_mangle`. Then run
   `docker-compose -f sandbox/docker-compose.yml run --rm sandbox /test-builds/build-unit/adapter_iptc/test/adapter_iptc_kernel_tests`
   (15 `MangleKernelTest` cases, all skipped so far). `appendRule`/`listRules` are not verified against the
   kernel until they pass; a failure is fixed in its own commit. This is also the base of the I3 exit gate (H-208).
2. **H-205, the use case for M0** (`logging` present gives an NFLOG rule through `MangleAdapter`, absent removes
   it), on a new branch cut from `develop`. `MangleAdapter::addNflogRule`, `readNflogRules`, `flush` and
   `createChain` already exist; what is missing is the use case that decides from the parsed `desired`. Then
   **H-204** (controller, on top of `adapter_socket` and the parser E1, both on `develop`), **H-206**
   (`main.cpp`, `SystemAdapters::createPosix()`), **H-207** (systemd units) and **H-208** (`socat` driver +
   `iptables-save`, the I3 exit gate).
3. **Hub:** `hub-bellerophon` pins this repo by SHA: move the submodule to the new `develop` (`1d44778`), and
   update `docs/design/status.md` (snapshot 2026-11-13) and the I3 line of its `CLAUDE.md`, which still call
   `adapter_iptc` "parked, PoC, 50 cases".

Open decisions and loose ends (none blocks the steps above):

- `RuleBuilder::setProtocol` TODO: the kernel needs the rule protocol to match the protocol of `-m tcp`/`-m udp`;
  planned `toBody()` mappers, not needed until the redirection DNAT reaches this adapter.
- `RuleMapper` public methods are static; an `IRuleMapper` interface was deferred by the user.
- Free helpers kept by the user in anonymous namespaces: `isUtf8Continuation`, `prefixBytesThatFit` (NFLOG prefix cut
  on a UTF-8 boundary) and `HeaderLayout`/`fieldsFitTheHeader` (extension header). `MAX_RULE_BYTES` is the one
  constant in `rule_mapper.cpp`.
- The untracked `.ai-memory.toml`, `apply`, `apply.sh`, `changes.diff` and `compress.sh` in the repo root are the
  user's, not part of any commit.

- Deviations from Task 3 as written: `toEntry` also throws `std::length_error` past the 16-bit offsets
  (`RuleTooLargeForTheOffsetsThrows`); the parameterized fixtures are named `RuleMapperToEntryShape`,
  `RuleMapperMalformedMatches` and `RuleMapperMalformedTarget`; the test redefines the constants instead of
  reusing `rule_builder_test.cpp`'s; the layout diagrams were copied, not moved; two extra tests
  (`MatchPayloadFollowsItsHeader`, `ProtocolIsRead`).

## Global Constraints

- House C++ rules: no free functions; headers only under `adapter_iptc/include/adapter_iptc/`; no calls
  and no long conditions inside `if`/`while` (bind to a named `const` first); interfaces have no
  constructors.
- Mappers are `struct`s of static member functions only: no data members, no constructor, no interface.
  DTOs are `struct`s of data members only. Neither holds the other.
- One call per statement, as in `~/.claude/skills/docs/cpp-conventions.md`: a call is only the whole
  initializer of a declaration or a statement of its own; arguments, `return` and braced-initializer fields
  hold names and literals. Applied to `rule_mapper.cpp` so far; apply it to every new mapper.
- Every comment starts with a modifier (`BUG COMPLEX FIXME HACK LEARN OPTIMIZE REVIEW TODO`) and a colon.
  Moved code keeps its `LEARN` comments, rewritten where they name a class that no longer exists.
- Project headers are included with quotes (`make include-check`). Column limit 100 (`make format-check`).
- `GLOB_RECURSE` picks up sources: after adding or deleting a file, run `make configure-unit` before
  `make build-unit`.
- Every build and test runs in the sandbox. One gtest filter:
  `docker-compose -f sandbox/docker-compose.yml run --rm sandbox /test-builds/build-unit/adapter_iptc/test/adapter_iptc_tests --gtest_filter='<Filter>*'`
  (if the binary is elsewhere, find it under `/test-builds/build-unit`).
- Full gate, the pre-commit hook's: `make format-check && make rebuild && make tidy-check && make rebuild-unit && make test-unit && make rebuild-asan && make test-asan && make rebuild-valgrind && make test-valgrind`.
- Commits only when the user asks (`CLAUDE.md`). Each "Commit" step is a checkpoint: offer the commit,
  don't make it unasked. Work stays on `feat/adapter-iptc`. That branch already carries uncommitted edits
  to `hashlimit_match.cpp` (`LEARN` on `cfg`) and `rule_builder.cpp` (protocol `TODO`); keep both.
- Names fixed by the spec: `RuleParam`, `ExtensionParam`, `PayloadIdentity`, `PayloadMapper`,
  `RuleMapper`, `MarkMapper`, `TcpMapper`, `UdpMapper`, `ConntrackMapper`, `HashlimitMapper`,
  `NflogMapper`, `VerdictMapper`, `StandardVerdict`, `RuleBody` (named in the `TODO` only).

## Review Focus

1. **A read-back extension name filling all 29 bytes with no NUL** (a foreign or corrupt rule) must
   produce a bounded `std::string` and never match `"mark"`/`"NFLOG"`. Test: Task 3,
   `RuleMapperFromEntry.NameWithoutTerminatorIsBounded`.
2. **The payload read back is longer than the struct** (alignment padding: mark is 12 bytes, read back
   16). `fromExtension` must accept it, and an exact `RuleParam` round trip must not be assumed. Tests:
   Task 2, `PayloadMapperTest.LongerPayloadStillDecodes`; Task 3,
   `RuleMapperFromEntry.PayloadKeepsAlignmentPadding`.
3. **A malformed matches area must not hide a well-formed NFLOG target**: today `NflogTarget::read`
   ignores the matches. Test: Task 3, `RuleMapperFromEntry.BrokenMatchStillLeavesTheTarget`.
4. **A rule with no target**: `RuleBuilder::build()` and `RuleMapper::toEntry()` must throw
   `std::invalid_argument` and never hand libiptc a rule without a target. Tests: Task 3,
   `RuleMapperToEntry.RuleWithoutTargetThrows`; Task 5, `RuleBuilderTest.BuildWithoutTargetThrows`.
5. **An extension name longer than the kernel field** on write is cut to 28 bytes plus NUL, as `strncpy`
   does today, never overflowing into the revision byte. Test: Task 3,
   `RuleMapperToEntry.LongNameIsCutToTheField`.

---

### Task 1: DTOs and enums in `dtos/`

**Files:**
- Create: `adapter_iptc/include/adapter_iptc/dtos/rule.h`, `adapter_iptc/include/adapter_iptc/dtos/verdict.h`
- Modify: `adapter_iptc/include/adapter_iptc/dtos/conntrack.h` (no longer includes `matchs/conntrack_match.h`)
- Modify: `matchs/conntrack_match.h/.cpp`, `targets/standard_target.h/.cpp`, `src/adapters/mangle_adapter.cpp`
- Modify (call sites only): `test/match_test.cpp`, `test/target_test.cpp`, `test/mangle_adapter_test.cpp`,
  `test/nflog_target_test.cpp`, `test/kernel/mangle_kernel_test.cpp`
- Test: `adapter_iptc/test/rule_dto_test.cpp`

**Interfaces:**
- Produces:
  - `struct ExtensionParam { std::string name; uint8_t revision = 0; std::vector<unsigned char> payload; bool operator==(const ExtensionParam&) const = default; };`
  - `struct RuleParam { uint8_t protocol = 0; std::vector<ExtensionParam> matches; std::optional<ExtensionParam> target; bool operator==(const RuleParam&) const = default; };`
  - `enum class ConntrackState : uint8_t { NEW, ESTABLISHED_RELATED, INVALID };` in `dtos/conntrack.h`, and `ConntrackParam { ConntrackState state; }`
  - `enum class Verdict : uint8_t { ACCEPT, DROP, RETURN };` in `dtos/verdict.h`
  - `ConntrackMatch(ConntrackState)` and `StandardTarget(Verdict)` replace the nested enums, which are removed.

- [x] **Step 1: Write the failing test** `rule_dto_test.cpp`:
  - `RuleDtoTest.DefaultRuleHasNoProtocolNoMatchesNoTarget`: `RuleParam{}.protocol == 0`, `matches.empty()`, `!target.has_value()`.
  - `RuleDtoTest.RulesWithEqualFieldsAreEqual`: two `RuleParam`s with the same protocol, one match `{"mark", 1, {1,2}}` and a target `{"NFLOG", 0, {}}` compare equal; changing the match payload to `{1,3}` makes them differ.
  - `RuleDtoTest.DtoHeadersPullNoClass`: `static_assert(std::is_aggregate_v<ConntrackParam>)` plus `ConntrackParam{.state = ConntrackState::NEW}`, built in a file that includes only `dtos/conntrack.h`.
- [x] **Step 2: Run it to verify it fails.** `make configure-unit build-unit`. Expected: compile error, `dtos/rule.h` / `ConntrackState` not found.
- [x] **Step 3: Create the DTO headers, move both enums, update every call site** (`ConntrackMatch::State::X` → `ConntrackState::X`, `StandardTarget::Verdict::X` → `Verdict::X`). Each header gets one `LEARN` comment saying what it carries. `rule.h` includes no kernel header.
- [x] **Step 4: Run the unit tests.** `make build-unit && make test-unit`. Expected: all green, including the new `RuleDtoTest.*`.
- [x] **Step 5: Verify the inversion is gone.** `grep -rn '#include' adapter_iptc/include/adapter_iptc/dtos/` lists no `matchs/` or `targets/` header.
- [x] **Step 6: Commit** (checkpoint): `refactor(adapter_iptc): rule DTOs, enums move into dtos/`

### Task 2: `PayloadMapper` and `PayloadIdentity`

**Files:**
- Create: `adapter_iptc/include/adapter_iptc/mappers/payload_mapper.h` (header-only templates)
- Test: `adapter_iptc/test/payload_mapper_test.cpp`

**Interfaces:**
- Consumes: `ExtensionParam` (Task 1).
- Rationale (template, identity, `memcpy`, concept): [docs/adapter-iptc-payload-mapper.md](../../adapter-iptc-payload-mapper.md).
- Produces:
  - `template <typename Payload> struct PayloadIdentity;` primary template declared, never defined. A specialization provides `static constexpr const char* NAME` and `static constexpr uint8_t REVISION`.
  - `template <typename Payload> concept KernelPayload = std::is_trivially_copyable_v<Payload> && requires { { PayloadIdentity<Payload>::NAME } -> std::convertible_to<const char*>; { PayloadIdentity<Payload>::REVISION } -> std::convertible_to<uint8_t>; };`
  - `struct PayloadMapper { template <KernelPayload Payload> [[nodiscard]] static ExtensionParam toExtension(const Payload& payload); template <KernelPayload Payload> [[nodiscard]] static std::optional<Payload> fromExtension(const ExtensionParam& extension); };`
  - Both constrained by `KernelPayload`, no `static_assert`. `toExtension` copies `sizeof(Payload)` bytes. `fromExtension` returns `nullopt` unless `name == NAME`, `revision == REVISION` and `payload.size() >= sizeof(Payload)`, then copies the first `sizeof(Payload)` bytes with `std::memcpy`.

- [x] **Step 1: Write the failing tests** with a test-only payload `struct TestPayload { uint32_t first; uint16_t second; };` and its `PayloadIdentity` specialization (`"test"`, revision 2) in the test file:
  - `PayloadMapperTest.ToExtensionTakesNameAndRevisionFromTheIdentity`: `name == "test"`, `revision == 2`, `payload.size() == sizeof(TestPayload)`.
  - `PayloadMapperTest.RoundTripsThePayload`: `fromExtension<TestPayload>(toExtension(TestPayload{0x11223344, 0x5566}))` has `first == 0x11223344`, `second == 0x5566`.
  - `PayloadMapperTest.OtherNameIsNotDecoded`, `PayloadMapperTest.OtherRevisionIsNotDecoded`: edit `name` to `"other"` / `revision` to 3 → `nullopt`.
  - `PayloadMapperTest.ShortPayloadIsNotDecoded`: `payload.resize(sizeof(TestPayload) - 1)` → `nullopt`.
  - `PayloadMapperTest.LongerPayloadStillDecodes`: `payload.resize(sizeof(TestPayload) + 4, 0)` → decodes the original values (Review Focus 2).
  - `PayloadMapperTest.ConceptAcceptsOnlyMappableTypes`: `static_assert(KernelPayload<TestPayload>)`, `static_assert(!KernelPayload<NoIdentity>)` (a trivially copyable struct with no specialization) and `static_assert(!KernelPayload<std::string>)`, written after the `TestPayload` specialization.
- [x] **Step 2: Run them to verify they fail.** `make configure-unit build-unit`. Expected: `mappers/payload_mapper.h` not found.
- [x] **Step 3: Implement `payload_mapper.h`.** Short `LEARN` comments that point to the payload doc: on `PayloadIdentity` (left undefined; specializations live in the `.cpp` of the mapper that owns the struct), on `KernelPayload` (a specialization must be visible before the concept is first checked for its type), on the padding read back and on copying instead of `reinterpret_cast`.
- [x] **Step 4: Run them to verify they pass.** Gtest filter `PayloadMapperTest`. Expected: 7 passed.
- [x] **Step 5: Commit** (checkpoint): `feat(adapter_iptc): PayloadMapper with a payload identity trait`

### Task 3: `RuleMapper`

**Files:**
- Create: `adapter_iptc/include/adapter_iptc/mappers/rule_mapper.h`, `adapter_iptc/src/mappers/rule_mapper.cpp`
- Test: `adapter_iptc/test/rule_mapper_test.cpp`

**Interfaces:**
- Consumes: `RuleParam`, `ExtensionParam` (Task 1). `RuleLayout` stays for now as the implementation's helper; Task 6 folds it in.
- Produces: `struct RuleMapper { [[nodiscard]] static IptEntryPtr toEntry(const RuleParam& rule); [[nodiscard]] static RuleParam fromEntry(const ipt_entry& entry); };`
  - `toEntry`: throws `std::invalid_argument` when `!rule.target`. Each extension takes `XT_ALIGN(sizeof header + payload.size())` bytes. Match headers carry name, revision and `match_size`; the target header carries name, revision and `target_size`; the payload follows each header; `target_offset = sizeof(ipt_entry) + Σ matches`, `next_offset = target_offset + target`, `ip.proto = rule.protocol`. Names are cut to `XT_EXTENSION_MAXNAMELEN - 1` bytes.
  - `fromEntry`: the walk and the bounds checks of `MarkMatch::dataOf` (matches) and `NflogTarget::dataOf` (target), kept separate, so a failure in one never empties the other. A match is copied while its header fits before `target_offset`, its size is at least its header and it ends at or before `target_offset`; the first that fails ends `matches`. The matches area is empty when `target_offset < sizeof(ipt_entry)` or `target_offset > next_offset`. The target is set when `target_offset >= sizeof(ipt_entry)`, its header fits before `next_offset`, `target_size >= sizeof(xt_entry_target)` and it ends at or before `next_offset`. `name` is the field up to its first NUL, at most `XT_EXTENSION_MAXNAMELEN` bytes. `payload` is `size − header` bytes. `revision` comes from each header, target included. `protocol = entry.ip.proto`.

- [x] **Step 1: Write the failing tests.** Build rules as `RuleParam` literals; the expected values come from `rule_builder_test.cpp`'s constants (`MARK_MATCH_BYTES`, `STANDARD_TARGET_BYTES`, …), which this file reuses. A standard target here is `ExtensionParam{"", 0, <4 bytes of ACCEPT_VERDICT>}`.
  - `RuleMapperToEntry.TargetOffsetCoversHeaderAndEveryMatch`, `RuleMapperToEntry.NextOffsetIsTargetOffsetPlusTargetSize`: parameterized over the `RULE_LAYOUT_CASES` shapes (mark only; mark+tcp; tcp+udp; none), with payload sizes `sizeof(xt_mark_mtinfo1)`, `sizeof(xt_tcp)`, `sizeof(xt_udp)`.
  - `RuleMapperToEntry.MatchHeadersLandInInsertionOrder`: name, revision and `match_size` of each match at its offset.
  - `RuleMapperToEntry.StandardTargetVerdictLandsAtTargetOffset`: `target_size == XT_ALIGN(sizeof(xt_standard_target))`, `verdict == ACCEPT_VERDICT`, empty name.
  - `RuleMapperToEntry.ProtocolLandsInTheRuleHeader`: `protocol = IPPROTO_TCP` → `ip.proto == IPPROTO_TCP`.
  - `RuleMapperToEntry.RuleWithoutTargetThrows`: `EXPECT_THROW(..., std::invalid_argument)` (Review Focus 4).
  - `RuleMapperToEntry.LongNameIsCutToTheField`: a 40-char name → the header name is its first 28 chars plus NUL, and the revision byte is the one given (Review Focus 5).
  - `RuleMapperFromEntry.RoundTripsAnAlignedRule`: payload sizes chosen so `header + payload` is already aligned (8 bytes) → `fromEntry(*toEntry(r)) == r`.
  - `RuleMapperFromEntry.PayloadKeepsAlignmentPadding`: a 12-byte payload reads back as `XT_ALIGN(32 + 12) - 32` bytes whose first 12 are the originals (Review Focus 2).
  - `RuleMapperFromEntry.MalformedMatches`: parameterized. After `toEntry` of mark+accept, each case edits the buffer and asserts `matches.size()` and `target.has_value()`. Cases: `ZeroMatchSizeStopsTheWalk` (0, yes), `MatchRunningIntoTheTargetStops` (0, yes), `HeaderOnlyMatchIsKeptWithAnEmptyPayload` (1 with `payload.empty()`, yes), `TargetOffsetPastTheEntry` (0, no).
  - `RuleMapperFromEntry.MalformedTarget`: parameterized over NFLOG targets, asserting `!target`. Cases: `TargetRunningPastTheEntry`, `TargetOffsetInsideTheHeader` (the `nflog_target_test` construction that copies the target over the header), `TargetSizeSmallerThanItsHeader`.
  - `RuleMapperFromEntry.HeaderOnlyTargetIsKeptWithAnEmptyPayload`: `target_size = sizeof(xt_entry_target)` → target set, `payload.empty()`.
  - `RuleMapperFromEntry.BrokenMatchStillLeavesTheTarget`: mark + NFLOG, `match_size = 0` → `matches.empty()`, `target->name == "NFLOG"` (Review Focus 3).
  - `RuleMapperFromEntry.NameWithoutTerminatorIsBounded`: match name filled with 29 `'m'` → `name == std::string(29, 'm')` (Review Focus 1).
  - `RuleMapperFromEntry.TargetRevisionIsRead`: target written with revision 3 reads back 3.
- [x] **Step 2: Run them to verify they fail.** `make configure-unit build-unit`. Expected: `mappers/rule_mapper.h` not found.
- [x] **Step 3: Implement `RuleMapper`** with `RuleLayout`'s helpers (`allocateEntry`, `writeMatchHeader`, `writeTargetHeader`, `readMatchHeader`, `readTargetHeader`, `matchPayload`, `targetPayload`, `bytesOf`). Add a revision parameter to `writeTargetHeader`, and make `readTargetHeader` report `u.user.revision`. Move the two layout diagrams (`LEARN`) from `mark_match.cpp` and `nflog_target.cpp` to `fromEntry`; in Task 6 they become the only copies.
- [x] **Step 4: Run them to verify they pass.** Gtest filter `RuleMapper`. Expected: all pass; the whole `make test-unit` stays green.
- [x] **Step 5: Commit** (checkpoint): `feat(adapter_iptc): RuleMapper between RuleParam and ipt_entry`

### Task 4: Per-extension mappers

**Files:**
- Create in `adapter_iptc/include/adapter_iptc/mappers/` and `adapter_iptc/src/mappers/`: `mark_mapper`, `tcp_mapper`, `udp_mapper`, `conntrack_mapper`, `hashlimit_mapper`, `nflog_mapper`, `verdict_mapper` (`.h` + `.cpp` each)
- Test: `adapter_iptc/test/match_mapper_test.cpp`, `adapter_iptc/test/target_mapper_test.cpp`

**Interfaces:**
- Consumes: `PayloadMapper`/`PayloadIdentity` (Task 2); DTOs and enums (Task 1).
- Produces (all `[[nodiscard]] static`):
  - `MarkMapper::toExtension(MarkParam) -> ExtensionParam` (mask `0xffffffff`); `MarkMapper::toExtension(MaskedMark) -> ExtensionParam`; `MarkMapper::fromRule(const RuleParam&) -> std::optional<MarkParam>`.
  - `TcpMapper::toExtension(PortRange) -> ExtensionParam`; `UdpMapper::toExtension(PortRange) -> ExtensionParam`. The single-port overloads go away: a port is `{p, p}`.
  - `ConntrackMapper::toExtension(ConntrackState) -> ExtensionParam`.
  - `HashlimitMapper::toExtension(const HashlimitParam&) -> ExtensionParam`.
  - `NflogMapper::toExtension(const NflogParam&) -> ExtensionParam`; `NflogMapper::fromRule(const RuleParam&) -> std::optional<NflogParam>` (reads `rule.target`).
  - `VerdictMapper::toExtension(Verdict) -> ExtensionParam`; payload struct `StandardVerdict { int verdict; }`, identity `""`, revision 0.
- Identities, specialized in each `.cpp`: `xt_mark_mtinfo1` `"mark"`/1, `xt_tcp` `"tcp"`/0, `xt_udp` `"udp"`/0, `xt_conntrack_mtinfo3` `"conntrack"`/3, `xt_hashlimit_mtinfo1` `"hashlimit"`/1, `xt_nflog_info` `"NFLOG"`/0, `StandardVerdict` `""`/0.
- Translations move verbatim from the old `fillData`/`read`: hashlimit `mode` 0 → `SIP|DIP|DPT`, `cfg` fields (keep the uncommitted `LEARN` on `cfg`); conntrack `resolve()`; `Verdict` → `-NF_ACCEPT-1`, `-NF_DROP-1`, `XT_RETURN`; NFLOG prefix cut on a UTF-8 boundary within 63 bytes, `range` → `len` + `XT_NFLOG_F_COPY_LEN`, threshold. `fromRule` rules: mark takes the first match that `fromExtension<xt_mark_mtinfo1>` decodes, then `nullopt` if `mask != 0xffffffff` or `invert != 0`; NFLOG reads prefix with `strnlen` over the field, `range` only with the flag, threshold `XT_NFLOG_DEFAULT_THRESHOLD` → unset. Helper methods that are free functions today (`prefixBytesThatFit`, `isUtf8Continuation`) become private static members of `NflogMapper`.

- [x] **Step 1: Write the failing tests.** Tests that need a payload the mappers never write (inverted mark, flags 0, a full 64-byte prefix) build the `ExtensionParam` by hand with a test-only `extensionOf(name, revision, const T&)` helper that `memcpy`s the struct. Port each case from the old files with its values:
  - `match_mapper_test.cpp`:
    - `MatchIdentityTest` (parameterized: name, revision, `payload.size()` for each of the five matches);
    - `MarkMapperTest.StoresMarkAndMask` (plain → mask `0xffffffff`; `MaskedMark{0x1234, 0xff00}`);
    - `PortMapperTest.WritesDestinationBoundsAndEverySourcePort` (`spts {0, 65535}`, `dpts` from the range; tcp and udp);
    - `ConntrackMapperTest.WritesFlagsAndStateBits` (the three `ConntrackStateCase`s);
    - `HashlimitMapperTest.WriteFillsNamedRateConfigWithDefaults` and `HashlimitMapperTest.ExplicitModeIsWrittenVerbatim`;
    - `MarkFromRuleTest` (parameterized, the `MARK_DECODED_CASES` and the semantic `MARK_REJECTED_CASES`: no mark, no matches, partial mask, inverted, other revision, payload too small, name not `"mark"`). The buffer-level cases (zero size, running into the target, target offset past the entry) live in Task 3.
  - `target_mapper_test.cpp`:
    - `VerdictMapperTest.WritesTheKernelVerdict` (three cases, name `""`, `payload.size() == sizeof(int)`);
    - `NflogMapperTest` identity and `WritesEveryKnobIntoTheKernelInfo`;
    - `NflogPrefixTest.KeepsWholeCharactersWithinTheKernelBudget` (move the cases and helpers from `nflog_target_test.cpp`);
    - `NflogFromRuleTest` (the `NFLOG_DECODED_CASES`, plus rejected: target is a standard verdict, name `"NFQUEUE"`, no target, payload too small).
- [x] **Step 2: Run them to verify they fail.** `make configure-unit build-unit`. Expected: mapper headers not found.
- [x] **Step 3: Implement the seven mappers.** Each `.cpp` holds its `PayloadIdentity` specialization and the `LEARN` comments moved with its code.
- [x] **Step 4: Run them to verify they pass.** Gtest filters `Match`, `Mark`, `Port`, `Conntrack`, `Hashlimit`, `Verdict`, `Nflog`. Expected: all pass; `make test-unit` green, old tests included.
- [x] **Step 5: Commit** (checkpoint): `feat(adapter_iptc): stateless mappers per extension`

### Task 5: Switch the boundary to `RuleParam`

**Files:**
- Modify: `include/adapter_iptc/i_iptc_builder.h`, `include/adapter_iptc/builder/rule_builder.h`, `src/builder/rule_builder.cpp`
- Modify: `include/adapter_iptc/i_iptc_helper.h`, `include/adapter_iptc/adapters/iptc_helper.h`, `src/adapters/iptc_helper.cpp`, `include/adapter_iptc/mocks/mock_iptc_helper.h`
- Modify: `src/adapters/mangle_adapter.cpp`, `include/adapter_iptc/adapters/mangle_adapter.h` (includes only)
- Test: rewrite `test/rule_builder_test.cpp`; migrate `test/mangle_adapter_test.cpp` and `test/kernel/mangle_kernel_test.cpp`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `IBuilder::build() const -> RuleParam`.
  - `RuleBuilder& setProtocol(uint8_t protocol); RuleBuilder& addMatch(ExtensionParam match); RuleBuilder& setTarget(ExtensionParam target); [[nodiscard]] RuleParam build() const override;`. `build()` throws `std::invalid_argument` without a target. `resolveProtocol()` goes away; the protocol `TODO` moves above `setProtocol`, rewritten so it no longer names `resolveProtocol`/`protocol()` but keeps the kernel requirement, the `EINVAL`-at-commit consequence and the `RuleBody` plan.
  - `IIptcHelper::appendRule(const RuleParam& rule)` replaces `appendEntry`; `IIptcHelper::listRules() -> std::vector<RuleParam>` replaces `listEntries`, with the same throw on a missing chain (`ENOENT`) and the same `LEARN`. `IptcHelper::appendRule` calls `RuleMapper::toEntry`; `listRules` calls `RuleMapper::fromEntry` on each libiptc rule; `copyOf` goes away.
  - `MockIptcHelper`: `MOCK_METHOD1(appendRule, void(const RuleParam& rule)); MOCK_METHOD0(listRules, std::vector<RuleParam>());`.
  - `MangleAdapter`: conntrack rule = `addMatch(MarkMapper::toExtension(mark))`, `addMatch(ConntrackMapper::toExtension(conntrack.state))`, `setTarget(VerdictMapper::toExtension(Verdict::ACCEPT))`. NFLOG rule = mark match + `NflogMapper::toExtension(nflog)`. `readNflogRules` uses `NflogMapper::fromRule` and `MarkMapper::fromRule`.

- [x] **Step 1: Rewrite the builder tests** in `rule_builder_test.cpp`:
  - `RuleBuilderTest.MatchesKeepInsertionOrder`;
  - `RuleBuilderTest.TargetIsTheOneSet` (the last `setTarget` wins);
  - `RuleBuilderTest.ProtocolIsTheOneSet` (default 0; `setProtocol(IPPROTO_TCP)` → 6);
  - `RuleBuilderTest.BuildWithoutTargetThrows` (Review Focus 4).

  The offset and layout tests already live in `rule_mapper_test.cpp` (Task 3); delete them here.
- [x] **Step 2: Migrate `mangle_adapter_test.cpp`.** Expectations capture the `RuleParam` given to `appendRule` and compare it with one built from the mappers (`AddConntrackRule…` expects matches `[mark, conntrack NEW]` and the ACCEPT verdict target). `WhatAddNflogRuleAppendsReadsBackUnchanged` stores the captured `RuleParam`s and returns them from `listRules`. The `MangleAdapterReadNflogTest` cases build `RuleParam`s with the mappers. `firstMatch`, `targetOf` and `copyOf` go away.
- [x] **Step 3: Migrate `mangle_kernel_test.cpp`.** `appendEntry`/`listEntries` → `appendRule`/`listRules`; `UnknownTarget` → `ExtensionParam{.name = "BBNOSUCHTARGET", .revision = 0, .payload = std::vector<unsigned char>(4, 0)}`; `NflogRuleWithoutMarkReadsBackWithoutMark` builds with `RuleBuilder().setTarget(NflogMapper::toExtension(fullNflog())).build()`.
- [x] **Step 4: Run to verify the build fails** (the tests use the new API). `make build-unit`. Expected: errors on `appendRule`/`addMatch`.
- [x] **Step 5: Switch `RuleBuilder`, `IIptcHelper`, `IptcHelper`, `MockIptcHelper`, `MangleAdapter`** to the interfaces above. Update the `LEARN` in `ipt_entry_ptr.h`: the owners are now `RuleMapper::toEntry()` and the copies `IptcHelper` makes internally, no longer `RuleBuilder::build()`/`listEntries()`.
- [x] **Step 6: Run the unit and kernel tiers.** `make rebuild-unit && make test-unit`. Expected: green, kernel tests included (`ReadSkipsRulesThatAreNotNflog`, `KernelRejectionThrowsWithErrnoAndChangesNothing`, `NflogRuleWithoutMarkReadsBackWithoutMark` are the ones that exercise the new path against the kernel). A skipped kernel tier (no namespace) is not a pass for this task; say so and run it where it can execute.
- [x] **Step 7: Commit** (checkpoint): `refactor(adapter_iptc): IIptcHelper and RuleBuilder speak RuleParam`

### Task 6: Delete the old hierarchy, fold `RuleLayout` into `RuleMapper`

**Files:**
- Delete: `include/adapter_iptc/template_match.h`, `src/matchs/template_match.cpp`, `include/adapter_iptc/targets/extension_target_template.h`, `src/targets/extension_target_template.cpp`, `include/adapter_iptc/i_target_strategy.h`, all of `include/adapter_iptc/matchs/`, `src/matchs/`, `include/adapter_iptc/targets/`, `src/targets/`, `include/adapter_iptc/mocks/mock_template_match.h`, `mock_target_strategy.h`, `mock_builder.h`, `include/adapter_iptc/rule_layout.h`, `src/rule_layout.cpp`, `test/match_test.cpp`, `test/target_test.cpp`, `test/nflog_target_test.cpp`
- Create: `adapter_iptc/test/iptc_exception_test.cpp` (the two `IptcExceptionTest` cases, moved out of `nflog_target_test.cpp` unchanged)
- Modify: `include/adapter_iptc/mappers/rule_mapper.h`, `src/mappers/rule_mapper.cpp`
- Rationale: [docs/adapter-iptc-hierarchy-removal.md](../../adapter-iptc-hierarchy-removal.md) (what each hook of the hierarchy becomes, the boundary before and after).
- Modify: `docs/adapter-iptc-rule-mapper.md`, `docs/adapter-iptc-hierarchy-removal.md` and `docs/adapter-iptc-payload-mapper.md` (status), `CLAUDE.md` (Components diagram names `MangleAdapter (adapter_iptc)`; check for stale class names)

**Interfaces:**
- Consumes: everything above; nothing outside `adapter_iptc` uses the deleted files (verify in Step 1).
- Produces: `RuleMapper`'s public surface unchanged. `RuleLayout`'s functions become private static members of `RuleMapper`, `ExtensionHeader` becomes a private nested struct, and the `NOLINT` blocks and `LEARN` comments move with them.

- [x] **Step 1: Check nothing else uses the files to delete.** `grep -rnE 'template_match|extension_target_template|i_target_strategy|matchs/|targets/|rule_layout|mock_builder|MockBuilder|TemplateMatch|ITargetStrategy|RuleLayout' --include=*.h --include=*.cpp --include=CMakeLists.txt .` from the repo root. Expected: hits only in the files this task deletes or edits.
- [x] **Step 2: Delete the files, create `iptc_exception_test.cpp`, fold `RuleLayout` into `RuleMapper`.**
- [x] **Step 3: Verify the confinement goal.** `grep -rln 'rule_mapper.h\|ipt_entry_ptr.h' adapter_iptc/include adapter_iptc/src` lists only `rule_mapper.h`/`.cpp` and `iptc_helper.cpp` (the `ipt_entry_ptr.h` hit in `rule_mapper.h` is expected). `grep -rn 'ipt_entry' adapter_iptc/include` hits only `rule_mapper.h` and `ipt_entry_ptr.h`.
- [x] **Step 4: Run the full gate** (Global Constraints). Expected: every stage passes. Compare the `adapter_iptc_tests` count with Task 5's run: the drop must match the deleted buffer-level cases that Tasks 3–4 re-homed. List any case that was not re-homed.
- [x] **Step 5: Update the docs.** In `docs/adapter-iptc-rule-mapper.md` set the status to `accepted 2026-11-15, implemented <date>`, naming the main files and tests as `socket-endpoint.md` does. In `CLAUDE.md`, fix any `adapter_iptc` class names that no longer exist.
- [ ] **Step 6: Commit** (checkpoint): `refactor(adapter_iptc): drop the self-serializing matches, RuleLayout folds into RuleMapper`
