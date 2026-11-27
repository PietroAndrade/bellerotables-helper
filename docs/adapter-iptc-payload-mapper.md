# adapter_iptc: PayloadMapper and PayloadIdentity

**Status:** accepted 2026-11-15 (decision 3 of [adapter-iptc-rule-mapper.md](adapter-iptc-rule-mapper.md)),
implemented 2026-11-19 in Task 2 of the [plan](superpowers/plans/2026-11-15-adapter-iptc-rule-mapper.md)
(`payload_mapper.h`, test `payload_mapper_test.cpp`). The
`KernelPayload` concept in the last section was adopted 2026-11-19 in place of the two `static_assert`s.
**Scope:** `adapter_iptc/include/adapter_iptc/mappers/payload_mapper.h`: how one kernel payload struct
(`xt_mark_mtinfo1`, `xt_nflog_info`, ...) becomes the bytes of an `ExtensionParam` and back.

## What it does

```cpp
template <typename Payload>
struct PayloadIdentity;   // declared, never defined

template <typename Payload>
concept KernelPayload = /* trivially copyable, with a PayloadIdentity: last section */;

struct PayloadMapper
{
    template <KernelPayload Payload>
    [[nodiscard]] static ExtensionParam toExtension(const Payload& payload);

    template <KernelPayload Payload>
    [[nodiscard]] static std::optional<Payload> fromExtension(const ExtensionParam& extension);
};
```

- `toExtension` takes the name and revision from `PayloadIdentity<Payload>` and copies `sizeof(Payload)`
  bytes into `payload`.
- `fromExtension` returns `nullopt` unless the name and revision are the trait's and `payload.size() >=
  sizeof(Payload)`; then it copies the first `sizeof(Payload)` bytes into a `Payload`.

The per-extension mappers (`MarkMapper`, `NflogMapper`, ...) build the `xt_*` struct from a domain DTO
and hand it to `PayloadMapper`. Only `PayloadMapper` turns a struct into bytes.

## Why a template and not `void*`

Every extension has its own payload struct, of its own size:

| Mapper | Payload struct |
|--------|----------------|
| `MarkMapper` | `xt_mark_mtinfo1` |
| `TcpMapper` / `UdpMapper` | `xt_tcp` / `xt_udp` |
| `ConntrackMapper` | `xt_conntrack_mtinfo3` |
| `HashlimitMapper` | `xt_hashlimit_mtinfo1` |
| `NflogMapper` | `xt_nflog_info` |
| `VerdictMapper` | `StandardVerdict { int verdict; }` |

The work is the same for all of them; only the type changes. Three ways to write it:

- **One function per struct**: seven copies of the same code. That duplication exists today, in
  `TemplateMatch::fillData` overrides and the two `dataOf` walks.
- **`void*` plus a size**: `toExtension(const void* data, std::size_t size, const char* name, uint8_t
  revision)`. The type is lost at the call: the caller passes the size by hand, and nothing ties a struct to
  its name and revision. `toExtension(&tcp, sizeof(tcp), "udp", 0)` compiles. On read, `memcpy` cannot see
  the type either, so nothing stops copying into a type that cannot be copied as bytes (below).
- **A template** (chosen): the type is the parameter. From it the compiler takes `sizeof(Payload)` and
  `PayloadIdentity<Payload>::NAME` / `REVISION`, at compile time. A `xt_tcp` cannot be mapped under the
  name `"udp"`, because the name is not an argument.

## The name and revision the kernel looks up

"Extension" is netfilter's word, not C++ inheritance. Each match or target is a kernel module (`xt_mark.ko`,
`xt_NFLOG.ko`, ...) registered under a **name** and a **revision**. The kernel reads both from the header in
front of each payload (`xt_entry_match`, `xt_entry_target`) and looks the module up by them; the revision
picks which layout of the payload struct the module expects (`xt_mark_mtinfo1` is revision 1 of `mark`).
That is why `ExtensionParam` carries `name` and `revision` next to `payload`.

`PayloadIdentity` attaches that pair to a struct from outside, by template specialization:

```cpp
// mark_mapper.cpp
template <>
struct PayloadIdentity<xt_mark_mtinfo1>
{
    static constexpr const char* NAME = "mark";
    static constexpr uint8_t REVISION = 1;
};
```

- The kernel struct is untouched: no base class, no vtable, nothing added to a type we do not own.
- **The primary template is declared and never defined.** A struct with no specialization is an incomplete
  type, so `toExtension` on it does not compile, instead of writing an empty name the kernel rejects at
  commit.
- **Specializations live in the `.cpp` of the mapper that owns the struct.** That translation unit is the
  only one that maps it, and `payload_mapper.h` needs no kernel header.
- On read, the identity is a check: an extension with another name or another revision is never decoded
  with this struct, so a revision-0 payload is not read with the revision-1 layout.

## The xt_* structs do not cause a double free

The `xt_*` structs are C aggregates: integers, fixed `char` arrays, unions. They have no destructor and own
no resource, so copying their bytes **is** copying the object, and they pass the check below.

Some hold a pointer, such as `hinfo` in `xt_hashlimit_mtinfo1`. To C++ that is a value like any other. The
helper writes it as zero, the kernel fills it on its side, and nothing in userspace ever frees it.

## The hidden problem with memcpy

`std::memcpy` takes `void*`: it copies bytes and cannot see what type they belong to. Only the bytes of a
type move with it. For a type that **owns** memory, the bytes are not the data.

```cpp
struct Bad
{
    std::string name;
};
```

The bytes of a `std::string` (outside the small-string buffer) are a pointer to the heap, a size and a
capacity. With a template that accepts any `Payload`, this compiles and breaks at runtime:

- **On write**, the kernel receives a userspace heap address instead of the characters.
- **On read**, `memcpy` builds a second `std::string` holding the same heap pointer as the first. Both
  destructors free it: a **double free**. If the first one is gone already, the second reads a dangling
  pointer.

Nothing in the call says so. The template makes it possible, because it accepts every type.

Reading in place has the same root and is undefined behaviour too:
`*reinterpret_cast<const Payload*>(extension.payload.data())` reads a `Payload` that was never created in
that storage, and the vector's storage is not guaranteed to be aligned for one. That is why `fromExtension`
copies into a local `Payload value{}`. `std::bit_cast` does not fit: it needs source and destination of the
same size, and a payload read back is longer than its struct (alignment padding: mark's 12 bytes read back
as 16).

## Why is_trivially_copyable solves it

The standard allows copying an object byte by byte only when its type is **trivially copyable**: no
user-provided copy or move operations and a trivial destructor, so all of its state is its bytes. That is
exactly the condition under which `memcpy` is valid.

```cpp
static_assert(std::is_trivially_copyable_v<Payload>);
```

The assert turns the implicit requirement of `memcpy` into a compile error. `PayloadMapper::toExtension(Bad{})`
no longer compiles. Every `xt_*` struct passes. `payload_mapper.h` states the same check through the
`KernelPayload` concept (last section) instead of the `static_assert`.

The assert is needed because of the template. In a function with a concrete type in its signature it would
be redundant: the reader would see `xt_tcp`. The generality of the template is what creates the need.

What it does **not** check: that the layout is the one the kernel expects (padding, revision, endianness).
That is the job of whoever writes the `PayloadIdentity` specialization, and of each mapper's tests.

## Two gates, joined by a concept

The template has two independent gates:

| Gate | Question it answers | Failure with `static_assert` alone |
|------|---------------------|---------------|
| `PayloadIdentity<Payload>` | Is this type an extension's payload, with a name and revision? | "incomplete type" deep in the body |
| `is_trivially_copyable_v<Payload>` | Can it be copied as bytes? | `static_assert` failure in the body |

Neither covers the other: nothing stops someone from writing `PayloadIdentity<Bad>`, and a trivially copyable
struct may have no identity.

The `KernelPayload` concept (adopted) joins both under one name and moves them into the signature:

```cpp
template <typename Payload>
concept KernelPayload = std::is_trivially_copyable_v<Payload> && requires {
    { PayloadIdentity<Payload>::NAME } -> std::convertible_to<const char*>;
    { PayloadIdentity<Payload>::REVISION } -> std::convertible_to<uint8_t>;
};

struct PayloadMapper
{
    template <KernelPayload Payload>
    [[nodiscard]] static ExtensionParam toExtension(const Payload& payload);

    template <KernelPayload Payload>
    [[nodiscard]] static std::optional<Payload> fromExtension(const ExtensionParam& extension);
};
```

What it improves over the `static_assert`:

- **Where the error shows.** The call site reports "constraints not satisfied for `KernelPayload`" and names
  the clause that failed, instead of an error inside the instantiated body.
- **The requirement is in the interface.** The declaration says what may be passed; the body does not have
  to be read.
- **One gate instead of two**, and a missing identity reads as an unmet constraint, not as an incomplete
  type.
- **It checks the trait's shape**: a specialization whose `NAME` is not a string or whose `REVISION` is not
  an integer fails at the call, not inside `toExtension`.

One rule comes with it: a specialization must be visible before the concept is first checked for that type.
If the concept is checked for `T` and the specialization is declared later, the program is ill-formed with
no diagnostic required (the compiler may keep the earlier `false`). Specializations at the top of each
mapper's `.cpp`, before any call, keep the rule.
