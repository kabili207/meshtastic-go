# Meshtastic 2.8 Upgrade Plan

Target: protobufs `v2.8.0` (tagged 2026-08-28), firmware `v2.8.0.47db0e3` (alpha, 2026-08-31).
Current baseline: protobufs `v2.7.26`, submodule at `da60cee`.

Firmware 2.8 is still an alpha. The protobuf tag is stable (no `.proto` changes on
`master` past `v2.8.0`), so the generated bindings are safe to adopt ahead of the
firmware going final. Behavior work that depends on alpha firmware semantics is
sequenced later, so it can be revisited if the alpha shifts.

## Progress

Work is on branch `feature/protobufs-2.8`, branched from `main`.

| Phase | Status |
| --- | --- |
| 1. Protobuf bump | Done |
| 2. Identity from public key | Done |
| 3. XEdDSA signing | Primitives done and cross-checked; policy layer not started |
| 4. Position precision clamping | Done |
| 5. Features and hardening | UDP multicast done; rest not started |

Build, vet, and the full test suite pass against protobufs v2.8.0.

The UDP work was pulled forward after a fleet upgrade to 2.8 exposed the multicast
address change as an outright break. It is done: see "UDP multicast" under phase 5.

Two things turned up during phase 1 that are not in the original plan:

- `truncateToBytes` over-truncated by one rune whenever the byte cut landed exactly on
  a rune boundary, dropping a complete character. Pre-existing, but tightening the long
  name limit to 24 makes it fire far more often, so it is fixed here. It had no test
  coverage at all; `core/name_test.go` now covers both name validators.
- `core/node_id_test.go`, `device/node/node_test.go`, and `transport/client/transport.go`
  are not gofmt-clean, and were already that way before this branch. Left alone.

## Status of findings

Everything below was verified against the protobuf tag and the firmware source,
not against release notes alone. Two things were checked by execution rather than
reading: the trial regeneration and build, and the CRC32 variant.

---

## Blocker: upstream generates non-compiling Go

`admin.proto` adds `message AS3935_config` while `telemetry.proto` already defines
`message AS3935Config`. They are distinct protobuf names, so `protoc` accepts them,
but `protoc-gen-go` mangles both to the Go identifier `AS3935Config` in the same
package:

```
core/proto/telemetry.pb.go:2005:6: AS3935Config redeclared in this block
	core/proto/admin.pb.go:2360:6: other declaration of AS3935Config
```

This is not a consequence of our layout. Upstream sets
`go_package = "github.com/meshtastic/go/generated"` on every file, so the official
`meshtastic/go` bindings collapse into one package and break identically.

### Options

| Option | Cost | Downside |
| --- | --- | --- |
| Patch the proto during generation | Small | Carries a local patch until upstream fixes it |
| Wait for an upstream fix | Zero | Blocks the entire upgrade on someone else |
| Vendor a patched copy of protobufs | Medium | Loses the clean submodule-at-a-tag model |

**Recommendation:** file the issue upstream, and add a patch step to
`core/gen/update_protos.go` that renames the admin message before invoking `protoc`.
Keep it isolated and clearly marked so it can be deleted when upstream lands a fix.
Note that `updateProtobufRepo()` already auto-selects the highest semver tag, so
`go generate` will pick up `v2.8.0` on its own once the collision is handled.

---

## What breaks

### Our build

`MeshPacket.rx_time` and `rx_rssi` gained explicit presence, so the generated Go
types move from `uint32`/`int32` to `*uint32`/`*int32`.

| File | Line | Change |
| --- | --- | --- |
| `device/node/base.go` | 128 | `pkt.RxTime == 0` becomes a nil check; assign `proto.Uint32(...)` |
| `device/node/bridge_send.go` | 91 | Struct literal needs a pointer |
| `device/node/bridge.go` | 380 | Use `GetRxTime()` |
| `device/node/node.go` | 436 | Use `GetRxTime()` |
| `device/node/node_test.go` | 669 | Struct literal needs a pointer |

With those five edits, build, vet, and the full test suite pass against v2.8.0.
This was confirmed by trial regeneration in a scratch copy, not by inspection.

### Downstream consumers of `core/proto`

These do not affect our code but are breaking for anyone importing the generated
package, so the release needs a minor version bump at minimum:

- `HardwareModel` renames: `SENSELORA_RP2040` and `SENSELORA_S3` become
  `MAKERFABS_TRACKER` and `MAKERFABS_RESERVED`; `TRACKER_T1000_E_PRO` becomes
  `MESH_TRACKER_X1`.
- `NodeInfoLite` flattened: `user`, `position`, `device_metrics` removed and
  replaced with inline fields plus satellite maps.
- `TrafficManagementConfig` bool toggles removed in favor of a
  "non-zero implies enabled" convention on the companion integer fields.
- `interdevice.proto` rewritten wholesale.
- `Position.ground_speed` re-documented as km/h rather than m/s. No type change,
  but the meaning of the field moved.

---

## Phase 1 — Protobuf bump

Effort: small. Risk: low. Depends on: AS3935 workaround.

1. Add the AS3935 rename patch to `core/gen/update_protos.go`.
2. Run `go generate ./...` in `core/`, which advances the submodule to `v2.8.0`
   and regenerates `core/proto`.
3. Apply the five `RxTime` fixes from the table above.
4. Change `MaxLongName` in `core/constants.go:19` from `39` to `24`, and update
   the doc comment on `ValidateLongName` in `core/node_id.go:191`.

On the long-name limit: firmware defines `MAX_LONG_NAME_BYTES 24` in
`src/meshUtils.h`. The release notes say "25 bytes," which is the storage width
including the NUL terminator. **The constant is 24, not 25.**

Firmware's `clampLongName()` truncates at byte 24 and then sanitizes UTF-8,
replacing a broken lead byte with `?`. Our `truncateToBytes` cuts on a rune
boundary instead. Both produce valid UTF-8 that firmware accepts unchanged, so
they are compatible without being byte-identical on a name that ends mid-rune.
No change needed beyond the constant.

**Verify:** `go build ./... && go vet ./... && go test ./...` clean across all
modules.

---

## Phase 2 — Node identity from public key

Effort: small. Risk: low. Unblocks phase 3.

Firmware 2.8 derives a node's mesh address from its identity key rather than its
MAC address:

```
my_node_num = crc32Buffer(config.security.public_key.bytes, 32)
```

`crc32Buffer` comes from ErriezCRC32: polynomial `0xEDB88320`, init `0xFFFFFFFF`,
final complement. This was checked by compiling the library against a 32-byte test
vector and comparing to Go:

```
C  (ErriezCRC32):        a10e8695
Go (crc32.ChecksumIEEE): a10e8695
```

So it is plain `crc32.ChecksumIEEE(pubkey[:32])` with no adaptation.

MAC derivation survives only as a pre-keygen bootstrap in `pickNewNodeNum()`, and
is replaced the moment an identity keypair exists.

The binding is enforced on the wire, not just locally: `Router.cpp:710` rejects a
first-contact signed NodeInfo unless `crc32Buffer(user.public_key) == p->from`.

### Work

- Add a derivation helper to `core` alongside `NodeID`, deriving a `NodeID` from a
  32-byte public key.
- Add a verification helper that checks a claimed sender against a carried public
  key. Phase 3 depends on this.
- Callers still supply their own `NodeID`, which stays valid. Only key generation
  and validation paths use the new derivation.

**Verify:** unit test against the C-derived vector above, plus a round-trip
through an existing known keypair.

---

## Phase 3 — XEdDSA packet signing

Effort: large. Risk: medium. Depends on: phase 2.

The single largest piece, and the only change that alters how packets on the air
must be interpreted.

### Signing input

A flat buffer, all little-endian, over the **decoded** payload before encryption:

```
[ from(u32) | packet_id(u32) | portnum(u32) | payload(N) ]
```

Covering the metadata prevents replay, reattribution, and portnum redirection.

### Keys

Derived from the existing Curve25519 identity, so no new key material and no
config migration.

- Signing converts the X25519 private key to Ed25519.
- Verification converts the peer's public key via the RFC 7748 birational map,
  `y = (u - 1) / (u + 1) mod p`, then clears the sign bit unconditionally.
  XEdDSA normalizes the signer's key to sign bit zero, so this is not a lost bit.

Portable to Go with `filippo.io/edwards25519`. Firmware caches the converted key
per peer because the field inversion is expensive; worth mirroring.

### When a sender signs

All three conditions must hold:

- not `pki_encrypted`, and
- `is_licensed` **or** the packet is a broadcast, and
- the signed `Data` still fits the radio payload.

The signature adds exactly 66 bytes: 64 signature + 1 tag byte + 1 length byte.
Firmware asserts this stays exact.

### Receive policy

Implemented in `checkXeddsaReceivePolicy`. The order matters:

1. The inbound `xeddsa_signed` flag is **never trusted**. Clear it, and set it
   only from a verification we perform.
2. A signature field that is neither 0 nor exactly 64 bytes is malformed, so drop
   it. This is deliberate: a crafted partial signature would otherwise fall
   through into the unsigned branch.
3. Verify against authoritative NodeDB keys only, never an opportunistic TOFU
   cache key.
4. First-contact NodeInfo may bootstrap: a signed `NODEINFO_APP` packet
   self-verifies against the key it carries, subject to the phase 2 identity
   binding.

Policy modes, from `Config.SecurityConfig.PacketSignaturePolicy`:

| Mode | Behavior |
| --- | --- |
| `COMPATIBLE` (wire default) | Accept unsigned; still drop malformed |
| `BALANCED` | Drop unsigned only from nodes known to sign, and only for non-PKI broadcasts whose signed encoding would have fit |
| `STRICT` | Drop all unsigned |

### Reference

`test/test_packet_signing/test_main.cpp` in the firmware tree is 2250 lines and
reads as a usable conformance spec. Port its vectors rather than inventing our own.

**Verify:** vectors from the firmware test suite, covering each policy mode, the
malformed-length drop, and the first-contact bootstrap path.

---

## Phase 4 — Position precision clamping

Effort: small. Risk: low. Independent of phases 2 and 3.

New `src/mesh/PositionPrecision.{h,cpp}` in firmware. Position precision is
clamped to 15 bits on any channel whose effective key is publicly decryptable:

```c
#define MAX_POSITION_PRECISION_PUBLIC_KEY 15
```

That is roughly a 700m latitude cell. The stated rationale is CCPA "precise
geolocation," and 15 also matches the existing MQTT map-report ceiling.

The truncation is not a plain mask, and should be ported exactly:

```c
truncated  = coordinateBits & (UINT32_MAX << (32 - precision));
truncated += (1UL << (31 - precision));   // center of cell, not low edge
```

Centering keeps the value stable under GPS jitter. `precision == 0` or `>= 32`
returns the coordinate unchanged.

There is also a channel-selection rule: position goes out on the lowest-indexed
channel with non-zero on-wire precision. If no channel qualifies, position sharing
is off entirely.

### Work

- Add `TruncateCoordinate` to `core/lora`, next to the existing bits/meters table
  in `precision.go`, which stays correct as-is.
- Add the public-channel clamp and the channel-selection helper.

**Verify:** table test over precision 0, 1, 15, 31, 32 and both coordinate signs,
against values computed from the C implementation.

---

## Phase 5 — Feature and hardening work

Effort: medium, and separable. Risk: low. Each item is independent.

### UDP multicast (done)

Firmware 2.8 moved the multicast group from `224.0.0.69` to `239.0.0.69` (PR #8612,
2026-07-25). `224.0.0.0/24` is the IANA local-control block and at least one access
point refused to forward it; `239.0.0.0/8` is the administratively scoped range
application multicast is meant to use. Upstream rejected a transition period: "Might
as well break it for 2.8, as there's already interop issues between 2.7 and 2.8."

Our transport now defaults to the new group. `udp.Config.MulticastIP` overrides it,
and `udp.LegacyMulticastIP` names the old one for anyone still talking to 2.7 nodes.
A mixed network needs one transport per group; joining both was not built.

Firmware's UDP handler also gained ingress gates, since a LAN packet carries no
authenticity of its own. `sanitizeInbound` in the transport mirrors them:

| Gate | Effect |
| --- | --- |
| Only the `encrypted` payload variant is accepted | An already-decoded LAN packet was previously processed as if we had decrypted it |
| `from == 0` dropped | Never a legitimate sender |
| `hop_limit` or `hop_start` above 7 dropped | Not relayable |
| `pki_encrypted` and `public_key` cleared | Only our own decryption may set these |
| `rx_rssi` presence and `rx_snr` cleared | The values belonged to whichever node put the packet on the wire |
| `transport_mechanism` set to multicast UDP | Consumers can tell UDP arrivals apart |

The remaining firmware gate, `from == self`, needs an identity the transport does
not have, so both node pipelines drop it as their step 2, ahead of client dispatch.
That applies to every transport, not only UDP, which is also what firmware does. A
side effect is that our own multicast sends, which the kernel loops back to us,
are now dropped by identity rather than relying on dedup.

`TRANSPORT_UNICAST_UDP = 8` is defined in the proto but nothing in firmware 2.8
sets or reads it. Nothing to do.

### MQTT downlink hardening

Firmware now forces `pki_encrypted = false` on every MQTT downlink, on the grounds
that "only local AES-CCM decryption may establish PKI authentication." It also runs
the signature policy on already-decoded downlinks, since those bypass
`perhapsDecode` entirely, and adds a `shouldDropMqttDownlink` gate covering ignored
nodes, `NODENUM_BROADCAST` as source, and `ignore_mqtt`.

We should not let a broker-supplied `pki_encrypted` flag mean anything. Audit what
our MQTT transport currently does with that field on ingest.

### Region presets in the client handshake

`FromRadio.region_presets = 19` carries a `LoRaRegionPresetMap` so client UIs can
prevent illegal region and preset combinations. The firmware `PhoneAPI` state enum
confirms the ordering:

```
metadata -> STATE_SEND_REGION_PRESETS -> channels -> config -> moduleconfig
```

Our `device/clientapi/server.go` already follows that sequence, so this is a clean
insertion. The source table is `getRegionPresetMap()` at `RadioInterface.cpp:688`.

### MeshBeacon

New `mesh_beacon.proto`, portnum `MESH_BEACON_APP = 37`,
`ModuleConfig.MeshBeaconConfig` with broadcast targets, and
`AdminMessage.MESHBEACON_CONFIG = 16`. Needs an incoming handler and a
`BeaconReceived` event to match the existing typed event set.

### Waypoint geofencing

`Waypoint` gains `geofence_radius`, `bounding_box` (new `BoundingBox` message),
`notify_on_enter`, `notify_on_exit`, and `notify_favorites_only`. Natural fit as
new functional options on `SendWaypoint`.

---

## Wire behavior changes with no direct code impact

Worth knowing, and worth revisiting if we later add routing or relay behavior.

**Channel hash collisions relay opaquely.** A packet whose one-byte channel hash
matches a local channel but fails to decrypt is now forwarded as an opaque relay
rather than dropped, because a collision is indistinguishable from tampering.
`isFromUs` still rejects, keeping forged senders off the ACK path. The companion
fix adds separate dedup on that path, since opaque frames deliberately never enter
`PacketHistory` and previously had no dedup at all. That combination was causing
broadcast storms.

**Implicit ACKs carry provenance.** When a node overhears its own packet
rebroadcast, the local ROUTING ack now carries the relay's `relay_node`,
`rx_rssi`, and `rx_snr`. Phone-facing only, no wire change, but it changes what a
client reads off an ack.

**Licensed rebroadcast tightened.** Licensed nodes now refuse to rebroadcast
packets both *to* and *from* unlicensed users; previously only *from*. Combined
with licensed nodes signing unicasts as well as broadcasts, ham mode is a
meaningfully different routing regime in 2.8.

**PKI nonce hardening.** `encryptCurve25519` moved off `random()` to a hardware
RNG with a seeded-CSPRNG fallback, and fixed a latent bug where the extra nonce
was written before `aes_ccm_ae` overwrote it.

**Defaults moved.** Telemetry and position are now opt-in across the board.
Stationary position broadcast floor went 12h to 6h, and the traffic-management
position dedup window 11h to 5h, deliberately ordered so a stationary node's
refresh is not deduped by its neighbors. New US nodes default to LongTurbo rather
than LongFast on first-time region selection, and the two presets cannot hear each
other.

---

## Sequencing

```
Phase 1  Protobuf bump          (blocked on AS3935 workaround)
Phase 2  Identity derivation    (small, unblocks 3)
Phase 4  Position precision     (small, independent)
Phase 3  XEdDSA                 (large, needs 2)
Phase 5  Features and hardening (separable, any order)
```

Phases 1, 2, and 4 are all small and mutually independent once the AS3935 blocker
clears. They make a reasonable first pass. Phase 3 is the real work and deserves
its own review.

## Open decisions

1. **AS3935 workaround.** Patch in the generation step as recommended, or wait for
   upstream? Waiting blocks everything.
2. **Version bump.** The `core/proto` changes are breaking for downstream
   importers even though our own code survives. Minor bump, or hold 2.8 support on
   a branch until the firmware leaves alpha?
3. **Signing default.** Resolved: `COMPATIBLE`. It is the firmware wire default and
   the enum's zero value, so a zero-valued config field means it without ceremony.
   Callers opt into `BALANCED` or `STRICT`.
