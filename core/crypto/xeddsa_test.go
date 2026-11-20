package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/kabili207/meshtastic-go/core/proto"
)

// These vectors were produced by compiling the exact XEdDSA implementation the firmware
// links against (github.com/meshtastic/Crypto at 591ff9a, the library named in
// variants/*/*.ini) and signing with a fixed nonce so the result is reproducible. They
// pin the Go port to the C byte for byte, including the conditional scalar negation:
// case 0 leaves the scalar alone, the rest negate it.
var xeddsaVectors = []struct {
	curvePrivate string
	edPublic     string
	random       string
	message      string
	signature    string
}{
	{
		curvePrivate: "0004070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e",
		edPublic:     "40be61ab73f5c85c42c36728a4a4a3d4aff507262f4d5616eb5fe708fb268434",
		random:       "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
		message:      "00",
		signature:    "3a0a1e448e30183f95b8a1f81c108b1480991110c69b7571f9af5b9c3801b043eb5ccdc1804f32ab636d05424ace391e7c190fab65d5259d75e241db2efe6d09",
	},
	{
		curvePrivate: "081014181c2024282c3034383c4044484c5054585c6064686c7074787c808448",
		edPublic:     "76dd052a509544c8f237b09c2597f70b0c3dc2b51f8776a9935895765cb11974",
		random:       "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
		message:      "01060b10151a1f24292e",
		signature:    "525e8a546cd9694103ed1c3ec08960ea8a4bfc5477db47e7d606529765f209b36b0ce61acfc09a409820ceb7ee79d2eb31dd316c8a53f4c1d775d19664308500",
	},
	{
		curvePrivate: "101c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8ad72",
		edPublic:     "a160614b370033624b53cb345193676d462434bd40d928fdb94a01c41e89be71",
		random:       "a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1",
		message:      "02070c11161b20252a2f34393e43484d52575c",
		signature:    "efb1486409a7b02da8742b73c4ca12417166eea9e8205a90c7611e4ae134e7023df3b0a83ea9fe1504411e85cfbe08a3e9988cf08fcd4facbbe88b19edef1b0a",
	},
	{
		curvePrivate: "20282e343a40464c52585e646a70767c82888e949aa0a6acb2b8bec4cad0d65c",
		edPublic:     "9fb3ca2fe2e13fd1abfd32b3ec58f3dd225b2b0d47622d52c899f091c8f0ee7b",
		random:       "a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2",
		message:      "03080d12171c21262b30353a3f44494e53585d62676c71767b80858a",
		signature:    "609dff2da35bfa479dd0ac0f5a2737a75cf50f516e9a4fff2d90524361c2c1bf65e29c7029dc393f798fdf33551b040cb0cea21608ecc7c1d78a50141f56980e",
	},
	{
		curvePrivate: "28343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff46",
		edPublic:     "d19eb0c437a39c7f120d595e25cccc64d30f1773ef8bbbcf3bef304c06f4907e",
		random:       "a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3",
		message:      "04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8",
		signature:    "9fa47aba0cb55233144c6e362056916aa629ff3258905d5ad7f0d1b600176f263238111cc72881cdf7c430b06fdb7934fbed7b698a90b2919f1dea21c49ced05",
	},
	{
		curvePrivate: "38404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f800081018202870",
		edPublic:     "69fa9c517f1bcc47f0443203ddeda21893dad33c153e60ac17fafdb5af399b38",
		random:       "a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4",
		message:      "050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6",
		signature:    "11ae40889027b8b965c05d7cef8dc940dedbcb716f11c8c85214237dd2327388eb9ebcbb3ea292c47013e4c0deda7e19c4d7d2d5fa6e17dc7a6dc42d45b61201",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture %q: %v", s, err)
	}
	return b
}

func TestSignXEdDSAMatchesFirmware(t *testing.T) {
	for i, v := range xeddsaVectors {
		priv := mustHex(t, v.curvePrivate)
		msg := mustHex(t, v.message)
		random := mustHex(t, v.random)
		want := mustHex(t, v.signature)

		got, err := signXEdDSA(priv, msg, random)
		if err != nil {
			t.Fatalf("case %d: signXEdDSA: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("case %d: signature = %x, want %x", i, got, want)
		}
	}
}

// The scalar path and the public-key path must land on the same Ed25519 key, or a
// signer and a verifier would disagree about who signed.
func TestDeriveEd25519KeyMatchesFirmware(t *testing.T) {
	for i, v := range xeddsaVectors {
		priv := mustHex(t, v.curvePrivate)
		want := mustHex(t, v.edPublic)

		_, _, got := deriveEd25519Key(priv)
		if !bytes.Equal(got, want) {
			t.Errorf("case %d: derived public key = %x, want %x", i, got, want)
		}
		if got[31]&0x80 != 0 {
			t.Errorf("case %d: derived public key has a non-zero sign bit", i)
		}
	}
}

func TestVerifyXEdDSAAcceptsFirmwareSignatures(t *testing.T) {
	for i, v := range xeddsaVectors {
		priv := mustHex(t, v.curvePrivate)
		msg := mustHex(t, v.message)
		sig := mustHex(t, v.signature)

		pub, err := PublicKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !VerifyXEdDSA(pub, msg, sig) {
			t.Errorf("case %d: rejected a signature the firmware produced", i)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := mustHex(t, xeddsaVectors[1].curvePrivate)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the quick brown fox")

	sig, err := SignXEdDSA(priv, msg)
	if err != nil {
		t.Fatalf("SignXEdDSA: %v", err)
	}
	if len(sig) != XEdDSASignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), XEdDSASignatureSize)
	}
	if !VerifyXEdDSA(pub, msg, sig) {
		t.Error("a freshly produced signature did not verify")
	}
}

// Signing is randomized on purpose, so the same message must not produce the same bytes.
func TestSignXEdDSAIsRandomized(t *testing.T) {
	priv := mustHex(t, xeddsaVectors[1].curvePrivate)
	msg := []byte("same message")

	first, err := SignXEdDSA(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignXEdDSA(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Error("two signatures over the same message were identical")
	}
}

func TestVerifyXEdDSARejects(t *testing.T) {
	priv := mustHex(t, xeddsaVectors[2].curvePrivate)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("authentic message")
	sig, err := SignXEdDSA(priv, msg)
	if err != nil {
		t.Fatal(err)
	}

	otherPriv := mustHex(t, xeddsaVectors[3].curvePrivate)
	otherPub, err := PublicKeyFromPrivate(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	flippedSig := bytes.Clone(sig)
	flippedSig[0] ^= 0x01
	flippedS := bytes.Clone(sig)
	flippedS[63] ^= 0x01

	tests := []struct {
		name string
		pub  []byte
		msg  []byte
		sig  []byte
	}{
		{"tampered message", pub, []byte("authentic messagf"), sig},
		{"truncated message", pub, msg[:len(msg)-1], sig},
		{"wrong signer", otherPub, msg, sig},
		{"flipped bit in R", pub, msg, flippedSig},
		{"flipped bit in s", pub, msg, flippedS},
		{"short signature", pub, msg, sig[:63]},
		{"long signature", pub, msg, append(bytes.Clone(sig), 0)},
		{"empty signature", pub, msg, nil},
		{"short public key", pub[:31], msg, sig},
		{"nil public key", nil, msg, sig},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyXEdDSA(tt.pub, tt.msg, tt.sig) {
				t.Error("accepted a signature it should have rejected")
			}
		})
	}
}

func TestPublicKeyToEd25519RejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		if _, err := PublicKeyToEd25519(make([]byte, size)); err == nil {
			t.Errorf("%d-byte key: expected an error", size)
		}
	}
}

// The converted key must be usable by the standard library, since that is what
// VerifyXEdDSA delegates to.
func TestPublicKeyToEd25519ProducesAUsableKey(t *testing.T) {
	priv := mustHex(t, xeddsaVectors[4].curvePrivate)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	edPub, err := PublicKeyToEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(edPub) != ed25519.PublicKeySize {
		t.Fatalf("converted key is %d bytes, want %d", len(edPub), ed25519.PublicKeySize)
	}

	msg := []byte("checked with the standard library")
	sig, err := SignXEdDSA(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(edPub, msg, sig) {
		t.Error("crypto/ed25519 rejected a signature we produced")
	}
}

func TestSignXEdDSARejectsWrongLengthKey(t *testing.T) {
	if _, err := SignXEdDSA(make([]byte, 31), []byte("x")); err == nil {
		t.Error("expected an error for a 31-byte private key")
	}
}

// These buffers come from compiling firmware v2.8.2's buildSigningBuffer
// (CryptoEngine.cpp) against its generated nanopb types and dumping the output. The
// XEdDSA primitive over a buffer is cross-checked separately above.
func TestPacketSigningBufferMatchesFirmware(t *testing.T) {
	tests := []struct {
		name         string
		from, id, to uint32
		data         *pb.Data
		want         string
	}{
		{
			name: "plain broadcast",
			from: 0xA1B2C3D4, id: 0x0F1E2D3C, to: 0xFFFFFFFF,
			data: &pb.Data{Portnum: pb.PortNum_TEXT_MESSAGE_APP, Payload: []byte("hello mesh")},
			want: "01d4c3b2a13c2d1e0fffffffff01000000000000000000000000000000000000000068656c6c6f206d657368",
		},
		{
			name: "every covered field set",
			from: 0xA1B2C3D4, id: 0x0F1E2D3C, to: 0x12345678,
			data: &pb.Data{
				Portnum:      pb.PortNum_NODEINFO_APP,
				Payload:      []byte("\x0a\x09!a1b2c3d4"),
				WantResponse: true,
				RequestId:    0x11223344,
				ReplyId:      0x55667788,
				Emoji:        0x1F600,
				Bitfield:     proto.Uint32(7),
			},
			want: "01d4c3b2a13c2d1e0f7856341204000000443322118877665500f6010007000000030a09216131623263336434",
		},
		{
			name: "empty payload, bitfield present but zero",
			from: 1, id: 2, to: 3,
			data: &pb.Data{Portnum: pb.PortNum_POSITION_APP, Bitfield: proto.Uint32(0)},
			want: "01010000000200000003000000030000000000000000000000000000000000000002",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packetSigningBuffer(tt.from, tt.id, tt.to, tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, tt.want); !bytes.Equal(got, want) {
				t.Errorf("packetSigningBuffer =\n%x, want\n%x", got, want)
			}
		})
	}
}

// Firmware's buffer holds at most DATA_PAYLOAD_LEN payload bytes, the most a Data can
// carry off the wire.
func TestPacketSigningBufferPayloadLimit(t *testing.T) {
	max := int(pb.Constants_DATA_PAYLOAD_LEN)
	buf, err := packetSigningBuffer(1, 2, 3, &pb.Data{Payload: make([]byte, max)})
	if err != nil || len(buf) != 267 {
		t.Errorf("at the limit: len %d, err %v; want 267, nil", len(buf), err)
	}
	if _, err := packetSigningBuffer(1, 2, 3, &pb.Data{Payload: make([]byte, max+1)}); err == nil {
		t.Error("expected an error one byte over the limit")
	}
}

// Every covered field must invalidate the signature when changed on its own.
func TestVerifyPacketDataRejectsAlteredMetadata(t *testing.T) {
	const (
		from     = uint32(0x1234ABCD)
		packetID = uint32(0x55667788)
		to       = uint32(0xFFFFFFFF)
	)
	signed := func() *pb.Data {
		return &pb.Data{
			Portnum:   pb.PortNum_TEXT_MESSAGE_APP,
			Payload:   []byte("original payload"),
			RequestId: 10,
			ReplyId:   20,
			Emoji:     30,
			Bitfield:  proto.Uint32(1),
		}
	}
	priv := mustHex(t, xeddsaVectors[0].curvePrivate)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPacketData(priv, from, packetID, to, signed())
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPacketData(pub, from, packetID, to, signed(), sig) {
		t.Fatal("the unmodified packet did not verify")
	}

	tests := []struct {
		name               string
		from, packetID, to uint32
		alter              func(*pb.Data)
	}{
		{"reattributed to another sender", from + 1, packetID, to, nil},
		{"replayed under a different id", from, packetID + 1, to, nil},
		{"broadcast re-addressed as a DM", from, packetID, 0x12345678, nil},
		{"redirected to another port", from, packetID, to, func(d *pb.Data) { d.Portnum = pb.PortNum_PRIVATE_APP }},
		{"payload altered", from, packetID, to, func(d *pb.Data) { d.Payload = []byte("modified payload") }},
		{"payload truncated", from, packetID, to, func(d *pb.Data) { d.Payload = d.Payload[:len(d.Payload)-1] }},
		{"payload emptied", from, packetID, to, func(d *pb.Data) { d.Payload = nil }},
		{"request_id changed", from, packetID, to, func(d *pb.Data) { d.RequestId++ }},
		{"reply_id changed", from, packetID, to, func(d *pb.Data) { d.ReplyId++ }},
		{"emoji changed", from, packetID, to, func(d *pb.Data) { d.Emoji++ }},
		{"bitfield changed", from, packetID, to, func(d *pb.Data) { d.Bitfield = proto.Uint32(0) }},
		{"bitfield stripped", from, packetID, to, func(d *pb.Data) { d.Bitfield = nil }},
		{"want_response set", from, packetID, to, func(d *pb.Data) { d.WantResponse = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := signed()
			if tt.alter != nil {
				tt.alter(d)
			}
			if VerifyPacketData(pub, tt.from, tt.packetID, tt.to, d, sig) {
				t.Error("accepted a packet whose signed metadata had changed")
			}
		})
	}
}

// A zero-length payload is legitimate, so it must still sign and verify.
func TestSignPacketDataEmptyPayload(t *testing.T) {
	priv := mustHex(t, xeddsaVectors[0].curvePrivate)
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	data := &pb.Data{Portnum: pb.PortNum_NODEINFO_APP}
	sig, err := SignPacketData(priv, 1, 2, 3, data)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPacketData(pub, 1, 2, 3, data, sig) {
		t.Error("an empty payload did not round-trip")
	}
}
