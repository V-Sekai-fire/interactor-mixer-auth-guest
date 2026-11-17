// MIT. The sandbox guest around src/mixer_auth.c: the host calls these by name (Sandbox.vmcall), passing and getting
// back PackedByteArray. Nothing here keeps a key: the host holds the private key between calls, as the relay's
// client does, so a guest restart loses nothing.
#include <api.hpp>

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "../src/mixer_auth.h"
}

static Variant bytes(const uint8_t *p, size_t n) {
	PackedArray<uint8_t> a(p, n);
	return Variant(a);
}

// auth_init(entropy[32]) -> 1 or 0. Call once per instance, with 32 fresh random bytes from the host.
static Variant auth_init(PackedByteArray entropy) {
	std::vector<uint8_t> e = entropy.fetch();
	if (e.size() != 32) {
		return Variant(int64_t(0));
	}
	return Variant(int64_t(ma_init(e.data())));
}

// auth_keygen(seed[32]) -> priv[32] || pub[65], or empty when the seed is not a valid scalar (draw again).
static Variant auth_keygen(PackedByteArray seed) {
	std::vector<uint8_t> s = seed.fetch();
	uint8_t out[MA_PRIV_LEN + MA_PUB_LEN];
	if (s.size() != 32 || !ma_keygen(s.data(), out, out + MA_PRIV_LEN)) {
		return bytes(nullptr, 0);
	}
	return bytes(out, sizeof out);
}

// auth_thumbprint(pub[65]) -> sha256(pub)[32], or empty.
static Variant auth_thumbprint(PackedByteArray pub) {
	std::vector<uint8_t> p = pub.fetch();
	if (p.size() != MA_PUB_LEN) {
		return bytes(nullptr, 0);
	}
	uint8_t out[32];
	ma_thumbprint(p.data(), out);
	return bytes(out, sizeof out);
}

// auth_sign(priv[32], room, nonce[32]) -> r || s [64], or empty.
static Variant auth_sign(PackedByteArray priv, String room, PackedByteArray nonce) {
	std::vector<uint8_t> k = priv.fetch(), n = nonce.fetch();
	std::string r = room.utf8();
	uint8_t sig[MA_SIG_LEN];
	if (k.size() != MA_PRIV_LEN || n.size() != MA_NONCE_LEN ||
			!ma_sign(k.data(), reinterpret_cast<const uint8_t *>(r.data()), r.size(), n.data(), sig)) {
		return bytes(nullptr, 0);
	}
	return bytes(sig, sizeof sig);
}

int main() {
	ADD_API_FUNCTION(auth_init, "int", "PackedByteArray entropy", "Seed the blinding RNG once per instance");
	ADD_API_FUNCTION(auth_keygen, "PackedByteArray", "PackedByteArray seed", "priv[32] || pub[65] from 32 random bytes");
	ADD_API_FUNCTION(auth_thumbprint, "PackedByteArray", "PackedByteArray pub", "SHA-256 of the 65-byte public key");
	ADD_API_FUNCTION(auth_sign, "PackedByteArray", "PackedByteArray priv, String room, PackedByteArray nonce",
			"ECDSA P-256 proof over the relay's message, r || s");
	fast_exit();
}
