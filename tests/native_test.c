// MIT. Known answers first, then the relay's message format. Prints PASS/FAIL per check; exits nonzero on any FAIL.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/mixer_auth.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

static int failures = 0;
static int unhex(const char *s, uint8_t *out) {
	int n = 0;
	for (; s[0] && s[1]; s += 2) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t)v; }
	return n;
}
static void check(const char *name, int ok) { printf("%s  %s\n", ok ? "PASS" : "FAIL", name); if (!ok) failures++; }
static int same(const uint8_t *a, const char *hex, int n) { uint8_t b[128]; return unhex(hex, b) == n && memcmp(a, b, n) == 0; }

int main(void) {
	uint8_t d[32];
	uint8_t ent[32]; memset(ent, 0x5a, sizeof ent);
	check("init seeds the blinding RNG", ma_init(ent) == 1);
	/* FIPS 180-4 / NIST: "abc" and the 448-bit message (two blocks) and one million 'a' */
	ma_sha256((const uint8_t *)"abc", 3, d);
	check("sha256 abc", same(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32));
	ma_sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
	check("sha256 448-bit message", same(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32));
	{
		uint8_t *a = malloc(1000000); memset(a, 'a', 1000000);
		ma_sha256(a, 1000000, d); free(a);
		check("sha256 one million a", same(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 32));
	}
	/* RFC 6979 A.2.5 key: its public key is a known answer; signatures are judged by verification (see below) */
	uint8_t priv[32], pub[65], seedbad[32] = { 0 };
	unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", priv);
	uint8_t pub2[65];
	check("keygen refuses the zero scalar", ma_keygen(seedbad, priv, pub2) == 0);
	unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", d);
	check("keygen accepts the RFC 6979 key", ma_keygen(d, priv, pub) == 1);
	check("RFC 6979 public key X", same(pub + 1, "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6", 32));
	check("RFC 6979 public key Y", same(pub + 33, "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", 32));
	uint8_t h[32], sig[64];
	ma_sha256((const uint8_t *)"sample", 6, h);
	check("sign returns success", ma_sign_hash(priv, h, sig) == 1);
	/* RFC 6979 A.2.5, SHA-256: the nonce is standard, so the bytes are the RFC's */
	check("RFC 6979 r (sample)", same(sig, "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", 32));
	check("RFC 6979 s (sample)", same(sig + 32, "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", 32));
	ma_sha256((const uint8_t *)"test", 4, h);
	ma_sign_hash(priv, h, sig);
	check("RFC 6979 r (test)", same(sig, "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367", 32));
	check("RFC 6979 s (test)", same(sig + 32, "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083", 32));
	/* the relay's message: deterministic, and it depends on the room and on the nonce */
	uint8_t n1[32], n2[32], s1[64], s2[64], s3[64], s4[64];
	memset(n1, 1, 32); memset(n2, 2, 32);
	check("auth sign ok", ma_sign(priv, (const uint8_t *)"hypo", 4, n1, s1) == 1);
	ma_sign(priv, (const uint8_t *)"hypo", 4, n1, s2);
	ma_sign(priv, (const uint8_t *)"hypo", 4, n2, s3);
	ma_sign(priv, (const uint8_t *)"other", 5, n1, s4);
	check("same inputs, same bytes", memcmp(s1, s2, 64) == 0);
	check("another nonce, another proof", memcmp(s1, s3, 64) != 0);
	check("another room, another proof", memcmp(s1, s4, 64) != 0);
	check("room over 65535 bytes is refused", ma_sign(priv, (const uint8_t *)"x", 70000, n1, s1) == 0);
	uint8_t t1[32];
	ma_thumbprint(pub, t1);
	ma_sha256(pub, 65, h);
	check("thumbprint is SHA-256 of the 65-byte key", memcmp(t1, h, 32) == 0);
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
