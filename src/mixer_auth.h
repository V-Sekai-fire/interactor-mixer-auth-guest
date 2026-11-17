// MIT. The player's side of the relay's door: a P-256 key, its thumbprint, and a proof over the relay's nonce.
// Plain C over mbedtls, no I/O, so one source builds for the RISC-V guest and for a native test.
#ifndef MIXER_AUTH_H
#define MIXER_AUTH_H
#include <stddef.h>
#include <stdint.h>

#define MA_PRIV_LEN 32
#define MA_PUB_LEN 65 /* 04 || X || Y */
#define MA_NONCE_LEN 32
#define MA_SIG_LEN 64 /* r || s, big-endian: what WebCrypto emits and the relay expects */

/* Seed the blinding RNG once per instance with 32 fresh random bytes from the host. It protects against side
 * channels only: the signature's nonce is RFC 6979's and does not depend on it. Returns 1 on success. */
int ma_init(const uint8_t entropy[32]);

/* Turn 32 fresh random bytes into a key pair. Returns 1, or 0 when the bytes are not a valid scalar
 * (about 2^-32 of draws): the caller draws again. Needs ma_init first. */
int ma_keygen(const uint8_t seed[32], uint8_t priv[MA_PRIV_LEN], uint8_t pub[MA_PUB_LEN]);

/* SHA-256 of the 65-byte public key: what the token's key caveat names. */
void ma_thumbprint(const uint8_t pub[MA_PUB_LEN], uint8_t out[32]);

/* Sign SHA-256("mixer-relay-v1" || u16 be room_len || room || nonce) with ECDSA P-256 and the RFC 6979 nonce
 * (mbedtls_ecdsa_sign_det_ext). Returns 1 on success, 0 when room is longer than 65535 bytes or the key is
 * invalid. Needs ma_init first. */
int ma_sign(const uint8_t priv[MA_PRIV_LEN], const uint8_t *room, size_t room_len,
		const uint8_t nonce[MA_NONCE_LEN], uint8_t sig[MA_SIG_LEN]);

/* The bare primitive over a ready hash, exposed for the RFC 6979 known-answer test. */
int ma_sign_hash(const uint8_t priv[MA_PRIV_LEN], const uint8_t hash[32], uint8_t sig[MA_SIG_LEN]);

/* SHA-256, so callers and tests need not include mbedtls. */
void ma_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
#endif
