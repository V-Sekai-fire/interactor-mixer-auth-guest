// MIT.
#include "mixer_auth.h"
#include <string.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static mbedtls_hmac_drbg_context g_rng;
static int g_ready;

int ma_init(const uint8_t entropy[32]) {
	mbedtls_hmac_drbg_init(&g_rng);
	g_ready = mbedtls_hmac_drbg_seed_buf(&g_rng, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), entropy, 32) == 0;
	return g_ready;
}

void ma_sha256(const uint8_t *data, size_t len, uint8_t out[32]) { mbedtls_sha256(data, len, out, 0); }

int ma_keygen(const uint8_t seed[32], uint8_t priv[MA_PRIV_LEN], uint8_t pub[MA_PUB_LEN]) {
	if (!g_ready) return 0;
	mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point q;
	mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_ecp_point_init(&q);
	size_t n = 0;
	int ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0
		&& mbedtls_mpi_read_binary(&d, seed, 32) == 0
		&& mbedtls_ecp_check_privkey(&grp, &d) == 0 /* 1 <= d < n */
		&& mbedtls_ecp_mul(&grp, &q, &d, &grp.G, mbedtls_hmac_drbg_random, &g_rng) == 0
		&& mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, pub, MA_PUB_LEN) == 0
		&& n == MA_PUB_LEN;
	if (ok) memcpy(priv, seed, MA_PRIV_LEN); else memset(priv, 0, MA_PRIV_LEN);
	mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&q);
	return ok;
}

void ma_thumbprint(const uint8_t pub[MA_PUB_LEN], uint8_t out[32]) { ma_sha256(pub, MA_PUB_LEN, out); }

int ma_sign_hash(const uint8_t priv[MA_PRIV_LEN], const uint8_t hash[32], uint8_t sig[MA_SIG_LEN]) {
	if (!g_ready) return 0;
	mbedtls_ecp_group grp; mbedtls_mpi d, r, s;
	mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
	int ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0
		&& mbedtls_mpi_read_binary(&d, priv, MA_PRIV_LEN) == 0
		&& mbedtls_ecp_check_privkey(&grp, &d) == 0
		&& mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash, 32, MBEDTLS_MD_SHA256, mbedtls_hmac_drbg_random, &g_rng) == 0
		&& mbedtls_mpi_write_binary(&r, sig, 32) == 0
		&& mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0;
	mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
	return ok;
}

int ma_sign(const uint8_t priv[MA_PRIV_LEN], const uint8_t *room, size_t room_len,
		const uint8_t nonce[MA_NONCE_LEN], uint8_t sig[MA_SIG_LEN]) {
	if (room_len > 0xFFFF) return 0;
	static const uint8_t tag[] = "mixer-relay-v1";
	mbedtls_sha256_context c;
	mbedtls_sha256_init(&c);
	uint8_t len[2] = { (uint8_t)(room_len >> 8), (uint8_t)room_len };
	uint8_t digest[32];
	int ok = mbedtls_sha256_starts(&c, 0) == 0
		&& mbedtls_sha256_update(&c, tag, sizeof tag - 1) == 0
		&& mbedtls_sha256_update(&c, len, 2) == 0
		&& (room_len == 0 || mbedtls_sha256_update(&c, room, room_len) == 0)
		&& mbedtls_sha256_update(&c, nonce, MA_NONCE_LEN) == 0
		&& mbedtls_sha256_finish(&c, digest) == 0;
	mbedtls_sha256_free(&c);
	return ok && ma_sign_hash(priv, digest, sig);
}
