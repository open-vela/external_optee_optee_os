/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, ARM Limited
 * Copyright (C) 2019, Linaro Limited
 */

#ifndef MBED_HELPERS_H
#define MBED_HELPERS_H

#include <crypto/crypto.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <cipher_wrap.h>
#include <tee_api_types.h>

#define MBEDTLS_ECP_DP_SM2 MBEDTLS_ECP_DP_MAX

static inline int mbd_rand(void *rng_state __unused, unsigned char *output,
			size_t len)
{
	if (crypto_rng_read(output, len))
		return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	return 0;
}

static inline void mbed_copy_mbedtls_aes_context(mbedtls_aes_context *dst,
						 mbedtls_aes_context *src)
{
	*dst = *src;
#if !defined(MBEDTLS_AES_ALT)
#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_PADLOCK_ALIGN16)
	/*
	 * This build configuration should not occur, but just in case error out
	 * here. It needs special handling of the rk pointer, see
	 * mbedtls_aes_setkey_enc().
	 */
#error Do not know how to copy mbedtls_aes_context::rk
#endif
	dst->rk_offset = 0;
#endif
}

TEE_Result mbed_gen_random_upto(mbedtls_mpi *n, mbedtls_mpi *max);

/**
 * \brief           Clone the state of an cipher context
 *
 * \note            The two contexts must have been setup to the same type
 *                  (cloning from AES to DES make no sense).
 *
 * \param dst       The destination context
 * \param src       The context to be cloned
 *
 * \return          \c 0 on success,
 *                  \c MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on parameter failure.
 */
int mbedtls_cipher_clone(mbedtls_cipher_context_t *dst,
                         const mbedtls_cipher_context_t *src);

/**
 * \brief               setup the cipher info structure.
 *
 * \param ctx           cipher's context. Must have been initialised.
 * \param cipher_info   cipher to use.
 *
 * \return              0 on success,
 *                      MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on parameter failure
 */
int mbedtls_cipher_setup_info(mbedtls_cipher_context_t *ctx,
                              const mbedtls_cipher_info_t *cipher_info);

/**
 * \brief               Initialises and allocate CMAC context memory
 *                      Must be called with an initialized cipher context.
 *
 * \param ctx           The cipher context used for the CMAC operation, initialized
 *                      as one of the following types: MBEDTLS_CIPHER_AES_128_ECB,
 *                      MBEDTLS_CIPHER_AES_192_ECB, MBEDTLS_CIPHER_AES_256_ECB,
 *                      or MBEDTLS_CIPHER_DES_EDE3_ECB.
 * \return              \c 0 on success.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_cmac_setup(mbedtls_cipher_context_t *ctx);
#endif /*MBED_HELPERS_H*/
