// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021 Huawei Technologies Co., Ltd
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <mbedtls/arc4.h>
#include <mbedtls/aria.h>
#include <mbedtls/blowfish.h>
#include <mbedtls/camellia.h>
#include <mbedtls/ccm.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/des.h>
#include <mbedtls/gcm.h>
#include <mbedtls/nist_kw.h>
#include <mbedtls/platform.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include "mbed_helpers.h"

/* Generate random number 1 <= n < max */
TEE_Result mbed_gen_random_upto(mbedtls_mpi *n, mbedtls_mpi *max)
{
	size_t sz = mbedtls_mpi_size(max);
	bool found = false;
	int mres = 0;

	do {
		mres = mbedtls_mpi_fill_random(n, sz, mbd_rand, NULL);
		if (mres)
			return TEE_ERROR_BAD_STATE;
		if (mbedtls_mpi_bitlen(n) != 0 &&
		    mbedtls_mpi_cmp_mpi(n, max) == -1)
			found = true;
	} while (!found);

	return TEE_SUCCESS;
}

static void mbedtls_cipher_ctx_clone(mbedtls_cipher_context_t *dst,
				     const mbedtls_cipher_context_t *src)
{
	size_t ctx_size = 0;
	mbedtls_cipher_mode_t mode = mbedtls_cipher_info_get_mode(src->cipher_info);

	switch (src->cipher_info->base->cipher) {
		case MBEDTLS_CIPHER_ID_AES:
			ctx_size = sizeof(mbedtls_aes_context);
			break;
		case MBEDTLS_CIPHER_ID_DES:
			ctx_size = sizeof(mbedtls_des_context);
			break;
		case MBEDTLS_CIPHER_ID_3DES:
			ctx_size = sizeof(mbedtls_des3_context);
			break;
		case MBEDTLS_CIPHER_ID_CAMELLIA:
			ctx_size = sizeof(mbedtls_camellia_context);
			break;
		case MBEDTLS_CIPHER_ID_BLOWFISH:
			ctx_size = sizeof(mbedtls_blowfish_context);
			break;
		case MBEDTLS_CIPHER_ID_ARC4:
			ctx_size = sizeof(mbedtls_arc4_context);
			break;
		case MBEDTLS_CIPHER_ID_ARIA:
			ctx_size = sizeof(mbedtls_aria_context);
			break;
		case MBEDTLS_CIPHER_ID_CHACHA20:
			ctx_size = sizeof(mbedtls_chacha20_context);
			break;
		default:
			break;
	}

	switch (mode) {
		case MBEDTLS_MODE_GCM:
			ctx_size = sizeof(mbedtls_gcm_context);
			break;
		case MBEDTLS_MODE_CCM:
			ctx_size = sizeof(mbedtls_ccm_context);
			break;
		case MBEDTLS_MODE_CHACHAPOLY:
			ctx_size = sizeof(mbedtls_chachapoly_context);
			break;
		case MBEDTLS_MODE_KW:
			ctx_size = sizeof(mbedtls_nist_kw_context);
			break;
		default:
			break;
	}

	memcpy(dst->cipher_ctx, src->cipher_ctx, ctx_size);
}

int mbedtls_cipher_clone(mbedtls_cipher_context_t *dst,
			 const mbedtls_cipher_context_t *src)
{
	if(dst == NULL || dst->cipher_info == NULL ||
	   src == NULL || src->cipher_info == NULL) {
		return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
	}

	dst->cipher_info = src->cipher_info;
	dst->key_bitlen = src->key_bitlen;
	dst->operation = src->operation;
#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
	dst->add_padding = src->add_padding;
	dst->get_padding = src->get_padding;
#endif
	memcpy(dst->unprocessed_data, src->unprocessed_data, MBEDTLS_MAX_BLOCK_LENGTH);
	dst->unprocessed_len = src->unprocessed_len;
	memcpy(dst->iv, src->iv, MBEDTLS_MAX_IV_LENGTH);
	dst->iv_size = src->iv_size;
	mbedtls_cipher_ctx_clone(dst, src);

#if defined(MBEDTLS_CMAC_C)
	if(dst->cmac_ctx != NULL && src->cmac_ctx != NULL) {
		memcpy(dst->cmac_ctx, src->cmac_ctx, sizeof(mbedtls_cmac_context_t));
	}
#endif
	return 0;
}

int mbedtls_cipher_setup_info(mbedtls_cipher_context_t *ctx,
			      const mbedtls_cipher_info_t *cipher_info)
{
	if(NULL == cipher_info || NULL == ctx)
		return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;

	ctx->cipher_info = cipher_info;
	return 0;
}

int mbedtls_cipher_cmac_setup(mbedtls_cipher_context_t *ctx)
{
	mbedtls_cmac_context_t *cmac_ctx;

	/* Allocated and initialise in the cipher context memory for the CMAC
	 * context */
	cmac_ctx = mbedtls_calloc(1, sizeof(mbedtls_cmac_context_t));
	if(cmac_ctx == NULL)
		return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;

	ctx->cmac_ctx = cmac_ctx;

	mbedtls_platform_zeroize(cmac_ctx->state, sizeof(cmac_ctx->state));
	return 0;
}
