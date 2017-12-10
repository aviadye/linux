/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef __MLX5_ACCEL_H__
#define __MLX5_ACCEL_H__

enum mlx5_accel_esp_aes_gcm_keymat_iv_algo {
	MLX5_ACCEL_ESP_AES_GCM_IV_ALGO_SEQ,
};

enum mlx5_accel_esp_flags {
	MLX5_ACCEL_ESP_FLAGS_TUNNEL            = 0,    /* Default */
	MLX5_ACCEL_ESP_FLAGS_TRANSPORT         = 1UL << 0,
	MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED     = 1UL << 1,
	/* TODO: Ask Boris if we need ESN_ENABLED flag */
	MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP = 1UL << 2,
};

enum mlx5_accel_esp_action {
	MLX5_ACCEL_ESP_ACTION_DECRYPT,
	MLX5_ACCEL_ESP_ACTION_ENCRYPT,
};

enum mlx5_accel_esp_keymats {
	MLX5_ACCEL_ESP_KEYMAT_AES_NONE,
	MLX5_ACCEL_ESP_KEYMAT_AES_GCM,
};

enum mlx5_accel_esp_replay {
	MLX5_ACCEL_ESP_REPLAY_NONE,
	MLX5_ACCEL_ESP_REPLAY_BMP,
};

struct aes_gcm_keymat {
	u64   seq_iv;
	enum mlx5_accel_esp_aes_gcm_keymat_iv_algo iv_algo;

	u32   salt;
	u32   icv_len;

	u32   key_len;
	u32   aes_key[256 / 32];
};

struct mlx5_accel_esp_xfrm_attrs {
	enum mlx5_accel_esp_action action;
	u32   esn;
	u32   spi;
	u32   seq;
	u32   tfc_pad;
	u32   flags;
	u32   sa_handle;
	enum mlx5_accel_esp_replay replay_type;
	union {
		struct {
			u32 	size;

		} bmp;
	} replay;
	enum mlx5_accel_esp_keymats keymat_type;
	union {
		struct aes_gcm_keymat aes_gcm;
	} keymat;
};

struct mlx5_accel_esp_xfrm {
	struct mlx5_core_dev  *mdev;
	struct mlx5_accel_esp_xfrm_attrs attrs;
};

enum {
	MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA = 1UL << 0,
};

enum {
	MLX5_ACCEL_IPSEC_DEVICE = BIT(1),
	MLX5_ACCEL_IPSEC_IPV6 = BIT(2),
	MLX5_ACCEL_IPSEC_ESP = BIT(3),
	MLX5_ACCEL_IPSEC_LSO = BIT(4),
	MLX5_ACCEL_IPSEC_NO_TRAILER = BIT(5),
	MLX5_ACCEL_IPSEC_ESN = BIT(6),
	MLX5_ACCEL_IPSEC_V2_CMD = BIT(7),
};

#ifdef CONFIG_MLX5_ACCEL

struct mlx5_accel_esp_xfrm *mlx5_accel_esp_create_xfrm(struct mlx5_core_dev *mdev,
						       const struct mlx5_accel_esp_xfrm_attrs *attrs,
						       u32 flags);

void mlx5_accel_esp_destroy_xfrm(struct mlx5_accel_esp_xfrm *xfrm);


#else

static inline struct mlx5_accel_esp_xfrm *mlx5_accel_esp_create_xfrm(struct mlx5_core_dev *mdev,
								     const struct mlx5_accel_xfrm_ipsec_attrs *attrs,
								     u32 flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void mlx5_accel_esp_destroy_xfrm(struct mlx5_accel_ipsec_xfrm *xfrm)
{
}

#endif
#endif
