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

struct mlx5_accel_xfrm_ipsec_attrs {
	u32			      esn;
	u8			      key[32];
	u32			      key_length;
	u8			      salt[4];
	u8			      seqiv[8];
	bool			      is_esn;
};

enum {
	MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA = 1UL << 0,
};

struct mlx5_accel_ipsec_ctx;

#ifdef CONFIG_MLX5_ACCEL

struct mlx5_accel_ipsec_ctx *mlx5_accel_ipsec_create_xfrm_ctx(struct mlx5_core_dev *mdev,
							      const struct mlx5_accel_xfrm_ipsec_attrs *attrs,
							      u32 flags);
void mlx5_accel_ipsec_destroy_xfrm_ctx(struct mlx5_accel_ipsec_ctx *ctx);

#else

static inline struct mlx5_accel_ipsec_ctx *mlx5_accel_ipsec_create_xfrm_ctx(struct mlx5_core_dev *mdev,
									    const struct mlx5_accel_xfrm_ipsec_attrs *attrs,
									    u32 flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

void mlx5_accel_ipsec_destroy_xfrm_ctx(struct mlx5_accel_ipsec_ctx *ctx)
{
}

#endif
#endif
