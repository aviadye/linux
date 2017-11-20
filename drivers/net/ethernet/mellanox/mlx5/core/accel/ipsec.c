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

#include <linux/mlx5/device.h>

#include "accel/ipsec.h"
#include "mlx5_core.h"
#include "fpga/ipsec.h"

void *mlx5_accel_ipsec_sa_cmd_exec(struct mlx5_core_dev *mdev,
				   struct mlx5_accel_ipsec_sa *cmd, int cmd_size)
{
	if (!MLX5_IPSEC_DEV(mdev))
		return ERR_PTR(-EOPNOTSUPP);

	return mlx5_fpga_ipsec_sa_cmd_exec(mdev, cmd, cmd_size);
}

int mlx5_accel_ipsec_sa_cmd_wait(void *ctx)
{
	return mlx5_fpga_ipsec_sa_cmd_wait(ctx);
}

u32 mlx5_accel_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	return mlx5_fpga_ipsec_device_caps(mdev);
}

unsigned int mlx5_accel_ipsec_counters_count(struct mlx5_core_dev *mdev)
{
	return mlx5_fpga_ipsec_counters_count(mdev);
}

int mlx5_accel_ipsec_counters_read(struct mlx5_core_dev *mdev, u64 *counters,
				   unsigned int count)
{
	return mlx5_fpga_ipsec_counters_read(mdev, counters, count);
}

int mlx5_accel_ipsec_init(struct mlx5_core_dev *mdev)
{
	return mlx5_fpga_ipsec_init(mdev);
}

void mlx5_accel_ipsec_cleanup(struct mlx5_core_dev *mdev)
{
	mlx5_fpga_ipsec_cleanup(mdev);
}

int mlx5_accel_esp_validate_xfrm_attrs(struct mlx5_core_dev *mdev,
				       const struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	return mlx5_fpga_esp_validate_xfrm_attrs(mdev, attrs);
}
EXPORT_SYMBOL_GPL(mlx5_accel_esp_validate_xfrm_attrs);

struct mlx5_accel_esp_xfrm_ctx *mlx5_accel_esp_create_xfrm_ctx(struct mlx5_core_dev *mdev,
							       const struct mlx5_accel_esp_xfrm_attrs *attrs,
							       u32 flags)
{
	struct mlx5_accel_esp_xfrm_ctx *ctx;

	ctx = mlx5_fpga_esp_create_xfrm_ctx(mdev, attrs, flags);
	if (IS_ERR(ctx))
		return ctx;

	ctx->mdev = mdev;
	return ctx;
}
EXPORT_SYMBOL_GPL(mlx5_accel_esp_create_xfrm_ctx);

void mlx5_accel_esp_destroy_xfrm_ctx(struct mlx5_accel_esp_xfrm_ctx *ctx)
{
	mlx5_fpga_esp_destroy_xfrm_ctx(ctx);
}
EXPORT_SYMBOL_GPL(mlx5_accel_esp_destroy_xfrm_ctx);
