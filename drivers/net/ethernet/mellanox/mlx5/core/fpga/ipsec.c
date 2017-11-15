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

#include <linux/rhashtable.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs_helpers.h>
#include <linux/mlx5/fs.h>
#include <linux/rbtree.h>

#include "fs_core.h"
#include "fs_cmd.h"
#include "mlx5_core.h"
#include "fpga/ipsec.h"
#include "fpga/sdk.h"
#include "fpga/core.h"

#define SBU_QP_QUEUE_SIZE 8

enum mlx5_ipsec_response_syndrome {
	MLX5_IPSEC_RESPONSE_SUCCESS = 0,
	MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST = 1,
	MLX5_IPSEC_RESPONSE_SADB_ISSUE = 2,
	MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE = 3,
};

enum mlx5_fpga_ipsec_sacmd_status {
	MLX5_FPGA_IPSEC_SACMD_PENDING,
	MLX5_FPGA_IPSEC_SACMD_SEND_FAIL,
	MLX5_FPGA_IPSEC_SACMD_COMPLETE,
};

struct mlx5_ipsec_command_context {
	struct mlx5_fpga_dma_buf buf;
	struct mlx5_accel_ipsec_sa sa;
	enum mlx5_fpga_ipsec_sacmd_status status;
	int status_code;
	struct completion complete;
	struct mlx5_fpga_device *dev;
	struct list_head list; /* Item in pending_cmds */
};

struct mlx5_ipsec_sadb_resp {
	__be32 syndrome;
	__be32 sw_sa_handle;
	u8 reserved[24];
} __packed;

struct mlx5_fpga_ipsec_notifier_block {
	struct notifier_block		fs_notifier;
	struct mlx5_fpga_device		*fpga_device;
};

struct ipsec_rule {
	struct rb_node	node;
	struct		mlx5_flow_table *ft;
	struct mlx5_accel_ipsec_ctx *accel_ctx;
	int		id;
	u32 action;
	u32 outer_esp_spi_mask;
	u32 outer_esp_spi_value;
};

struct mlx5_fpga_ipsec {
	struct list_head pending_cmds;
	spinlock_t pending_cmds_lock; /* Protects pending_cmds */
	u32 caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
	struct mlx5_fpga_conn *conn;
	struct mlx5_fpga_ipsec_notifier_block fs_notifier_ingress;
	struct mlx5_fpga_ipsec_notifier_block fs_notifier_egress;
	struct rhashtable sa_hash;
	/* lock for sa hash */
	struct mutex sa_hash_lock;
	struct rb_root	rules;
};

struct mlx5_fpga_ipsec_sa_ctx {
	struct kref			ref;
	struct rhash_head		hash;
	struct mlx5_accel_ipsec_sa	hw_sa;
	struct mlx5_core_dev		*dev;
};

static const struct rhashtable_params rhash_sa = {
	.key_len = FIELD_SIZEOF(struct mlx5_fpga_ipsec_sa_ctx, hw_sa),
	.key_offset = offsetof(struct mlx5_fpga_ipsec_sa_ctx, hw_sa),
	.head_offset = offsetof(struct mlx5_fpga_ipsec_sa_ctx, hash),
	.automatic_shrinking = true,
	.min_size = 1,
};

static bool mlx5_fpga_is_ipsec_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_IPSEC)
		return false;

	return true;
}

static void mlx5_fpga_ipsec_send_complete(struct mlx5_fpga_conn *conn,
					  struct mlx5_fpga_device *fdev,
					  struct mlx5_fpga_dma_buf *buf,
					  u8 status)
{
	struct mlx5_ipsec_command_context *context;

	if (status) {
		context = container_of(buf, struct mlx5_ipsec_command_context,
				       buf);
		mlx5_fpga_warn(fdev, "IPSec command send failed with status %u\n",
			       status);
		context->status = MLX5_FPGA_IPSEC_SACMD_SEND_FAIL;
		complete(&context->complete);
	}
}

static inline int syndrome_to_errno(enum mlx5_ipsec_response_syndrome syndrome)
{
	switch (syndrome) {
	case MLX5_IPSEC_RESPONSE_SUCCESS:
		return 0;
	case MLX5_IPSEC_RESPONSE_SADB_ISSUE:
		return -EEXIST;
	case MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST:
		return -EINVAL;
	case MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE:
		return -EIO;
	}
	return -EIO;
}

static void mlx5_fpga_ipsec_recv(void *cb_arg, struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_ipsec_sadb_resp *resp = buf->sg[0].data;
	struct mlx5_ipsec_command_context *context;
	enum mlx5_ipsec_response_syndrome syndrome;
	struct mlx5_fpga_device *fdev = cb_arg;
	unsigned long flags;

	if (buf->sg[0].size < sizeof(*resp)) {
		mlx5_fpga_warn(fdev, "Short receive from FPGA IPSec: %u < %zu bytes\n",
			       buf->sg[0].size, sizeof(*resp));
		return;
	}

	mlx5_fpga_dbg(fdev, "mlx5_ipsec recv_cb syndrome %08x sa_id %x\n",
		      ntohl(resp->syndrome), ntohl(resp->sw_sa_handle));

	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	context = list_first_entry_or_null(&fdev->ipsec->pending_cmds,
					   struct mlx5_ipsec_command_context,
					   list);
	if (context)
		list_del(&context->list);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	if (!context) {
		mlx5_fpga_warn(fdev, "Received IPSec offload response without pending command request\n");
		return;
	}
	mlx5_fpga_dbg(fdev, "Handling response for %p\n", context);

	if (context->sa.sw_sa_handle != resp->sw_sa_handle) {
		mlx5_fpga_err(fdev, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
			      ntohl(context->sa.sw_sa_handle),
			      ntohl(resp->sw_sa_handle));
		return;
	}

	syndrome = ntohl(resp->syndrome);
	context->status_code = syndrome_to_errno(syndrome);
	context->status = MLX5_FPGA_IPSEC_SACMD_COMPLETE;

	if (context->status_code)
		mlx5_fpga_warn(fdev, "IPSec SADB command failed with syndrome %08x\n",
			       syndrome);
	complete(&context->complete);
}

void *mlx5_fpga_ipsec_sa_cmd_exec(struct mlx5_core_dev *mdev,
				  struct mlx5_accel_ipsec_sa *cmd)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned long flags;
	int res = 0;

	BUILD_BUG_ON((sizeof(struct mlx5_accel_ipsec_sa) & 3) != 0);
	if (!fdev || !fdev->ipsec)
		return ERR_PTR(-EOPNOTSUPP);

	context = kzalloc(sizeof(*context), GFP_ATOMIC);
	if (!context)
		return ERR_PTR(-ENOMEM);

	memcpy(&context->sa, cmd, sizeof(*cmd));
	context->buf.complete = mlx5_fpga_ipsec_send_complete;
	context->buf.sg[0].size = sizeof(context->sa);
	context->buf.sg[0].data = &context->sa;
	init_completion(&context->complete);
	context->dev = fdev;
	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	list_add_tail(&context->list, &fdev->ipsec->pending_cmds);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	context->status = MLX5_FPGA_IPSEC_SACMD_PENDING;

	res = mlx5_fpga_sbu_conn_sendmsg(fdev->ipsec->conn, &context->buf);
	if (res) {
		mlx5_fpga_warn(fdev, "Failure sending IPSec command: %d\n",
			       res);
		spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
		list_del(&context->list);
		spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);
		kfree(context);
		return ERR_PTR(res);
	}
	/* Context will be freed by wait func after completion */
	return context;
}

int mlx5_fpga_ipsec_sa_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	int res;

	res = wait_for_completion_killable(&context->complete);
	if (res) {
		mlx5_fpga_warn(context->dev, "Failure waiting for IPSec command response\n");
		return -EINTR;
	}

	if (context->status == MLX5_FPGA_IPSEC_SACMD_COMPLETE)
		res = context->status_code;
	else
		res = -EIO;

	kfree(context);
	return res;
}

u32 mlx5_fpga_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	u32 ret = 0;

	if (mlx5_fpga_is_ipsec_device(mdev))
		ret |= MLX5_ACCEL_IPSEC_DEVICE;
	else
		return ret;
	mlx5_fpga_err(fdev, "HMR: %s:%d\n", __func__, __LINE__);


	if (!fdev->ipsec)
		return ret;
	mlx5_fpga_err(fdev, "HMR: %s:%d\n", __func__, __LINE__);

	ret |= MLX5_ACCEL_IPSEC_REQUIRE_METADATA;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, esp))
		ret |= MLX5_ACCEL_IPSEC_ESP;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, ipv6))
		ret |= MLX5_ACCEL_IPSEC_IPV6;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, lso))
		ret |= MLX5_ACCEL_IPSEC_LSO;

	return ret;
}

unsigned int mlx5_fpga_ipsec_counters_count(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!fdev || !fdev->ipsec)
		return 0;

	return MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			number_of_ipsec_counters);
}

int mlx5_fpga_ipsec_counters_read(struct mlx5_core_dev *mdev, u64 *counters,
				  unsigned int counters_count)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned int i;
	__be32 *data;
	u32 count;
	u64 addr;
	int ret;

	if (!fdev || !fdev->ipsec)
		return 0;

	addr = (u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_low) +
	       ((u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_high) << 32);

	count = mlx5_fpga_ipsec_counters_count(mdev);

	data = kzalloc(sizeof(*data) * count * 2, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_fpga_mem_read(fdev, count * sizeof(u64), addr, data,
				 MLX5_FPGA_ACCESS_TYPE_DONTCARE);
	if (ret < 0) {
		mlx5_fpga_err(fdev, "Failed to read IPSec counters from HW: %d\n",
			      ret);
		goto out;
	}
	ret = 0;

	if (count > counters_count)
		count = counters_count;

	/* Each counter is low word, then high. But each word is big-endian */
	for (i = 0; i < count; i++)
		counters[i] = (u64)ntohl(data[i * 2]) |
			      ((u64)ntohl(data[i * 2 + 1]) << 32);

out:
	kfree(data);
	return ret;
}

static void mlx5_fs_ipsec_build_hw_sa(struct mlx5_core_dev *dev,
				      struct mlx5_fs_rule_notifier_attrs *attrs,
				      struct mlx5_accel_ipsec_ctx *accel_ctx,
				      struct mlx5_accel_ipsec_sa *hw_sa)
{
	struct mlx5_accel_xfrm_ipsec_attrs *esp_aes_gcm = &accel_ctx->attrs;
	memset(hw_sa, 0, sizeof(*hw_sa));

	memcpy(&hw_sa->key_enc, esp_aes_gcm->key, esp_aes_gcm->key_length);
	if (esp_aes_gcm->key_length == 16)
		memcpy(&hw_sa->key_enc[16], esp_aes_gcm->key,
		       esp_aes_gcm->key_length);
	hw_sa->gcm.salt = *((__be32 *)esp_aes_gcm->salt);

	hw_sa->cmd = htonl(MLX5_IPSEC_CMD_ADD_SA);
	hw_sa->flags |= MLX5_IPSEC_SADB_SA_VALID | MLX5_IPSEC_SADB_SPI_EN;
	if (mlx5_fs_is_outer_ipv4_flow(dev, attrs->spec.match_criteria, attrs->spec.match_value)) {
		memcpy(&hw_sa->sip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4, attrs->spec.match_value,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       sizeof(hw_sa->sip[3]));
		memcpy(&hw_sa->dip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4, attrs->spec.match_value,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       sizeof(hw_sa->dip[3]));
		hw_sa->sip_masklen = 32;
		hw_sa->dip_masklen = 32;
	} else {
		memcpy(hw_sa->sip,
		       MLX5_ADDR_OF(fte_match_param, attrs->spec.match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       sizeof(hw_sa->sip));
		memcpy(hw_sa->dip,
		       MLX5_ADDR_OF(fte_match_param, attrs->spec.match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       sizeof(hw_sa->dip));
		hw_sa->sip_masklen = 128;
		hw_sa->dip_masklen = 128;
		hw_sa->flags |= MLX5_IPSEC_SADB_IPV6;
	}
	hw_sa->spi = MLX5_GET_BE(typeof(hw_sa->spi),
				 fte_match_param, attrs->spec.match_value,
				 misc_parameters.outer_esp_spi);
	hw_sa->sw_sa_handle = 0;
	hw_sa->flags |= MLX5_IPSEC_SADB_IP_ESP;
	switch (esp_aes_gcm->key_length) {
	case 16:
		hw_sa->enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_128_AUTH_128;
		break;
	case 32:
		hw_sa->enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_256_AUTH_128;
		break;
	}

	if (attrs->spec.flow_act->action & MLX5_FLOW_CONTEXT_ACTION_ENCRYPT)
		hw_sa->flags |= MLX5_IPSEC_SADB_DIR_SX;

	print_hex_dump(KERN_ERR, "fs_hw_sa: ", DUMP_PREFIX_OFFSET, 32, 4, hw_sa, sizeof(*hw_sa), false);
}

static bool mlx5_is_fpga_ipsec_rule(struct mlx5_core_dev *dev,
				    u8 match_criteria_enable,
				    const u32 *match_c,
				    const u32 *match_v)
{
	u32 ipsec_dev_caps = mlx5_accel_ipsec_device_caps(dev);
	bool ipv6_flow;

	ipv6_flow = mlx5_fs_is_outer_ipv6_flow(dev, match_c, match_v);

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!(match_criteria_enable & 1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS) ||
	    mlx5_fs_is_outer_udp_flow(match_c, match_v) ||
	    mlx5_fs_is_outer_tcp_flow(match_c, match_v) ||
	    mlx5_fs_is_vxlan_flow(match_c) ||
	    !(mlx5_fs_is_outer_ipv4_flow(dev, match_c, match_v) ||
	      ipv6_flow))
		return false;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_DEVICE))
		return false;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_ESP) &&
	    mlx5_fs_is_ipsec_flow(match_c))
		return false;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_IPV6) &&
	    ipv6_flow)
		return false;
	pr_err("HMR: %s:%d\n", __func__, __LINE__);

	return true;
}

static bool mlx5_is_fpga_egress_ipsec_rule(struct mlx5_core_dev *dev,
					   u8 match_criteria_enable,
					   const u32 *match_c,
					   const u32 *match_v,
					   struct mlx5_flow_act *flow_act)
{
	const void *outer_c = MLX5_ADDR_OF(fte_match_param, match_c,
					   outer_headers);
	bool is_dmac = MLX5_GET(fte_match_set_lyr_2_4, outer_c, dmac_47_16) ||
		MLX5_GET(fte_match_set_lyr_2_4, outer_c, dmac_15_0);
	bool is_smac = MLX5_GET(fte_match_set_lyr_2_4, outer_c, smac_47_16) ||
		MLX5_GET(fte_match_set_lyr_2_4, outer_c, smac_15_0);
	int ret;

	pr_err("HMR: dmac: %x %x\n", MLX5_GET(fte_match_set_lyr_2_4, outer_c, dmac_47_16),
			MLX5_GET(fte_match_set_lyr_2_4, outer_c, dmac_15_0));
	pr_err("HMR: smac: %x %x\n", MLX5_GET(fte_match_set_lyr_2_4, outer_c, smac_47_16),
				MLX5_GET(fte_match_set_lyr_2_4, outer_c, smac_15_0));
	ret = mlx5_is_fpga_ipsec_rule(dev, match_criteria_enable, match_c, match_v);
	if (!ret)
		return ret;

	pr_err("HMR: match_criteria %x action %x flow_tag: %d\n", match_criteria_enable, flow_act->action, flow_act->has_flow_tag);

	if (is_dmac || is_smac ||
	    (match_criteria_enable &
			    ~((1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS) |
			      (1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_MISC_PARAMETERS)))||
	    (flow_act->action & ~(MLX5_FLOW_CONTEXT_ACTION_ENCRYPT | MLX5_FLOW_CONTEXT_ACTION_ALLOW)) ||
	    flow_act->has_flow_tag)
		return false;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	return true;
}

static bool is_full_mask(const void *p, size_t len)
{
	WARN_ON(len % 4);

	return !memchr_inv(p, 0xff, len);
}

static bool validate_fpga_full_mask(struct mlx5_core_dev *dev,
				    const u32 *match_c,
				    const u32 *match_v)
{
	const void *misc_params_c = MLX5_ADDR_OF(fte_match_param,
						 match_c,
						 misc_parameters);
	const void *headers_c = MLX5_ADDR_OF(fte_match_param,
					     match_c,
					     outer_headers);
	const void *headers_v = MLX5_ADDR_OF(fte_match_param,
					     match_v,
					     outer_headers);

	if (mlx5_fs_is_outer_ipv4_flow(dev, headers_c, headers_v)) {
		const void *s_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    src_ipv4_src_ipv6.ipv4_layout.ipv4);
		const void *d_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    dst_ipv4_dst_ipv6.ipv4_layout.ipv4);

		if (!is_full_mask(s_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)) ||
		    !is_full_mask(d_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)))
			return false;
	} else {
		const void *s_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    src_ipv4_src_ipv6.ipv6_layout.ipv6);
		const void *d_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
						    dst_ipv4_dst_ipv6.ipv6_layout.ipv6);

		if (!is_full_mask(s_ipv6_c, MLX5_FLD_SZ_BYTES(ipv6_layout,
							      ipv6)) ||
		    !is_full_mask(d_ipv6_c, MLX5_FLD_SZ_BYTES(ipv6_layout,
							      ipv6)))
			return false;
	}

	if (!is_full_mask(MLX5_ADDR_OF(fte_match_set_misc, misc_params_c,
				       outer_esp_spi),
			  MLX5_FLD_SZ_BYTES(fte_match_set_misc, outer_esp_spi)))
		return false;

	return true;
}

int mlx5_create_ipsec_fpga(struct mlx5_fpga_device *fpga,
			   struct mlx5_fs_rule_notifier_attrs *attrs,
			   bool is_egress)
{
	struct mlx5_fpga_ipsec_sa_ctx *sa_ctx;
	struct mlx5_fpga_ipsec_sa_ctx *sa_ctx_exist;
	struct mlx5_core_dev *dev = fpga->mdev;
	struct mlx5_fpga_ipsec *fipsec = fpga->ipsec;
	void *context;
	struct mlx5_accel_ipsec_ctx *accel_ctx;
	int err;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (is_egress) {
		pr_err("HMR: %s:%d\n", __func__, __LINE__);
		if (!mlx5_is_fpga_egress_ipsec_rule(dev, *attrs->spec.match_criteria_enable,
						    attrs->spec.match_criteria,
						    attrs->spec.match_value,
						    attrs->spec.flow_act))
			return -EINVAL;
	} else {
		pr_err("HMR: %s:%d\n", __func__, __LINE__);
		if (!mlx5_is_fpga_ipsec_rule(dev, *attrs->spec.match_criteria_enable,
					     attrs->spec.match_criteria,
					     attrs->spec.match_value))
		return -EINVAL;
	}

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!attrs->spec.flow_act->esp_aes_gcm_id)
		return -EINVAL;

	accel_ctx = (struct mlx5_accel_ipsec_ctx *)attrs->spec.flow_act->esp_aes_gcm_id;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	if (!validate_fpga_full_mask(dev, attrs->spec.match_criteria,
				     attrs->spec.match_value))
		return -EINVAL;

	sa_ctx = kzalloc(sizeof(*sa_ctx), GFP_KERNEL);
	if (!sa_ctx)
		return -ENOMEM;

	mlx5_fs_ipsec_build_hw_sa(dev, attrs, accel_ctx, &sa_ctx->hw_sa);

	mutex_lock(&fipsec->sa_hash_lock);
	sa_ctx_exist = rhashtable_lookup_fast(&fipsec->sa_hash, &sa_ctx->hash,
					       rhash_sa);
	if (sa_ctx_exist) {
		pr_err("HMR kref_get\n");
		kref_get(&sa_ctx->ref);
		err = 0;
		goto err_free;
	}

	pr_err("HMR kref_init\n");
	kref_init(&sa_ctx->ref);
	sa_ctx->dev = dev;
	err = rhashtable_lookup_insert_fast(&fipsec->sa_hash, &sa_ctx->hash,
					    rhash_sa);
	if (err)
		goto err_free;

	mutex_unlock(&fipsec->sa_hash_lock);
	context = mlx5_accel_ipsec_sa_cmd_exec(dev, &sa_ctx->hw_sa);
	if (IS_ERR(context))
		return PTR_ERR(context);

	return mlx5_accel_ipsec_sa_cmd_wait(context);

err_free:
	mutex_unlock(&fipsec->sa_hash_lock);
	kfree(sa_ctx);
	return err;
}

static void release_sa_ctx(struct kref *ref)
{
	void *context;
	struct mlx5_fpga_ipsec_sa_ctx *sa_ctx =
		container_of(ref, struct mlx5_fpga_ipsec_sa_ctx, ref);
	struct mlx5_fpga_ipsec *fipsec = sa_ctx->dev->fpga->ipsec;;

	pr_err("HMR release_sa_ctx\n");
	WARN_ON(rhashtable_remove_fast(&fipsec->sa_hash, &sa_ctx->hash,
				       rhash_sa));
	sa_ctx->hw_sa.cmd = htonl(MLX5_IPSEC_CMD_DEL_SA);
	context = mlx5_accel_ipsec_sa_cmd_exec(sa_ctx->dev, &sa_ctx->hw_sa);
	if (WARN_ON(context))
		return;

	WARN_ON(mlx5_accel_ipsec_sa_cmd_wait(context));
}

int mlx5_delete_ipsec_fpga(struct mlx5_fpga_device *fpga,
			   struct mlx5_fs_rule_notifier_attrs *attrs,
			   struct mlx5_accel_ipsec_ctx *accel_ctx)
{
	struct mlx5_accel_ipsec_sa hw_sa;
	struct mlx5_fpga_ipsec_sa_ctx *sa_ctx;
	struct mlx5_core_dev *dev = fpga->mdev;
	struct mlx5_fpga_ipsec *fipsec = fpga->ipsec;
	int err = 0;

	mlx5_fs_ipsec_build_hw_sa(dev, attrs, accel_ctx, &hw_sa);

	mutex_lock(&fipsec->sa_hash_lock);
	sa_ctx = rhashtable_lookup_fast(&fipsec->sa_hash, &hw_sa,
					rhash_sa);
	if (WARN_ON(sa_ctx == NULL)) {
		err = -EINVAL;
		goto err;
	}

	pr_err("HMR kref_put\n");
	kref_put(&sa_ctx->ref, release_sa_ctx);
err:
	mutex_unlock(&fipsec->sa_hash_lock);
	return err;
}

static int compare_keys(struct mlx5_flow_table *ft1, int id1,
			struct mlx5_flow_table *ft2, int id2)
{
	if (ft1 < ft2 || (ft1 == ft2 && id1 < id2))
		return -1;

	if (ft1 > ft2 || (ft1 == ft2 && id1 > id2))
		return 1;

	return 0;
}

struct ipsec_rule *rule_search(struct rb_root *root, struct mlx5_flow_table *ft,
			       int id)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct ipsec_rule *rule = container_of(node, struct ipsec_rule,
						       node);
		int result;

		result = compare_keys(ft, id, rule->ft, rule->id);
		if (result < 0) {
			pr_err("search left\n");
			node = node->rb_left;
		}
		else if (result > 0) {
			pr_err("search left\n");
			node = node->rb_right;
		}
		else {
			pr_err("search match\n");
			return rule;
		}
	}
	pr_err("%s:%d Couldn't find rule\n", __func__, __LINE__);
	return NULL;
}

int rule_insert(struct rb_root *root, struct ipsec_rule *rule)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	pr_err("in insert\n");
	/* Figure out where to put new node */
	while (*new) {
		struct ipsec_rule *this =
			container_of(*new, struct ipsec_rule, node);
		int result = compare_keys(rule->ft, rule->id,
					  this->ft, this->id);

		parent = *new;
		if (result < 0) {
			pr_err("insert left\n");
			new = &((*new)->rb_left);
		}
		else if (result > 0) {
			pr_err("search right\n");
			new = &((*new)->rb_right);
		}
		else {
			pr_err("search exists\n");
			return -EEXIST;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&rule->node, parent, new);
	rb_insert_color(&rule->node, root);

	return 0;
}

int rule_delete(struct rb_root *root, struct ipsec_rule *rule)
{
	if (rule) {
		rb_erase(&rule->node, root);
		kfree(rule);
		return 0;
	}
	return -ENOENT;
}

void restore_spec_mailbox(struct ipsec_rule *rule, struct mlx5_fs_rule_notifier_attrs *attrs)
{
	char *misc_params_c = MLX5_ADDR_OF(fte_match_param, attrs->spec.match_criteria,
			misc_parameters);
	char *misc_params_v = MLX5_ADDR_OF(fte_match_param, attrs->spec.match_value,
			misc_parameters);

	MLX5_SET(fte_match_set_misc, misc_params_c, outer_esp_spi,
		 rule->outer_esp_spi_mask);
	MLX5_SET(fte_match_set_misc, misc_params_v, outer_esp_spi,
		 rule->outer_esp_spi_value);
	attrs->spec.flow_act->action |= rule->action;
	attrs->spec.flow_act->esp_aes_gcm_id = (uintptr_t)rule->accel_ctx;
}

int fs_rule_notifier(struct notifier_block *nb, unsigned long action,
		     void *data, bool is_egress)
{
	struct mlx5_fpga_ipsec_notifier_block *fpga_nb =
		container_of(nb, struct mlx5_fpga_ipsec_notifier_block,
			     fs_notifier);
	struct mlx5_fpga_device *fdev = fpga_nb->fpga_device;
	struct mlx5_fpga_ipsec *ipsec = fdev->ipsec;
	struct mlx5_core_dev *mdev = fdev->mdev;
	struct mlx5_fs_rule_notifier_attrs *attrs = data;
	bool is_esp = attrs->spec.flow_act->esp_aes_gcm_id;
	char *misc_params_c = MLX5_ADDR_OF(fte_match_param, attrs->spec.match_criteria,
			misc_parameters);
	char *misc_params_v = MLX5_ADDR_OF(fte_match_param, attrs->spec.match_value,
			misc_parameters);
	int ret;
	struct ipsec_rule *rule;

	pr_err("HMR: %s:%d\n", __func__, __LINE__);
	pr_err("%s:%d got ft %p id %d\n", __func__, __LINE__, attrs->ft, attrs->id);
	switch (action) {
	case MLX5_FS_RULE_NOTIFY_ADD_PRE:
		pr_err("HMR MLX5_FS_RULE_NOTIFY_ADD_PRE\n");
		if (!is_esp ||
		    !(attrs->spec.flow_act->action &
		      (MLX5_FLOW_CONTEXT_ACTION_ENCRYPT |
		       MLX5_FLOW_CONTEXT_ACTION_DECRYPT)))
			return NOTIFY_DONE;

		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return notifier_from_errno(-ENOMEM);

		ret = mlx5_create_ipsec_fpga(fdev, attrs, is_egress);
		if (ret) {
			pr_err("fpga returned code %d\n", ret);
			kfree(rule);
			return notifier_from_errno(ret);
		}

		pr_err("%s:%d pass fpga\n", __func__, __LINE__);
		rule->ft = attrs->ft;
		rule->id = attrs->id;
		rule->action = attrs->spec.flow_act->action &
			(MLX5_FLOW_CONTEXT_ACTION_ENCRYPT |
			 MLX5_FLOW_CONTEXT_ACTION_DECRYPT);
		rule->accel_ctx = (struct mlx5_accel_ipsec_ctx *)attrs->spec.flow_act->esp_aes_gcm_id;
		rule->outer_esp_spi_mask = MLX5_GET(fte_match_set_misc, misc_params_c, outer_esp_spi);
		rule->outer_esp_spi_value = MLX5_GET(fte_match_set_misc, misc_params_v, outer_esp_spi);
		WARN_ON(rule_insert(&ipsec->rules, rule));

		attrs->spec.flow_act->action &= ~rule->action;
		attrs->spec.flow_act->esp_aes_gcm_id = 0;
		if (!MLX5_CAP_FLOWTABLE(mdev,
					flow_table_properties_nic_receive.ft_field_support.outer_esp_spi) &&
		    !is_egress) {
			pr_err("HMR flow_table_properties_nic_receive.outer_esp_spi %d\n", MLX5_CAP_FLOWTABLE(mdev, flow_table_properties_nic_receive.ft_field_support.outer_esp_spi));
			MLX5_SET(fte_match_set_misc, misc_params_c, outer_esp_spi, 0);
			MLX5_SET(fte_match_set_misc, misc_params_v, outer_esp_spi, 0);
			if (!(*misc_params_c) &&
			    !memcmp(misc_params_c, misc_params_c + 1,
				    MLX5_ST_SZ_BYTES(fte_match_set_misc) - 1))
				*attrs->spec.match_criteria_enable &=
						~(1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_MISC_PARAMETERS);

		}
		break;
	case MLX5_FS_RULE_NOTIFY_ADD_POST:
		pr_err("HMR MLX5_FS_RULE_NOTIFY_ADD_POST %d\n", attrs->success);
		rule = rule_search(&ipsec->rules, attrs->ft, attrs->id);
		if (!rule)
			break;

		restore_spec_mailbox(rule, attrs);
		if (!attrs->success) {
			mlx5_delete_ipsec_fpga(fdev, attrs, rule->accel_ctx);
			rule_delete(&ipsec->rules, rule);
		}
		break;
	case MLX5_FS_RULE_NOTIFY_DEL:
		pr_err("HMR MLX5_FS_RULE_NOTIFY_DEL\n");
		rule = rule_search(&ipsec->rules, attrs->ft, attrs->id);
		if (!rule)
			break;

		restore_spec_mailbox(rule, attrs);
		mlx5_delete_ipsec_fpga(fdev, attrs, rule->accel_ctx);
		rule_delete(&ipsec->rules, rule);
		break;
	}

	return NOTIFY_DONE;
}

int fs_rule_notifier_egress(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	return fs_rule_notifier(nb, action, data, true);
}

int fs_rule_notifier_ingress(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	return fs_rule_notifier(nb, action, data, false);
}

static int init_notifier_block(struct mlx5_fpga_device *fdev,
			       struct mlx5_fpga_ipsec_notifier_block *nb,
			       enum mlx5_flow_namespace_type type,
			       notifier_fn_t notifier_fn)
{
	struct mlx5_core_dev *mdev = fdev->mdev;

	nb->fpga_device = fdev;
	nb->fs_notifier.notifier_call = notifier_fn;
	return mlx5_fs_rule_notifier_register(mdev, type, &nb->fs_notifier);
}

int mlx5_fpga_ipsec_init(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_fpga_device *fdev = mdev->fpga;
	struct mlx5_fpga_conn *conn;
	int err;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return 0;

	fdev->ipsec = kzalloc(sizeof(*fdev->ipsec), GFP_KERNEL);
	if (!fdev->ipsec)
		return -ENOMEM;

	err = mlx5_fpga_get_sbu_caps(fdev, sizeof(fdev->ipsec->caps),
				     fdev->ipsec->caps);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to retrieve IPSec extended capabilities: %d\n",
			      err);
		goto error;
	}

	INIT_LIST_HEAD(&fdev->ipsec->pending_cmds);
	spin_lock_init(&fdev->ipsec->pending_cmds_lock);

	err = init_notifier_block(fdev, &fdev->ipsec->fs_notifier_ingress,
				  MLX5_FLOW_NAMESPACE_BYPASS,
				  fs_rule_notifier_ingress);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to register ingress rule notifier: %d\n",
			      err);
		goto error;
	}

	err = init_notifier_block(fdev, &fdev->ipsec->fs_notifier_egress,
				  MLX5_FLOW_NAMESPACE_EGRESS,
				  fs_rule_notifier_egress);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to register egress rule notifier: %d\n",
			      err);
		goto error1;
	}

	fdev->ipsec->rules = RB_ROOT;
	init_attr.rx_size = SBU_QP_QUEUE_SIZE;
	init_attr.tx_size = SBU_QP_QUEUE_SIZE;
	init_attr.recv_cb = mlx5_fpga_ipsec_recv;
	init_attr.cb_arg = fdev;
	conn = mlx5_fpga_sbu_conn_create(fdev, &init_attr);
	if (IS_ERR(conn)) {
		err = PTR_ERR(conn);
		mlx5_fpga_err(fdev, "Error creating IPSec command connection %d\n",
			      err);
		goto error2;
	}
	fdev->ipsec->conn = conn;

	err = rhashtable_init(&fdev->ipsec->sa_hash, &rhash_sa);
	if (err)
		goto error;

	return 0;

error2:
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev, MLX5_FLOW_NAMESPACE_EGRESS,
						 &fdev->ipsec->fs_notifier_egress.fs_notifier));
error1:
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev, MLX5_FLOW_NAMESPACE_BYPASS,
						 &fdev->ipsec->fs_notifier_ingress.fs_notifier));
error:
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
	return err;
}

void destroy_rules_rb(struct rb_root *root)
{
	struct ipsec_rule *r, *tmp;

	rbtree_postorder_for_each_entry_safe(r, tmp, root, node) {
		rb_erase(&r->node, root);
		kfree(r);
	}
}

void mlx5_fpga_ipsec_cleanup(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return;

	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev, MLX5_FLOW_NAMESPACE_EGRESS,
						 &fdev->ipsec->fs_notifier_egress.fs_notifier));
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev, MLX5_FLOW_NAMESPACE_BYPASS,
						 &fdev->ipsec->fs_notifier_ingress.fs_notifier));
	destroy_rules_rb(&fdev->ipsec->rules);
	mlx5_fpga_sbu_conn_destroy(fdev->ipsec->conn);
	rhashtable_destroy(&fdev->ipsec->sa_hash);
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
}

struct mlx5_accel_ipsec_ctx *mlx5_fpga_ipsec_create_xfrm_ctx(struct mlx5_core_dev *mdev,
							     const struct mlx5_accel_xfrm_ipsec_attrs *attrs,
							     u32 flags)
{
	struct mlx5_accel_ipsec_ctx *ctx;

	if (!(flags & MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA)) {
		mlx5_core_warn(mdev, "Tried to create an esp_aes_gcm action without metadata\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (attrs->key_length != 32 &&
	    attrs->key_length != 16) {
		pr_err("only 256 and 128 bit aes-gcm keys are supported\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (attrs->is_esn) {
		pr_err("ESN not supported\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	memcpy(&ctx->attrs, attrs, sizeof(ctx->attrs));

	return ctx;
}

void mlx5_fpga_ipsec_destroy_xfrm_ctx(struct mlx5_accel_ipsec_ctx *ctx)
{
	kfree(ctx);
}
