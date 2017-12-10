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

#include "mlx5_core.h"
#include "fpga/ipsec.h"
#include "fpga/sdk.h"
#include "fpga/core.h"

#define SBU_QP_QUEUE_SIZE 8

#define MLX5_FPGA_IPSEC_SADB_IP_AH       BIT(7)
#define MLX5_FPGA_IPSEC_SADB_IP_ESP      BIT(6)
#define MLX5_FPGA_IPSEC_SADB_SA_VALID    BIT(5)
#define MLX5_FPGA_IPSEC_SADB_SPI_EN      BIT(4)
#define MLX5_FPGA_IPSEC_SADB_DIR_SX      BIT(3)
#define MLX5_FPGA_IPSEC_SADB_IPV6        BIT(2)
#define MLX5_FPGA_IPSEC_SADB_ESN_OVERLAP BIT(1)
#define MLX5_FPGA_IPSEC_SADB_ESN_EN      BIT(0)

enum mlx5_fpga_ipsec_cmd {
	MLX5_FPGA_IPSEC_CMD_ADD_SA = 0,
	MLX5_FPGA_IPSEC_CMD_DEL_SA = 1,
	MLX5_FPGA_IPSEC_CMD_ADD_SA_V2 = 2,
	MLX5_FPGA_IPSEC_CMD_DEL_SA_V2 = 3,
	MLX5_FPGA_IPSEC_CMD_MOD_SA_V2 = 4,
	MLX5_FPGA_IPSEC_CMD_SET_CAP = 5,
};

enum mlx5_ipsec_response_syndrome {
	MLX5_IPSEC_RESPONSE_SUCCESS = 0,
	MLX5_IPSEC_RESPONSE_ILLEGAL_REQUEST = 1,
	MLX5_IPSEC_RESPONSE_SADB_ISSUE = 2,
	MLX5_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE = 3,
};

enum mlx5_fpga_ipsec_cmd_status {
	MLX5_FPGA_IPSEC_CMD_PENDING,
	MLX5_FPGA_IPSEC_CMD_SEND_FAIL,
	MLX5_FPGA_IPSEC_CMD_COMPLETE,
};

struct mlx5_fpga_ipsec_sa_v1 {
	__be32 cmd;
	u8 key_enc[32];
	u8 key_auth[32];
	__be32 sip[4];
	__be32 dip[4];
	union {
		struct {
			__be32 reserved;
			u8 salt_iv[8];
			__be32 salt;
		} __packed gcm;
		struct {
			u8 salt[16];
		} __packed cbc;
	};
	__be32 spi;
	__be32 sw_sa_handle;
	__be16 tfclen;
	u8 enc_mode;
	u8 reserved1[2];
	u8 flags;
	u8 reserved2[2];
};

struct mlx5_fpga_ipsec_sa {
	struct mlx5_fpga_ipsec_sa_v1 ipsec_sa_v1;
	__be32 udp_sp;
	__be32 udp_dp;
	__be32 esn;
	__be32 vid:12;
	__be32 reserved3:20;
} __packed;

struct mlx5_ipsec_cmd_resp {
	__be32 syndrome;
	union {
		__be32 sw_sa_handle;
		__be32 flags;
	};
	u8 reserved[24];
} __packed;

struct mlx5_ipsec_command_context {
	struct mlx5_fpga_dma_buf buf;
	enum mlx5_fpga_ipsec_cmd_status status;
	struct mlx5_ipsec_cmd_resp resp;
	int status_code;
	struct completion complete;
	struct mlx5_fpga_device *dev;
	struct list_head list; /* Item in pending_cmds */
	u8 command[0];
};

struct mlx5_fpga_ipsec_notifier_block {
	struct notifier_block           fs_notifier;
	struct mlx5_fpga_device         *fpga_device;
};

struct ipsec_rule {
	struct rb_node                          node;
	struct mlx5_flow_table                  *ft;
	int                                     id;

	struct mlx5_fpga_ipsec_xfrm_ctx         *xfrm_ctx;
	struct mlx5_fpga_ipsec_sa_ctx 		*sa_ctx;
	u32                                     saved_action;
	u32                                     saved_outer_esp_spi_mask;
	u32                                     saved_outer_esp_spi_value;
};

struct mlx5_fpga_ipsec {
	struct list_head pending_cmds;
	spinlock_t pending_cmds_lock; /* Protects pending_cmds */
	u32 caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
	struct mlx5_fpga_conn *conn;
	struct mlx5_fpga_ipsec_notifier_block fs_notifier_ingress;
	struct mlx5_fpga_ipsec_notifier_block fs_notifier_egress;
	struct rhashtable sa_hash;	/* hw_sa -> mlx5_fpga_ipsec_sa_ctx */
	struct mutex sa_hash_lock;
	struct rb_root rules;		/* (ft, id) -> mlx5_fpga_ipsec_sa_ctx */
	struct mutex rules_lock; 	/* lock for rules */
};

struct mlx5_fpga_ipsec_sa_ctx {
	struct rhash_head               hash;
	struct mlx5_fpga_ipsec_sa       hw_sa;
	struct mlx5_core_dev            *dev;
};

struct mlx5_fpga_ipsec_xfrm_ctx {
	unsigned int 			num_rules;
	struct mlx5_fpga_ipsec_sa_ctx   *sa_ctx;
	struct mutex 			lock;
	struct mlx5_accel_esp_xfrm_ctx  accel_xfrm_ctx;
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
		context->status = MLX5_FPGA_IPSEC_CMD_SEND_FAIL;
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
	struct mlx5_ipsec_cmd_resp *resp = buf->sg[0].data;
	struct mlx5_ipsec_command_context *context;
	enum mlx5_ipsec_response_syndrome syndrome;
	struct mlx5_fpga_device *fdev = cb_arg;
	unsigned long flags;

	if (buf->sg[0].size < sizeof(*resp)) {
		mlx5_fpga_warn(fdev, "Short receive from FPGA IPSec: %u < %zu bytes\n",
			       buf->sg[0].size, sizeof(*resp));
		return;
	}

	mlx5_fpga_dbg(fdev, "mlx5_ipsec recv_cb syndrome %08x\n",
		      ntohl(resp->syndrome));

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

	syndrome = ntohl(resp->syndrome);
	context->status_code = syndrome_to_errno(syndrome);
	context->status = MLX5_FPGA_IPSEC_CMD_COMPLETE;
	memcpy(&context->resp, resp, sizeof(*resp));

	if (context->status_code)
		mlx5_fpga_warn(fdev, "IPSec command failed with syndrome %08x\n",
			       syndrome);

	complete(&context->complete);
}

static void *mlx5_fpga_ipsec_cmd_exec(struct mlx5_core_dev *mdev,
				      const void *cmd, int cmd_size)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned long flags;
	int res;

	if (!fdev || !fdev->ipsec)
		return ERR_PTR(-EOPNOTSUPP);

	if (cmd_size & 3)
		return ERR_PTR(-EOPNOTSUPP);

	context = kzalloc(sizeof(*context) + cmd_size, GFP_ATOMIC);
	if (!context)
		return ERR_PTR(-ENOMEM);

	context->status = MLX5_FPGA_IPSEC_CMD_PENDING;
	context->dev = fdev;
	context->buf.complete = mlx5_fpga_ipsec_send_complete;
	init_completion(&context->complete);
	memcpy(&context->command, cmd, cmd_size);
	context->buf.sg[0].size = cmd_size;
	context->buf.sg[0].data = &context->command;

	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	list_add_tail(&context->list, &fdev->ipsec->pending_cmds);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

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

static int mlx5_fpga_ipsec_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	int res;

	res = wait_for_completion_killable(&context->complete);
	if (res) {
		mlx5_fpga_warn(context->dev, "Failure waiting for IPSec command response\n");
		return -EINTR;
	}

	if (context->status == MLX5_FPGA_IPSEC_CMD_COMPLETE)
		res = context->status_code;
	else
		res = -EIO;

	return res;
}

void *mlx5_fpga_ipsec_sa_cmd_exec(struct mlx5_core_dev *mdev,
				  const void *cmd, int cmd_size)
{
	return mlx5_fpga_ipsec_cmd_exec(mdev, cmd, cmd_size);
}

int mlx5_fpga_ipsec_sa_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	struct mlx5_accel_ipsec_sa *sa;
	int res;

	res = mlx5_fpga_ipsec_cmd_wait(ctx);
	if (res)
		goto out;

	sa = (struct mlx5_accel_ipsec_sa *)&context->command;
	if (sa->ipsec_sa_v1.sw_sa_handle != context->resp.sw_sa_handle) {
		mlx5_fpga_err(context->dev, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
			      ntohl(sa->ipsec_sa_v1.sw_sa_handle),
			      ntohl(context->resp.sw_sa_handle));
		res = -EIO;
	}

out:
	kfree(context);
	return res;
}

//TODO: change this function
static int _mlx5_create_update_fpga_ipsec_ctx(struct mlx5_fpga_device *fpga,
		struct mlx5_fpga_ipsec_sa *hw_sa,
		enum mlx5_fpga_ipsec_cmd cmd)
{
	int err;
	size_t sa_cmd_size;
	struct mlx5_fpga_ipsec_sa *sa;
	struct mlx5_ipsec_command_context *mailbox_ctx;
	struct mlx5_core_dev *dev = fpga->mdev;
	struct mlx5_fpga_ipsec *fipsec = fpga->ipsec;

	hw_sa->ipsec_sa_v1.cmd = htonl(cmd);
	if (MLX5_GET(ipsec_extended_cap, fipsec->caps, v2_command))
		sa_cmd_size = sizeof(*hw_sa);
	else
		sa_cmd_size = sizeof(hw_sa->ipsec_sa_v1);

	mailbox_ctx = (struct mlx5_ipsec_command_context *)
		mlx5_fpga_ipsec_cmd_exec(dev, hw_sa, sa_cmd_size);
	if (IS_ERR(mailbox_ctx))
		return PTR_ERR(mailbox_ctx);

	err = mlx5_fpga_ipsec_cmd_wait(mailbox_ctx);
	if (err)
		goto out;

	sa = (struct mlx5_fpga_ipsec_sa *)&mailbox_ctx->command;
	if (sa->ipsec_sa_v1.sw_sa_handle != mailbox_ctx->resp.sw_sa_handle) {
		mlx5_fpga_err(fpga, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
				ntohl(sa->ipsec_sa_v1.sw_sa_handle),
				ntohl(mailbox_ctx->resp.sw_sa_handle));
		err = -EIO;
	}

out:
	kfree(mailbox_ctx);
	return err;
}

u32 mlx5_fpga_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	u32 ret = 0;

	if (mlx5_fpga_is_ipsec_device(mdev))
		ret |= MLX5_ACCEL_IPSEC_DEVICE;
	else
		return ret;

	if (!fdev->ipsec)
		return ret;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, esp))
		ret |= MLX5_ACCEL_IPSEC_ESP;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, ipv6))
		ret |= MLX5_ACCEL_IPSEC_IPV6;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, lso))
		ret |= MLX5_ACCEL_IPSEC_LSO;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, rx_no_trailer))
		ret |= MLX5_ACCEL_IPSEC_NO_TRAILER;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, v2_command))
		ret |= MLX5_ACCEL_IPSEC_V2_CMD;

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

static int mlx5_fpga_ipsec_set_caps(struct mlx5_core_dev *mdev, u32 flags)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_accel_ipsec_cap cmd = {0};
	int err;

	cmd.cmd = htonl(MLX5_FPGA_IPSEC_CMD_SET_CAP);
	cmd.flags = htonl(flags);
	context = mlx5_fpga_ipsec_cmd_exec(mdev, &cmd, sizeof(cmd));
	if (IS_ERR(context)) {
		err = PTR_ERR(context);
		goto out;
	}

	err = mlx5_fpga_ipsec_cmd_wait(context);
	if (err)
		goto out;

	if ((context->resp.flags & cmd.flags) != cmd.flags) {
		mlx5_fpga_err(context->dev, "Failed to set capabilities. cmd 0x%08x vs resp 0x%08x\n",
			      cmd.flags,
			      context->resp.flags);
		err = -EIO;
	}

out:
	return err;
}

static int mlx5_fpga_ipsec_enable_supported_caps(struct mlx5_core_dev *mdev)
{
	u32 dev_caps = mlx5_fpga_ipsec_device_caps(mdev);
	u32 flags = 0;

	if (dev_caps & MLX5_ACCEL_IPSEC_NO_TRAILER)
		flags |= MLX5_IPSEC_CAPS_NO_TRAILER;

	return mlx5_fpga_ipsec_set_caps(mdev, flags);
}


static void mlx5_fpga_ipsec_build_hw_sa_xfrm(struct mlx5_core_dev *mdev,
					     const struct mlx5_accel_esp_xfrm_attrs *xfrm_attrs,
					     struct mlx5_fpga_ipsec_sa *hw_sa)
{
	const struct aes_gcm_keymat *aes_gcm = &xfrm_attrs->keymat.aes_gcm;

	/* key */
	memcpy(&hw_sa->ipsec_sa_v1.key_enc, aes_gcm->aes_key, aes_gcm->key_len);
	/* Duplicate 128 bit key twice according to HW layout */
	if (aes_gcm->key_len == 128)
		memcpy(&hw_sa->ipsec_sa_v1.key_enc[16],
		       aes_gcm->aes_key, aes_gcm->key_len);

	/* salt and seq_iv */
	memcpy(&hw_sa->ipsec_sa_v1.gcm.salt_iv, &aes_gcm->seq_iv, sizeof(aes_gcm->seq_iv));
	hw_sa->ipsec_sa_v1.gcm.salt = aes_gcm->salt;

	/* esn */
	if (xfrm_attrs->flags & MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED) {
		hw_sa->ipsec_sa_v1.flags |= MLX5_FPGA_IPSEC_SADB_ESN_EN;
		hw_sa->ipsec_sa_v1.flags |=
				(xfrm_attrs->flags & MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP) ?
						MLX5_FPGA_IPSEC_SADB_ESN_OVERLAP : 0;
		hw_sa->esn = htonl(xfrm_attrs->esn);
	} else {
		hw_sa->ipsec_sa_v1.flags &= ~MLX5_FPGA_IPSEC_SADB_ESN_EN;
		hw_sa->ipsec_sa_v1.flags &=
				~(xfrm_attrs->flags & MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP) ?
						MLX5_FPGA_IPSEC_SADB_ESN_OVERLAP : 0;
		hw_sa->esn = 0;
	}

	/* rx handle */
	hw_sa->ipsec_sa_v1.sw_sa_handle = htonl(xfrm_attrs->sa_handle);

	/* enc mode */
	switch (aes_gcm->key_len) {
	case 128:
		hw_sa->ipsec_sa_v1.enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_128_AUTH_128;
		break;
	case 256:
		hw_sa->ipsec_sa_v1.enc_mode = MLX5_IPSEC_SADB_MODE_AES_GCM_256_AUTH_128;
		break;
	}
	if (xfrm_attrs->action & MLX5_FLOW_CONTEXT_ACTION_ENCRYPT)
		hw_sa->ipsec_sa_v1.flags |= MLX5_IPSEC_SADB_DIR_SX;

	/* flags */
	hw_sa->ipsec_sa_v1.flags |= MLX5_FPGA_IPSEC_SADB_SA_VALID |
				    MLX5_FPGA_IPSEC_SADB_SPI_EN |
				    MLX5_FPGA_IPSEC_SADB_IP_ESP;

	if (xfrm_attrs->action & MLX5_FLOW_CONTEXT_ACTION_ENCRYPT)
		hw_sa->ipsec_sa_v1.flags |= MLX5_IPSEC_SADB_DIR_SX;
	else
		hw_sa->ipsec_sa_v1.flags &= ~MLX5_IPSEC_SADB_DIR_SX;
}
					     


static void mlx5_fpga_ipsec_build_hw_sa(struct mlx5_core_dev *mdev,
					struct mlx5_fs_rule_notifier_attrs *rule_attrs,
					struct mlx5_accel_esp_xfrm_attrs *xfrm_attrs,
					struct mlx5_fpga_ipsec_sa *hw_sa)
{
	bool is_ipv6 = false;

	memset(hw_sa, 0, sizeof(*hw_sa));

	mlx5_fpga_ipsec_build_hw_sa_xfrm(mdev, xfrm_attrs, hw_sa);

	/* ips */
	if (mlx5_fs_is_outer_ipv4_flow(mdev, rule_attrs->spec.match_criteria,
				       rule_attrs->spec.match_value)) {
		memcpy(&hw_sa->ipsec_sa_v1.sip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    rule_attrs->spec.match_value,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
				    sizeof(hw_sa->ipsec_sa_v1.sip[3]));
		memcpy(&hw_sa->ipsec_sa_v1.dip[3],
		       MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    rule_attrs->spec.match_value,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
				    sizeof(hw_sa->ipsec_sa_v1.dip[3]));
	} else {
		memcpy(hw_sa->ipsec_sa_v1.sip,
		       MLX5_ADDR_OF(fte_match_param,
				    rule_attrs->spec.match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
				    sizeof(hw_sa->ipsec_sa_v1.sip));
		memcpy(hw_sa->ipsec_sa_v1.dip,
		       MLX5_ADDR_OF(fte_match_param, rule_attrs->spec.match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
				    sizeof(hw_sa->ipsec_sa_v1.dip));
		is_ipv6 = true;
	}

	/* spi */
	hw_sa->ipsec_sa_v1.spi =
			MLX5_GET_BE(typeof(hw_sa->ipsec_sa_v1.spi),
				    fte_match_param, rule_attrs->spec.match_value,
				    misc_parameters.outer_esp_spi);

	if (is_ipv6)
		hw_sa->ipsec_sa_v1.flags |= MLX5_FPGA_IPSEC_SADB_IPV6;
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
		const void *s_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4,
						    headers_c,
						    src_ipv4_src_ipv6.ipv4_layout.ipv4);
		const void *d_ipv4_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4,
						    headers_c,
						    dst_ipv4_dst_ipv6.ipv4_layout.ipv4);

		if (!is_full_mask(s_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)) ||
		    !is_full_mask(d_ipv4_c, MLX5_FLD_SZ_BYTES(ipv4_layout,
							      ipv4)))
			return false;
	} else {
		const void *s_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4,
						    headers_c,
						    src_ipv4_src_ipv6.ipv6_layout.ipv6);
		const void *d_ipv6_c = MLX5_ADDR_OF(fte_match_set_lyr_2_4,
						     headers_c,
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

static bool mlx5_is_fpga_ipsec_rule(struct mlx5_core_dev *dev,
				    u8 match_criteria_enable,
				    const u32 *match_c,
				    const u32 *match_v)
{
	u32 ipsec_dev_caps = mlx5_accel_ipsec_device_caps(dev);
	bool ipv6_flow;

	ipv6_flow = mlx5_fs_is_outer_ipv6_flow(dev, match_c, match_v);

	if (!(match_criteria_enable & 1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS) ||
	    mlx5_fs_is_outer_udp_flow(match_c, match_v) ||
	    mlx5_fs_is_outer_tcp_flow(match_c, match_v) ||
	    mlx5_fs_is_vxlan_flow(match_c) ||
	    !(mlx5_fs_is_outer_ipv4_flow(dev, match_c, match_v) ||
	      ipv6_flow))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_DEVICE))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_ESP) &&
	    mlx5_fs_is_outer_ipsec_flow(match_c))
		return false;

	if (!(ipsec_dev_caps & MLX5_ACCEL_IPSEC_IPV6) &&
	    ipv6_flow)
		return false;

	if (!validate_fpga_full_mask(dev, match_c, match_v))
		return false;

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

	ret = mlx5_is_fpga_ipsec_rule(dev, match_criteria_enable, match_c,
				      match_v);
	if (!ret)
		return ret;

	if (is_dmac || is_smac ||
	    (match_criteria_enable &
		~((1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS) |
		  (1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_MISC_PARAMETERS))) ||
	    (flow_act->action & ~(MLX5_FLOW_CONTEXT_ACTION_ENCRYPT | MLX5_FLOW_CONTEXT_ACTION_ALLOW)) ||
	     flow_act->has_flow_tag)
		return false;

	return true;
}

static int mlx5_create_fpga_ipsec_ctx(struct mlx5_fpga_device *fpga,
				      struct mlx5_fs_rule_notifier_attrs *attrs,
				      bool is_egress)
{
	struct mlx5_fpga_ipsec_sa_ctx *sa_ctx;
	struct mlx5_core_dev *dev = fpga->mdev;
	struct mlx5_fpga_ipsec *fipsec = fpga->ipsec;
	struct mlx5_accel_esp_xfrm_ctx *accel_xfrm_ctx;
	struct mlx5_fpga_ipsec_xfrm_ctx *ctx;
	enum mlx5_fpga_ipsec_cmd cmd;
	int err = 0;

	if (is_egress) {
		if (!mlx5_is_fpga_egress_ipsec_rule(dev, *attrs->spec.match_criteria_enable,
						    attrs->spec.match_criteria,
						    attrs->spec.match_value,
						    attrs->spec.flow_act))
			return -EINVAL;
	} else if (!mlx5_is_fpga_ipsec_rule(dev,
					    *attrs->spec.match_criteria_enable,
					    attrs->spec.match_criteria,
					    attrs->spec.match_value)) {
		return -EINVAL;
	}
	accel_xfrm_ctx = (struct mlx5_accel_esp_xfrm_ctx *)attrs->spec.flow_act->esp_id;
	ctx = container_of(accel_xfrm_ctx, typeof(*ctx), accel_xfrm_ctx);

	sa_ctx = kzalloc(sizeof(*sa_ctx), GFP_KERNEL);
	if (!sa_ctx)
		return -ENOMEM;

	sa_ctx->dev = dev;
	mlx5_fpga_ipsec_build_hw_sa(dev, attrs, &accel_xfrm_ctx->attrs, &sa_ctx->hw_sa);

	mutex_lock(&ctx->lock);
	if (ctx->sa_ctx) {	/* multiple rules for same accel_xfrm_ctx */
		/* all rules must be with same ips and spi */
		if (memcmp(&sa_ctx->hw_sa, &ctx->sa_ctx->hw_sa, sizeof(sa_ctx->hw_sa))) {
			err = -EINVAL;
			goto exists;
		}

		ctx->num_rules++;
		err = 0;
		goto exists;
	}

	/* this is unbounded accel_xfrm_ctx */
	mutex_lock(&fipsec->sa_hash_lock);
	err = rhashtable_lookup_insert_fast(&fipsec->sa_hash, &sa_ctx->hash,
					    rhash_sa);
	if (err)
		/* can't bound different accel_xfrm_ctx to same sa_ctx */
		goto unlock_hash;

	/* bound accel_xxfrm_ctx */
	cmd = MLX5_GET(ipsec_extended_cap, fipsec->caps, v2_command) ? 
		MLX5_FPGA_IPSEC_CMD_ADD_SA_V2 : MLX5_FPGA_IPSEC_CMD_ADD_SA;
	err = _mlx5_create_update_fpga_ipsec_ctx(fpga, &sa_ctx->hw_sa, cmd);
	if (err)
		goto delete_hash;

	mutex_unlock(&fipsec->sa_hash_lock);

	ctx->num_rules++;
	ctx->sa_ctx = sa_ctx;
	mutex_unlock(&ctx->lock);

	return 0;

delete_hash:
	WARN_ON(rhashtable_remove_fast(&fipsec->sa_hash, &sa_ctx->hash,
			       	       rhash_sa));
unlock_hash:
	mutex_unlock(&fipsec->sa_hash_lock);
exists:
	mutex_unlock(&ctx->lock);
	kfree(sa_ctx);
	return err;
}

static void mlx5_release_fpga_ipsec_sa_ctx(struct mlx5_fpga_ipsec_sa_ctx *sa_ctx)
{
	struct mlx5_fpga_ipsec *fipsec = sa_ctx->dev->fpga->ipsec;
	int sa_cmd_size;
	void *context;

	if (MLX5_GET(ipsec_extended_cap, fipsec->caps, v2_command)) {
		sa_ctx->hw_sa.ipsec_sa_v1.cmd =
				htonl(MLX5_FPGA_IPSEC_CMD_DEL_SA_V2);
		sa_cmd_size = sizeof(sa_ctx->hw_sa);
	} else {
		sa_ctx->hw_sa.ipsec_sa_v1.cmd =
				htonl(MLX5_FPGA_IPSEC_CMD_DEL_SA);
		sa_cmd_size = sizeof(sa_ctx->hw_sa.ipsec_sa_v1);
	}

	context = mlx5_fpga_ipsec_sa_cmd_exec(sa_ctx->dev,
					      &sa_ctx->hw_sa, sa_cmd_size);
	if (WARN_ON(context))
		return;

	WARN_ON(mlx5_accel_ipsec_sa_cmd_wait(context));

	mutex_lock(&fipsec->sa_hash_lock);
	WARN_ON(rhashtable_remove_fast(&fipsec->sa_hash, &sa_ctx->hash,
				       rhash_sa));
	mutex_unlock(&fipsec->sa_hash_lock);
}

static void mlx5_delete_fpga_xfrm_ctx(struct mlx5_fpga_ipsec_xfrm_ctx *ctx)
{
	mutex_lock(&ctx->lock);
	if (--ctx->num_rules) {
		mlx5_release_fpga_ipsec_sa_ctx(ctx->sa_ctx);
		ctx->sa_ctx = NULL;
	}
	mutex_unlock(&ctx->lock);
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

static struct ipsec_rule *_rule_search(struct rb_root *root,
			       struct mlx5_flow_table *ft,
			       int id)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct ipsec_rule *rule = container_of(node, struct ipsec_rule,
						       node);
		int result;

		result = compare_keys(ft, id, rule->ft, rule->id);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return rule;
	}
	return NULL;
}

static struct ipsec_rule *rule_search(struct mlx5_fpga_ipsec *ipsec_dev,
				      struct mlx5_flow_table *ft,
				      int id)
{
	struct ipsec_rule *rule;

	mutex_lock(&ipsec_dev->rules_lock);
	rule = _rule_search(&ipsec_dev->rules, ft, id);
	mutex_unlock(&ipsec_dev->rules_lock);

	return rule;
}

static int _rule_insert(struct rb_root *root, struct ipsec_rule *rule)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct ipsec_rule *this =
			container_of(*new, struct ipsec_rule, node);
		int result = compare_keys(rule->ft, rule->id,
					  this->ft, this->id);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&rule->node, parent, new);
	rb_insert_color(&rule->node, root);

	return 0;
}

static int rule_insert(struct mlx5_fpga_ipsec *ipsec_dev,
		       struct ipsec_rule *rule)
{
	int ret;

	mutex_lock(&ipsec_dev->rules_lock);
	ret = _rule_insert(&ipsec_dev->rules, rule);
	mutex_unlock(&ipsec_dev->rules_lock);

	return ret;
}

static int _rule_delete(struct rb_root *root, struct ipsec_rule *rule)
{
	if (rule) {
		rb_erase(&rule->node, root);
		kfree(rule);
		return 0;
	}
	return -ENOENT;
}

static int rule_delete(struct mlx5_fpga_ipsec *ipsec_dev,
		       struct ipsec_rule *rule)
{
	int ret;

	mutex_lock(&ipsec_dev->rules_lock);
	ret = _rule_delete(&ipsec_dev->rules, rule);
	mutex_unlock(&ipsec_dev->rules_lock);

	return ret;
}

static void restore_spec_mailbox(struct ipsec_rule *rule,
			  struct mlx5_fs_rule_notifier_attrs *attrs)
{
	char *misc_params_c = MLX5_ADDR_OF(fte_match_param,
					   attrs->spec.match_criteria,
					   misc_parameters);
	char *misc_params_v = MLX5_ADDR_OF(fte_match_param,
					   attrs->spec.match_value,
					   misc_parameters);

	MLX5_SET(fte_match_set_misc, misc_params_c, outer_esp_spi,
		 rule->saved_outer_esp_spi_mask);
	MLX5_SET(fte_match_set_misc, misc_params_v, outer_esp_spi,
		 rule->saved_outer_esp_spi_value);
	attrs->spec.flow_act->action |= rule->saved_action;
	attrs->spec.flow_act->esp_id = (uintptr_t)rule->xfrm_ctx;
}

static void modify_spec_mailbox(struct mlx5_core_dev *mdev,
				struct mlx5_fs_rule_notifier_attrs *attrs,
				struct ipsec_rule *rule,
				bool is_egress)
{
	struct mlx5_accel_esp_xfrm_ctx *accel_xfrm_ctx =
		(struct mlx5_accel_esp_xfrm_ctx *)attrs->spec.flow_act->esp_id;
	char *misc_params_c = MLX5_ADDR_OF(fte_match_param,
					   attrs->spec.match_criteria,
					   misc_parameters);
	char *misc_params_v = MLX5_ADDR_OF(fte_match_param,
					   attrs->spec.match_value,
					   misc_parameters);

	rule->saved_action = attrs->spec.flow_act->action &
		(MLX5_FLOW_CONTEXT_ACTION_ENCRYPT |
		 MLX5_FLOW_CONTEXT_ACTION_DECRYPT);

	rule->xfrm_ctx = container_of(accel_xfrm_ctx,
				      struct mlx5_fpga_ipsec_xfrm_ctx,
				      accel_xfrm_ctx);

	rule->saved_outer_esp_spi_mask =
			MLX5_GET(fte_match_set_misc, misc_params_c,
				 outer_esp_spi);
	rule->saved_outer_esp_spi_value =
			MLX5_GET(fte_match_set_misc, misc_params_v,
				 outer_esp_spi);

	attrs->spec.flow_act->action &= ~(MLX5_FLOW_CONTEXT_ACTION_ENCRYPT |
					  MLX5_FLOW_CONTEXT_ACTION_DECRYPT);
	attrs->spec.flow_act->esp_id = 0;
	if (!MLX5_CAP_FLOWTABLE(mdev,
				flow_table_properties_nic_receive.ft_field_support.outer_esp_spi) &&
	    !is_egress) {
		MLX5_SET(fte_match_set_misc, misc_params_c,
			 outer_esp_spi, 0);
		MLX5_SET(fte_match_set_misc, misc_params_v,
			 outer_esp_spi, 0);
		if (!(*misc_params_c) &&
		    !memcmp(misc_params_c, misc_params_c + 1,
		            MLX5_ST_SZ_BYTES(fte_match_set_misc) - 1))
			*attrs->spec.match_criteria_enable &=
					~(1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_MISC_PARAMETERS);
	}
}


static int fpga_fs_rule_notifier(struct notifier_block *nb, unsigned long action,
				 void *data, bool is_egress)
{
	struct mlx5_fpga_ipsec_notifier_block *fpga_nb =
		container_of(nb, struct mlx5_fpga_ipsec_notifier_block,
			     fs_notifier);
	struct mlx5_fpga_device *fdev = fpga_nb->fpga_device;
	struct mlx5_fpga_ipsec *ipsec = fdev->ipsec;
	struct mlx5_core_dev *mdev = fdev->mdev;
	struct mlx5_fs_rule_notifier_attrs *attrs = data;
	bool is_esp = attrs->spec.flow_act->esp_id;
	struct ipsec_rule *rule;
	int ret;

	switch (action) {
	case MLX5_FS_RULE_NOTIFY_ADD_PRE:
		if (!is_esp ||
		    !(attrs->spec.flow_act->action &
		      (MLX5_FLOW_CONTEXT_ACTION_ENCRYPT |
		       MLX5_FLOW_CONTEXT_ACTION_DECRYPT)))
			return NOTIFY_DONE;

		rule = kzalloc(sizeof(*rule), GFP_KERNEL);
		if (!rule)
			return notifier_from_errno(-ENOMEM);

		ret = mlx5_create_fpga_ipsec_ctx(fdev, attrs, is_egress);
		if (ret) {
			kfree(rule);
			return notifier_from_errno(ret);
		}

		rule->ft = attrs->ft;
		rule->id = attrs->id;
		modify_spec_mailbox(mdev, attrs, rule, is_egress);
		WARN_ON(rule_insert(ipsec, rule));
		break;

	case MLX5_FS_RULE_NOTIFY_ADD_POST:
		rule = rule_search(ipsec, attrs->ft, attrs->id);
		if (!rule)
			break;

		restore_spec_mailbox(rule, attrs);
		if (!attrs->success) {
			mlx5_delete_fpga_xfrm_ctx(rule->xfrm_ctx);
			rule_delete(ipsec, rule);
		}
		break;

	case MLX5_FS_RULE_NOTIFY_DEL:
		rule = rule_search(ipsec, attrs->ft, attrs->id);
		if (!rule)
			break;

		mlx5_delete_fpga_xfrm_ctx(rule->xfrm_ctx);
		rule_delete(ipsec, rule);
		break;
	}

	return NOTIFY_DONE;
}

static int fpga_fs_rule_notifier_egress(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	return fpga_fs_rule_notifier(nb, action, data, true);
}

static int fpga_fs_rule_notifier_ingress(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	return fpga_fs_rule_notifier(nb, action, data, false);
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
				  fpga_fs_rule_notifier_ingress);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to register ingress rule notifier: %d\n",
			      err);
		goto error;
	}

	err = init_notifier_block(fdev, &fdev->ipsec->fs_notifier_egress,
				  MLX5_FLOW_NAMESPACE_EGRESS,
				  fpga_fs_rule_notifier_egress);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to register egress rule notifier: %d\n",
			      err);
		goto err_unregister_notifier_ingress;
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
		goto err_unregister_notifier_egress;
	}
	fdev->ipsec->conn = conn;

	err = rhashtable_init(&fdev->ipsec->sa_hash, &rhash_sa);
	if (err)
		goto err_destroy_conn;

	err = mlx5_fpga_ipsec_enable_supported_caps(mdev);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to enable IPSec extended capabilities: %d\n",
			      err);
		goto err_destroy_hash;
	}

	return 0;

err_destroy_hash:
	rhashtable_destroy(&fdev->ipsec->sa_hash);

err_destroy_conn:
	mlx5_fpga_sbu_conn_destroy(conn);

err_unregister_notifier_egress:
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev,
						 MLX5_FLOW_NAMESPACE_EGRESS,
						 &fdev->ipsec->fs_notifier_egress.fs_notifier));

err_unregister_notifier_ingress:
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev,
						 MLX5_FLOW_NAMESPACE_BYPASS,
						 &fdev->ipsec->fs_notifier_ingress.fs_notifier));
error:
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
	return err;
}

static void destroy_rules_rb(struct rb_root *root)
{
	struct ipsec_rule *r, *tmp;

	rbtree_postorder_for_each_entry_safe(r, tmp, root, node) {
		rb_erase(&r->node, root);
		mlx5_delete_fpga_xfrm_ctx(r->xfrm_ctx);
		kfree(r);
	}
}

void mlx5_fpga_ipsec_cleanup(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return;

	destroy_rules_rb(&fdev->ipsec->rules);
	rhashtable_destroy(&fdev->ipsec->sa_hash);
	mlx5_fpga_sbu_conn_destroy(fdev->ipsec->conn);
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev,
						 MLX5_FLOW_NAMESPACE_EGRESS,
						 &fdev->ipsec->fs_notifier_egress.fs_notifier));
	WARN_ON(mlx5_fs_rule_notifier_unregister(mdev,
						 MLX5_FLOW_NAMESPACE_BYPASS,
						 &fdev->ipsec->fs_notifier_ingress.fs_notifier));
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
}

int mlx5_fpga_esp_validate_xfrm_attrs(struct mlx5_core_dev *mdev,
				      const struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	if ((attrs->flags != MLX5_ACCEL_ESP_FLAGS_TUNNEL) &&
	    (attrs->flags != MLX5_ACCEL_ESP_FLAGS_TUNNEL)) {
		mlx5_core_err(mdev, "Only transport and tunnel xfrm states may be offloaded\n");
		return -EOPNOTSUPP;
	}

	if (attrs->tfc_pad) {
		mlx5_core_err(mdev, "Cannot offload xfrm states with tfc padding\n");
		return -EOPNOTSUPP;
	}

	if (attrs->replay_type != MLX5_ACCEL_ESP_REPLAY_NONE) {
		mlx5_core_err(mdev, "Cannot offload xfrm states with anti replay\n");
		return -EOPNOTSUPP;
	}

	if (attrs->keymat_type != MLX5_ACCEL_ESP_KEYMAT_AES_GCM) {
		mlx5_core_err(mdev, "Only aes gcm keymat is supported\n");
		return -EOPNOTSUPP;
	}

	if (attrs->keymat.aes_gcm.iv_algo != MLX5_ACCEL_ESP_AES_GCM_IV_ALGO_SEQ) {
		mlx5_core_err(mdev, "Only iv sequence algo is supported\n");
		return -EOPNOTSUPP;
	}

	if (attrs->keymat.aes_gcm.icv_len != 128) {
		mlx5_core_err(mdev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EOPNOTSUPP;
	}

	if ((attrs->keymat.aes_gcm.key_len != 128) &&
	    (attrs->keymat.aes_gcm.key_len != 256)) {
		mlx5_core_err(mdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EOPNOTSUPP;
	}

	if ((attrs->flags & MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED) &&
	    (!MLX5_GET(ipsec_extended_cap, mdev->fpga->ipsec->caps, v2_command))) {
		mlx5_core_err(mdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

struct mlx5_accel_esp_xfrm_ctx *mlx5_fpga_esp_create_xfrm_ctx(struct mlx5_core_dev *mdev,
							      const struct mlx5_accel_esp_xfrm_attrs *attrs,
							      u32 flags)
{
	struct mlx5_fpga_ipsec_xfrm_ctx *ctx;

	if (!(flags & MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA)) {
		mlx5_core_warn(mdev, "Tried to create an esp action without metadata\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (!mlx5_fpga_esp_validate_xfrm_attrs(mdev, attrs)) {
		mlx5_core_warn(mdev, "Tried to create an esp with unsupported attrs\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	mutex_init(&ctx->lock);

	memcpy(&ctx->accel_xfrm_ctx.attrs, attrs,
	       sizeof(ctx->accel_xfrm_ctx.attrs));

	return &ctx->accel_xfrm_ctx;
}

void mlx5_fpga_esp_destroy_xfrm_ctx(struct mlx5_accel_esp_xfrm_ctx *ctx)
{
	struct mlx5_fpga_ipsec_xfrm_ctx *fpga_ctx =
			container_of(ctx, struct mlx5_fpga_ipsec_xfrm_ctx, accel_xfrm_ctx);
	/* assuming no sa_ctx are connected to this xfrm_ctx */
	kfree(fpga_ctx);
}

int mlx5_fpga_esp_modify_xfrm_ctx(struct mlx5_accel_esp_xfrm_ctx *xfrm,
				  const struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	struct mlx5_core_dev *mdev = xfrm->mdev;
	struct mlx5_fpga_device *fpga_dev = mdev->fpga;
	struct mlx5_fpga_ipsec_xfrm_ctx *fpga_ctx;
	struct mlx5_fpga_ipsec_sa hw_sa;
	struct mlx5_fpga_ipsec *fipsec = mdev->fpga->ipsec;
	int err = 0;

	if (!memcmp(&xfrm->attrs, attrs, sizeof(xfrm->attrs)))
		return 0;

	if (!mlx5_fpga_esp_validate_xfrm_attrs(mdev, attrs)) {
		mlx5_core_warn(mdev, "Tried to create an esp with unsupported attrs\n");
		return -EOPNOTSUPP;
	}

	if (!MLX5_GET(ipsec_extended_cap, fipsec->caps, v2_command)) {
		mlx5_core_warn(mdev, "Modify esp is not supported\n");
		return -EOPNOTSUPP;
	}

	fpga_ctx = container_of(xfrm, struct mlx5_fpga_ipsec_xfrm_ctx,
			        accel_xfrm_ctx);

	mutex_lock(&fpga_ctx->lock);

	if (!fpga_ctx->sa_ctx)
		goto change_sw_rep;

	memcpy(&hw_sa, &fpga_ctx->sa_ctx->hw_sa, sizeof(hw_sa));
	mutex_lock(&fipsec->sa_hash_lock);
	WARN_ON(rhashtable_remove_fast(&fipsec->sa_hash, &fpga_ctx->sa_ctx->hash,
				       rhash_sa));
	mlx5_fpga_ipsec_build_hw_sa_xfrm(xfrm->mdev, attrs, &fpga_ctx->sa_ctx->hw_sa);
	err = rhashtable_insert_fast(&fipsec->sa_hash,
			&fpga_ctx->sa_ctx->hash,
			rhash_sa);
	if (err)
		goto rollback_sa;

	err = _mlx5_create_update_fpga_ipsec_ctx(fpga_dev, &hw_sa,
			MLX5_FPGA_IPSEC_CMD_MOD_SA_V2);

	if (err)
		WARN_ON(rhashtable_remove_fast(&fipsec->sa_hash, &fpga_ctx->sa_ctx->hash,
					rhash_sa));
rollback_sa:
	if (err) {
		memcpy(&fpga_ctx->sa_ctx->hw_sa, &hw_sa, sizeof(hw_sa));
		WARN_ON(rhashtable_insert_fast(&fipsec->sa_hash,
					&fpga_ctx->sa_ctx->hash,
					rhash_sa));
	}
	mutex_unlock(&fipsec->sa_hash_lock);
change_sw_rep:
	if (!err)
		memcpy(&xfrm->attrs, attrs, sizeof(xfrm->attrs));
	mutex_unlock(&fpga_ctx->lock);
	return err;
}
