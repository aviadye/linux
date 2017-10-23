/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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
 */

#ifndef IB_USER_IOCTL_VERBS_H
#define IB_USER_IOCTL_VERBS_H

#include <rdma/rdma_user_ioctl.h>

#define UVERBS_UDATA_DRIVER_DATA_NS	1
#define UVERBS_UDATA_DRIVER_DATA_FLAG	(1UL << UVERBS_ID_NS_SHIFT)

enum uverbs_default_objects {
	UVERBS_OBJECT_DEVICE, /* No instances of DEVICE are allowed */
	UVERBS_OBJECT_PD,
	UVERBS_OBJECT_COMP_CHANNEL,
	UVERBS_OBJECT_CQ,
	UVERBS_OBJECT_QP,
	UVERBS_OBJECT_SRQ,
	UVERBS_OBJECT_AH,
	UVERBS_OBJECT_MR,
	UVERBS_OBJECT_MW,
	UVERBS_OBJECT_FLOW,
	UVERBS_OBJECT_FLOW_ACTION,
	UVERBS_OBJECT_XRCD,
	UVERBS_OBJECT_RWQ_IND_TBL,
	UVERBS_OBJECT_WQ,
	UVERBS_OBJECT_LAST,
};

enum {
	UVERBS_UHW_IN = UVERBS_UDATA_DRIVER_DATA_FLAG,
	UVERBS_UHW_OUT,
};

enum uverbs_create_cq_cmd_attr_ids {
	CREATE_CQ_HANDLE,
	CREATE_CQ_CQE,
	CREATE_CQ_USER_HANDLE,
	CREATE_CQ_COMP_CHANNEL,
	CREATE_CQ_COMP_VECTOR,
	CREATE_CQ_FLAGS,
	CREATE_CQ_RESP_CQE,
};

enum uverbs_destroy_cq_cmd_attr_ids {
	DESTROY_CQ_HANDLE,
	DESTROY_CQ_RESP,
};

enum uverbs_flow_action_esp_keymat {
	FLOW_ACTION_ESP_KEYMAT_AES_GCM,
};

enum ib_uverbs_flow_action_esp_aes_gcm_keymat_iv_algo {
	IB_UVERBS_FLOW_ACTION_IV_ALGO_SEQ,
};

struct ib_uverbs_flow_action_esp_keymat_aes_gcm {
	__u64	iv;
	__u32	iv_algo; /* Use enum ib_uverbs_flow_action_iv_algo */

	__u32   salt;
	__u32	icv_len;

	__u32	key_len;
	__u32   aes_key[256 / 32];
};

enum uverbs_flow_action_esp_replay {
	FLOW_ACTION_ESP_REPLAY_NONE,
	FLOW_ACTION_ESP_REPLAY_BMP,
};

struct ib_uverbs_flow_action_esp_replay_bmp {
	__u32	size;
};

enum uverbs_create_flow_action_esp {
	FLOW_ACTION_ESP_HANDLE,
	FLOW_ACTION_ESP_ATTRS,
	FLOW_ACTION_ESP_ESN,
	FLOW_ACTION_ESP_KEYMAT,
	FLOW_ACTION_ESP_REPLAY,
	FLOW_ACTION_ESP_ENCAP,
};

enum uverbs_destroy_flow_action_esp {
	DESTROY_FLOW_ACTION_HANDLE,
};

enum uverbs_actions_cq_ops {
	UVERBS_CQ_CREATE,
	UVERBS_CQ_DESTROY,
};

enum uverbs_actions_flow_action_ops {
	UVERBS_FLOW_ACTION_ESP_CREATE,
	UVERBS_FLOW_ACTION_DESTROY,
};

enum ib_uverbs_flow_action_esp_flags {
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_INLINE_CRYPTO	= 0,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_FULL_OFFLAOD	= 1UL << 0,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TUNNEL		= 0,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TRANSPORT	= 1UL << 1,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_DECRYPT		= 0,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ENCRYPT		= 1UL << 2,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ESN_NEW_WINDOW	= 1UL << 3,
};

struct ib_uverbs_flow_action_esp_encap {
	__u64	mask_ptr;	/* pointer to struct ib_uverbs_flow_xxxx_filter */
	__u64	val_ptr;	/* pointer to struct ib_uverbs_flow_xxxx_filter */
	__u64	next_ptr;	/* pointer to struct ib_uverbs_flow_action_esp_encap or NULL */
	__u16	len;		/* Len of mask and pointer (separately) */
	__u16	type;		/* Use flow_spec enum */
};

struct ib_uverbs_flow_action_esp {
	__u32	spi;
	__u32	seq;
	__u32	tfc_pad;
	__u32	flags;
	__u64	hard_limit_pkts;
};

#endif

