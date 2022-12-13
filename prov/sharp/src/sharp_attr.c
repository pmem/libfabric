/*
 * Copyright (c) 2022 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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

#include "sharp.h"

#define SHARP_TX_CAPS (FI_COLLECTIVE)
#define SHARP_RX_CAPS (FI_COLLECTIVE)


struct fi_tx_attr sharp_tx_attr = {
	.caps = SHARP_TX_CAPS,
	.op_flags = SHARP_TX_OP_FLAGS,
	.comp_order = FI_ORDER_NONE,
	.msg_order = ~0x0ULL,
	.size = SHARP_TX_SIZE,
	.iov_limit = SHARP_IOV_LIMIT,
	.rma_iov_limit = SHARP_IOV_LIMIT
};

struct fi_rx_attr sharp_rx_attr = {
	.caps = SHARP_RX_CAPS,
	.op_flags = SHARP_RX_OP_FLAGS,
	.comp_order = FI_ORDER_NONE,
	.msg_order = ~0x0ULL,
	.size = SHARP_RX_SIZE,
	.iov_limit = SHARP_IOV_LIMIT
};

struct fi_ep_attr sharp_ep_attr = {
	.type = FI_EP_RDM,
	.protocol = FI_PROTO_COLL,
	.protocol_version = 1,
	.max_msg_size = SIZE_MAX,
	.max_order_raw_size = SIZE_MAX,
	.max_order_waw_size = SIZE_MAX,
	.max_order_war_size = SIZE_MAX,
	.mem_tag_format = FI_TAG_GENERIC >> 1,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1
};

struct fi_domain_attr sharp_domain_attr = {
	.name = "sharp",
	.caps = SHARP_DOMAIN_CAPS,
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.resource_mgmt = FI_RM_ENABLED,
	.av_type = FI_AV_UNSPEC,
	.mr_mode = 0,
	.mr_key_size = sizeof_field(struct fi_rma_iov, key),  /* XXX */
	.cq_data_size = sizeof_field(struct ofi_op_hdr, data),
	.cq_cnt = 1024,
	.ep_cnt = 1,
	.tx_ctx_cnt = 1,
	.rx_ctx_cnt = 1,
	.max_ep_tx_ctx = 1,
	.max_ep_rx_ctx = 1,
	.mr_iov_limit = SHARP_IOV_LIMIT,
};

struct fi_fabric_attr sharp_fabric_attr = {
	.name = "sharp",
	.prov_version = OFI_VERSION_DEF_PROV
};

struct fi_info sharp_info = {
	.caps = SHARP_TX_CAPS | SHARP_RX_CAPS | SHARP_DOMAIN_CAPS | FI_COLLECTIVE,
	.addr_format = FI_ADDR_STR,
	.tx_attr = &sharp_tx_attr,
	.rx_attr = &sharp_rx_attr,
	.ep_attr = &sharp_ep_attr,
	.domain_attr = &sharp_domain_attr,
	.fabric_attr = &sharp_fabric_attr
};
