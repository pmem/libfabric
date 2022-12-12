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

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <ofi.h>

#include "rxm.h"

static int rxm_eq_close(struct fid *fid)
{
	struct rxm_eq *rxm_eq;
	int ret, retv = 0;

	rxm_eq = container_of(fid, struct rxm_eq, util_eq.eq_fid.fid);

	if (rxm_eq->util_coll_eq)
		fi_close(&rxm_eq->util_coll_eq->fid);

	ret = ofi_eq_cleanup(&rxm_eq->util_eq.eq_fid.fid);
	if (ret)
		retv = ret;

	free(rxm_eq);
	return retv;
}

static struct fi_ops rxm_eq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = rxm_eq_close,
	.bind = fi_no_bind,
	.control = ofi_eq_control,
	.ops_open = fi_no_ops_open,
};

ssize_t rxm_eq_write(struct fid_eq *eq_fid, uint32_t event,
		     const void *buf, size_t len, uint64_t flags)
{
	struct fi_eq_entry entry;
	const struct fi_eq_entry *in_entry = buf;
	struct rxm_mc *mc;
	int ret;

	if ((event != FI_JOIN_COMPLETE) && (event != FI_JOIN_FAILED)){
		return ofi_eq_write(eq_fid, event, buf, len, flags);
	}

	mc = in_entry->context;

	memset(&entry, 0, sizeof(entry));
	entry.context = mc->context;
	entry.fid = &mc->mc_fid.fid;

	ofi_spin_lock(&mc->lock);
	if (mc->state == RXM_MC_UTIL_STARTED) {
		if (event == FI_JOIN_FAILED) {
			mc->state = RXM_MC_ERROR;
			ofi_spin_unlock(&mc->lock);
			/* fi_close() for mc->util_coll_mc_fid postpone 
			   until fi_close() for rxm_mc */
			return ofi_eq_write(eq_fid, event, &entry, len, flags);
		}
		if (!mc->ep->offload_coll_ep) {
			mc->state = RXM_MC_READY;
			ofi_spin_unlock(&mc->lock);
			return ofi_eq_write(eq_fid, event, &entry, len, flags);
		}
		/* start fi_join for offload collective provider */
		mc->state = RXM_MC_OFF_STARTED;
		ofi_spin_unlock(&mc->lock);
		ret = fi_join(mc->ep->offload_coll_ep, mc->addr,
			      flags | FI_PEER, &mc->offload_coll_mc_fid,
			      &mc);
		if (ret) {
			ofi_spin_lock(&mc->lock);
			mc->state = RXM_MC_ERROR;
			ofi_spin_unlock(&mc->lock);
			/* fi_close() for mc->util_coll_mc_fid postpone
			   until fi_close() for rxm_mc */
			return ofi_eq_write(eq_fid, FI_JOIN_FAILED, &entry, len,
					    flags);
		}
		ofi_spin_lock(&mc->lock);
	} else if(mc->state == RXM_MC_OFF_STARTED) {
		if (event == FI_JOIN_FAILED) {
			mc->state = RXM_MC_ERROR;
			ofi_spin_unlock(&mc->lock);
			/* fi_close() for mc->off_coll_mc_fid postpone
			   until fi_close() for rxm_mc */
			return ofi_eq_write(eq_fid, FI_JOIN_FAILED, &entry, len,
					    flags);
		}
		mc->state = RXM_MC_READY;
		ofi_spin_unlock(&mc->lock);
		return ofi_eq_write(eq_fid, event, &entry, len, flags);
	} else {
		assert(0); /* we should never get event out of
			     RXM_MC_OFF_STARTED and RXM_MC_UTIL_STARTED
			     states */
	}

	ofi_spin_unlock(&mc->lock);

	return len;
};
static struct fi_ops_eq rxm_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = ofi_eq_read,
	.readerr = ofi_eq_readerr,
	.sread = ofi_eq_sread,
	.write = rxm_eq_write,
	.strerror = ofi_eq_strerror,
};

int rxm_eq_open(struct fid_fabric *fabric_fid, struct fi_eq_attr *attr,
		struct fid_eq **eq_fid, void *context)
{
	struct rxm_fabric *rxm_fabric;
	struct rxm_eq *rxm_eq;
	struct fi_peer_eq_context peer_context = {
		.size = sizeof(struct fi_peer_eq_context),
	};
	struct fi_eq_attr peer_attr = {
		.flags = FI_PEER,
	};
	int ret;

	rxm_fabric = container_of(fabric_fid, struct rxm_fabric,
				  util_fabric.fabric_fid);

	rxm_eq = calloc(1, sizeof(*rxm_eq));
	if (!rxm_eq)
		return -FI_ENOMEM;

	ret = ofi_eq_init(fabric_fid, attr, &rxm_eq->util_eq.eq_fid, context);
	if (ret)
		goto err1;

	peer_context.eq = &rxm_eq->util_eq.eq_fid;

	if (rxm_fabric->util_coll_fabric) {
		ret = fi_eq_open(rxm_fabric->util_coll_fabric, &peer_attr,
				 &rxm_eq->util_coll_eq, &peer_context);
		if (ret)
			goto err2;
	}

	rxm_eq->util_eq.eq_fid.fid.ops = &rxm_eq_fi_ops;
	rxm_eq->util_eq.eq_fid.ops = &rxm_eq_ops;
	*eq_fid = &rxm_eq->util_eq.eq_fid;
	return 0;

err2:
	ofi_eq_cleanup(&rxm_eq->util_eq.eq_fid.fid);
err1:
	free(rxm_eq);
	return ret;
}
