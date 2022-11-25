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

#include "sharp.h"

struct sharp_mr {
	struct fid_mr mr_fid;
	// mr_fid.mem_desc stores result of sharp_coll_reg_mr
	// XXX
};


static int sharp_mr_close(fid_t fid)
{
#if 0
	struct fid_mr mr_fid;
	struct sharp_mr *sharp_mr = container_of(fid, struct sharp_mr, mr_fid.fid);
#endif
// XXX
	return 0;
}
static struct fi_ops sharp_mr_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_mr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};


static int sharp_mr_reg(struct fid *fid, const void *buf, size_t len,
		uint64_t access, uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr, void *context)
{
	struct sharp_mr *sharp_mr;
#if 0
	struct sharp_domain *sharp_domain = container_of(fid,
			struct sharp_domain, util_domain.domain_fid.fid);
#endif

	sharp_mr = calloc(1, sizeof(*sharp_mr));
	if (!sharp_mr)
		return -FI_ENOMEM;

	void *sharp_coll_mr = NULL;
	// maped to sharp_coll_reg_mr
	// Only one outstanding registration supported. no registration cache.

	sharp_mr->mr_fid.fid.fclass = FI_CLASS_MR;
	sharp_mr->mr_fid.fid.context = context;
	sharp_mr->mr_fid.fid.ops = &sharp_mr_fi_ops;
	sharp_mr->mr_fid.mem_desc = sharp_coll_mr;
	sharp_mr->mr_fid.key = FI_KEY_NOTAVAIL;
	*mr = &sharp_mr->mr_fid;

	// XXX do we need to track mrs inside domain
	return 0;
}

static struct fi_ops_mr sharp_domain_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = sharp_mr_reg,
	.regv = fi_no_mr_regv,
	.regattr = fi_no_mr_regattr,
};

static struct fi_ops_domain sharp_domain_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = fi_no_av_open,
	.cq_open = fi_no_cq_open,
	.endpoint = sharp_endpoint,
	.scalable_ep = fi_no_scalable_ep,
	.cntr_open = fi_no_cntr_open,
	.poll_open = fi_poll_create,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
	.query_atomic = fi_no_query_atomic,
	.query_collective = sharp_query_collective,
	.endpoint2 = fi_no_endpoint2
};

static int sharp_domain_close(fid_t fid)
{
	int ret;
	struct sharp_domain *domain;

	domain = container_of(fid, struct sharp_domain, util_domain.domain_fid.fid);
	/// mapped to int sharp_coll_finalize(struct sharp_coll_context *context);
	ret = ofi_domain_close(&domain->util_domain);
	if (ret)
		return ret;

	free(domain);
	return 0;
}

static struct fi_ops sharp_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_domain_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static inline void
fid_domain_init(struct fid_domain **domain_fid, 
		struct util_domain *util_domain, struct fi_ops *fid_ops, 
		struct fi_ops_domain *ops, struct fi_ops_mr *mr)
{
	*domain_fid = &util_domain->domain_fid;
	(*domain_fid)->fid.ops = fid_ops;
	(*domain_fid)->ops = ops;
	(*domain_fid)->mr = mr;
}

int sharp_domain2(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **domain_fid, uint64_t flags, void *context)
{
	int ret;
	struct sharp_domain *domain;
	struct fi_peer_domain_context *peer_context = context;

	if (!(flags & FI_PEER)) {
		FI_WARN(&sharp_prov, FI_LOG_CORE,
			"FI_PEER flag required\n");
		return -EINVAL;
	}

	if (!peer_context || peer_context->size < sizeof(*peer_context)) {
		FI_WARN(&sharp_prov, FI_LOG_CORE,
			"Invalid peer domain context\n");
		return -EINVAL;
	}

	ret = ofi_prov_check_info(&sharp_util_prov, fabric->api_version, info);
	if (ret)
		return ret;

	domain = calloc(1, sizeof(*domain));
	if (!domain)
		return -FI_ENOMEM;

	ret = ofi_domain_init(fabric, info, &domain->util_domain, context,
			      OFI_LOCK_MUTEX);


	if (ret) {
		free(domain);
		return ret;
	}

	ofi_atomic_initialize32(&domain->ref, 0);
	domain->util_domain.threading = FI_THREAD_UNSPEC;

#if 0
	// XXX
	*domain_fid = &domain->util_domain.domain_fid;
	(*domain_fid)->fid.ops = &sharp_domain_fi_ops;
	(*domain_fid)->ops = &sharp_domain_ops;
	(*domain_fid)->mr = &sharp_domain_mr_ops;
#endif
	fid_domain_init(domain_fid, &domain->util_domain, &sharp_domain_fi_ops,
		&sharp_domain_ops, &sharp_domain_mr_ops);


// XXX maped to 
// int sharp_coll_init(struct sharp_coll_init_spec *sharp_coll_spec,
//		    struct sharp_coll_context  **sharp_coll_context);
#if 0
struct sharp_coll_init_spec {
	uint64_t	job_id;				/**< Job unique ID */
	int		world_rank;			/**< Global unique process id. */
	int		world_size;			/**< Num of processes in the job. */
	int		(*progress_func)(void);		/**< External progress function. */
	int		group_channel_idx;		/**< local group channel index(0 .. (max - 1))*/
	struct sharp_coll_config config;		/**< @ref sharp_coll_config "SHARP COLL Configuration". */
	struct sharp_coll_out_of_band_colls oob_colls;  /**< @ref sharp_coll_out_of_band_colls "List of OOB collectives". */
	int             world_local_rank;               /**< relative rank of this process on this node within its job. */
	int		enable_thread_support;		/**< enable multi threaded support. */
	void		*oob_ctx;			/**< context for OOB functions in sharp_coll_init */
	int		reserved[4];			/**< Reserved */
};
#endif
	return 0;
}
