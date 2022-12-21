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

#ifndef _SHARP_H_
#define _SHARP_H_

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/statvfs.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

#include <rdma/fabric.h>
 
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/providers/fi_prov.h>
#include <rdma/fi_ext.h>

#include <ofi.h>
#include <ofi_enosys.h>
#include <ofi_sharp.h>
#include <ofi_list.h>
#include <ofi_signal.h>
#include <ofi_util.h>
#include <ofi_mr.h>

#define SHARP_IOV_LIMIT		1
#define SHARP_TX_OP_FLAGS (0)
#define SHARP_RX_OP_FLAGS (0)
#define SHARP_DOMAIN_CAPS (FI_COLLECTIVE | FI_LOCAL_COMM | FI_REMOTE_COMM)
enum {
	SHARP_RX_SIZE = 65536,
	SHARP_TX_SIZE = 16384,
};


struct sharp_env {
	size_t ib_port;
};

extern struct sharp_env sharp_env;

/*
XXX temporary solution
*/
#ifdef sharp_coll_context
#define sharp_coll_context_t struct sharp_coll_context
#else
#define sharp_coll_context_t void
#endif

struct sharp_domain {
	struct util_domain	util_domain;
	struct fid_domain *peer_domain;
	sharp_coll_context_t *sharp_context;
	ofi_atomic32_t	ref; /* mr count XXX - to be handled in mr create and del */
	ofi_spin_t		lock;
};

struct sharp_fabric {
	struct util_fabric	util_fabric;
};

struct sharp_eq {
	struct util_eq util_eq;
	struct fid_eq *peer_eq;
};

struct sharp_ep {
	struct util_ep 	util_ep;
	struct fi_info 	*sharp_info;

	/*
	 * Peer ep from the main provider.
	 * Used for oob communications that SHARP uses during setup.
	 */
	struct fid_ep	*peer_ep;
	struct fi_info 	*peer_info;

	ofi_atomic32_t	ref; /* mc count XXX to be added to mc handling*/
	ofi_spin_t	lock;
};

/*
XXX to be reused from coll provider
*/
struct sharp_av {
	struct util_av util_av;
	struct fid_peer_av *peer_av;
};

/*
XXX temporary solution
*/
#ifdef sharp_coll_comm
#define sharp_coll_comm_t struct sharp_coll_comm
#else
#define sharp_coll_comm_t void
#endif
struct sharp_mc {
	struct fid_mc		mc_fid;
	struct util_av_set	*av_set;
	uint64_t		local_rank;
	uint16_t		group_id;
	uint16_t		seq;
	ofi_atomic32_t		ref;
	struct fid_mc		*peer_mc;
/* same as util_coll_mc until this point */
	struct sharp_ep		*ep;
	sharp_coll_comm_t 	*sharp_context;
};

struct sharp_cq {
	struct util_cq util_cq;
	struct fid_peer_cq *peer_cq;
};

extern struct fi_fabric_attr sharp_fabric_attr;
extern struct fi_provider sharp_prov;
extern struct util_prov sharp_util_prov;
extern struct fi_info sharp_info;

int sharp_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
				void *context);

int sharp_domain2(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, uint64_t flags, void *context);

int sharp_query_collective(struct fid_domain *domain,
		enum fi_collective_op coll, struct fi_collective_attr *attr,
		uint64_t flags);


int sharp_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep, void *context);

void sharp_ep_progress(struct util_ep *util_ep);

int sharp_join_collective(struct fid_ep *ep, const void *addr,
		         uint64_t flags, struct fid_mc **mc, void *context);

int sharp_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq_fid, void *context);

int sharp_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		 struct fid_eq **eq_fid, void *context);

void sharp_collective_comp(struct util_coll_operation *coll_op);

ssize_t sharp_ep_barrier(struct fid_ep *ep, fi_addr_t coll_addr, void *context);

ssize_t sharp_ep_barrier2(struct fid_ep *ep, fi_addr_t coll_addr, uint64_t flags,
			 void *context);

ssize_t sharp_ep_allreduce(struct fid_ep *ep, const void *buf, size_t count,
			  void *desc, void *result, void *result_desc,
			  fi_addr_t coll_addr, enum fi_datatype datatype,
			  enum fi_op op, uint64_t flags, void *context);

ssize_t sharp_peer_xfer_complete(struct fid_ep *ep,
				struct fi_cq_tagged_entry *cqe,
				fi_addr_t src_addr);

ssize_t sharp_peer_xfer_error(struct fid_ep *ep, struct fi_cq_err_entry *cqerr);


int sharp_oob_bcast(void* context, void* buffer, int len, int root);

int sharp_oob_barrier(void* context);

int sharp_oob_gather(void * context, int root, void *sbuf, void *rbuf, int len);

int sharp_oob_progress(void);

/*
int sharp_coll_init(struct sharp_coll_init_spec *sharp_coll_spec,
		    struct sharp_coll_context  **sharp_coll_context);
*/
ssize_t sharp_do_sharp_coll_init(struct sharp_domain *domain);

/*
int sharp_coll_finalize(struct sharp_coll_context *context);
*/
size_t sharp_do_sharp_coll_finalize(struct sharp_domain *domain);

/*
int sharp_coll_comm_init(struct sharp_coll_context *context,
			 struct sharp_coll_comm_init_spec *spec,
			 struct sharp_coll_comm **sharp_coll_comm);
*/
int sharp_do_coll_comm_init(struct sharp_mc *mc);

/* 
int sharp_coll_comm_destroy(struct sharp_coll_comm *comm);
*/
size_t sharp_do_coll_comm_destroy(struct sharp_mc *mc);

/*
int sharp_coll_do_barrier_nb(struct sharp_coll_comm *comm, void **handle);
*/
size_t sharp_do_coll_do_barrier(struct sharp_mc *mc, uint64_t flags,
				void *context, void **handle);

/* 
int sharp_coll_do_allreduce_nb(struct sharp_coll_comm *comm,
				struct sharp_coll_reduce_spec *spec,
				void **handle);
*/
int sharp_do_coll_do_allreduce(struct sharp_mc *mc, const void *buf, 
				size_t count, void *desc, void *result, 
				void *result_desc, enum fi_datatype datatype,
				enum fi_op op, uint64_t flags, void *context,
				void **handle);
#endif
