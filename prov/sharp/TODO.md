# TODO List

## Items to be completed by ww02'23

1. `sharp_domain2()` with sharp_coll API
   * oob functions definition with dummy implemntation
   * `sharp_coll_init_spec` allocation and definition
   * `sharp_coll_init()` (MOCK) allocate `sharp_coll_context`
   * `sharp_domain_close()` with sharp_coll API
      * `sharp_coll_finalize()` (MOCK) deallocate `sharp_coll_context`

2. make with/without mocks

   * extend build system for easy compilation with/without mock
   * test sharp_domain2 with mocks
   * test sharp_domain2 without mocks (option)

## Next item to be done after ww02'23

1. `fi_av_open(domain, **av)` – not sure if needed at all. If yes, to be reused from utill_coll provider. Or coll_av coverted to public ofi_coll_av. There are API calls like `coll_find_local_rank()` that use `coll_av`
2. `fi_av_set(av, **set)` - to be partially reused from `util_coll` provider. Common implementation is required for partially common implementation of `util_coll_mc` and `sharp_mc`
3. fi_join_collective() – the biggest item as it includes cooperation with the util_coll provider and conversion of the synchronous API of SHARP driver to the asynchronous mechanism used by libfabric
   * `struct sharp_mc` final implementation. Relation between `util_coll_mc` and `sharp_mc` to be defined.
   * thread to creat, as the SHARP driver uses libfabric services (oob) synchronously
   * sharp_oob_bcast() implementation based on fi_bcast(..., FI_PEER_TRANSFER,...)
   * sharp_oob_barrie() implementation based on fi_barrier(..., FI_PEER_TRANSFER,...)
   * sharp_oob_gather() implementation based on fi_gather(..., FI_PEER_TRANSFER,...)
   * `sharp_mc` to handle `sharp_coll_comm` context
   * `sharp_coll_comm_init()` (MOCK) with sharp_oob_barrier() (THREAD?)
   * xref_completion implementation
   * `fi_close(mc)`
      * `sharp_coll_comm_destroy()`

4. fi_barrier(mc)
   * `sharp_coll_do_barrier_nb()`
   * `sharp_ep_progress()` to use `sharp_coll_progress()`
   * `sharp_ep_progress()` to use `sharp_coll_req_test()`
   * support for `oob_progress()` (???)
5. fi_mr_reg(domain, **mr)
   * support for `FI_COLL_SHARP_SCARTCH_SIZE` and `FI_COLL_SHARP_MR_CACHE`
   * sharp_coll_do_mr()
   * `fi_close(*mr)`
6. `fi_allreduce()`
   * `sharp_coll_do_reduce_nb()`
   * `sharp_ep_progress()` to use `sharp_coll_progress()`
   * `sharp_ep_progress()` to use `sharp_coll_req_test()`

7. fi_query_collective()
   * `sharp_coll_caps_query()`
