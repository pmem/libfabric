# TODO List
## Items to be complited by ww2'23

1. sharp_domain2 with sharp_coll API
	
	1. oob functions definition
	2. sharp_coll_init_spec allocation and definition
	3. sharp_coll_init (MOCK) allocate sharp_coll_context

2. sharp_domain_close() with sharp_coll API

- sharp_coll_fini (MOCK) deallocate sharp_coll_context

3. make with/without mocks

- extend build system for easy compilation with/without mock
- test sharp_domain2 w/o mocks

## Next item to be done after ww02'23

1. fi_av_open(domain, **av) – to be partially reused from utill_coll provider

2. fi_av_set(av, **set) - to be partially reused from utill_coll provider
3. fi_join_collective() – the biggest item as it includes cooperation with util_coll provider and converting synchronous SHARP driver API to asynchronous used by libfabric
-	fi_barrier()
-	fi_mr_reg(domain, **mr)
-	fi_close(*mr)
-	fi_allreduce()
-	fi_query_collective() 


1. sharp_coll_comm_init (MOCK) with sharp_oob_barrier() (THREAD?)
- threaded
- oob
- xref_completion

6 sharp_barrier
- progress

7 sharp_coll_do_allreduce_nb
- sharp_coll_do_mr()
- 

4 sharp_query_collective with sharp_coll API
- sharp_coll_caps_query call


...
...
