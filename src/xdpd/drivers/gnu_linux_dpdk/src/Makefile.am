MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = hal-imp io processing pipeline-imp util#Add more here... 

noinst_LTLIBRARIES = libxdpd_driver_gnu_linux_dpdk_src.la

libxdpd_driver_gnu_linux_dpdk_src_la_SOURCES = bg_taskmanager.cc config.cc
libxdpd_driver_gnu_linux_dpdk_src_la_LIBADD = \
		hal-imp/libxdpd_driver_gnu_linux_dpdk_src_hal_imp.la\
		io/libxdpd_driver_gnu_linux_dpdk_src_io.la\
		pipeline-imp/libxdpd_driver_gnu_linux_dpdk_src_pipeline_imp.la\
		processing/libxdpd_driver_gnu_linux_dpdk_src_processing.la\
		util/libxdpd_driver_gnu_linux_dpdk_src_util.la\
		-lrte_eal\
		-lrte_ethdev\
		-lrte_hash\
		-lrte_kni\
		-lrte_lpm\
		-lrte_mbuf\
		-lrte_mempool\
		-lrte_power\
		-lrte_ring\
		-lrte_timer\
		-lrte_eal\
		-lrte_kvargs\
		-ldl
