#include "iface_manager.h"
#include <rofl/datapath/hal/cmm.h>
#include <utils/c_logger.h>
#include <rofl/datapath/pipeline/openflow/of_switch.h>
#include <rofl/datapath/pipeline/common/datapacket.h>
#include <rofl/datapath/pipeline/physical_switch.h>

#include "port_state.h"
#include "nf_iface_manager.h"

#include <assert.h> 
extern "C" {
#include <rte_config.h> 
#include <rte_common.h> 
#include <rte_malloc.h> 
#include <rte_errno.h> 
#include <rte_eth_ctrl.h>

#ifdef RTE_LIBRTE_IXGBE_PMD
#include <rte_pmd_ixgbe.h>
#endif
#ifdef RTE_LIBRTE_I40E_PMD
#include <rte_pmd_i40e.h>
#endif
}

#include <fcntl.h>
#include <set>

#define NB_MBUF                                                                                                        \
	RTE_MAX((nb_ports * nb_rx_queue * RTE_RX_DESC_DEFAULT + nb_ports * nb_lcores * MAX_PKT_BURST +                 \
		 nb_ports * n_tx_queue * RTE_TX_DESC_DEFAULT + nb_lcores * MEMPOOL_CACHE_SIZE),                        \
		(unsigned)8192)

#define MEMPOOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32

#define VLAN_ANTI_SPOOF
#define VLAN_INSERT
#define VLAN_RX_FILTER
//#define VLAN_STRIP
//#define VLAN_ADD_MAC
#define VLAN_SET_MACVLAN_FILTER

struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

switch_port_t* phy_port_mapping[PORT_MANAGER_MAX_PORTS] = {0};
struct rte_ring* port_tx_lcore_queue[PORT_MANAGER_MAX_PORTS][IO_IFACE_NUM_QUEUES] = {{NULL}}; // XXX(toanju) should be sufficient for shmen only

uint8_t nb_phy_ports = 0;
pthread_rwlock_t iface_manager_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static int numa_on = 1; /**< NUMA is enabled by default. */
/* Static global variables used within this file. */
//static uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
static uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;

static std::set<int> sockets;

// XXX(toanju) these values need a proper configuration
int port_vf_id[RTE_MAX_ETHPORTS] = {-1, 0, 1, -1, 0, 1};
int port_parent_id_of_vf[RTE_MAX_ETHPORTS] = {-1, 0, 0, -1, 3, 3};
uint16_t port_pvid[RTE_MAX_ETHPORTS] = {0, 101, 102, 0, 201, 202};
struct ether_addr port_ether_addr[RTE_MAX_ETHPORTS][ETHER_ADDR_LEN] = {
    {0}, {0x0e, 0x11, 0x11, 0x11, 0x01, 0x03}, {0x0e, 0x11, 0x11, 0x11, 0x01, 0x04},
    {0}, {0x0e, 0x11, 0x11, 0x11, 0x02, 0x03}, {0x0e, 0x11, 0x11, 0x11, 0x02, 0x04}};

#ifdef VLAN_ADD_MAC
static void set_vf_mac_addr(uint8_t port_id, uint16_t vf_id, struct ether_addr *mac_addr)
{
	int ret = -ENOTSUP;
	fprintf(stderr, "%s\n", __FUNCTION__);

	//if (port_id_is_invalid(res->port_id, ENABLED_WARN))
	//	return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_mac_addr(port_id, vf_id, mac_addr);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_mac_addr(port_id, vf_id, mac_addr);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or mac_addr\n", vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("%s: function not implemented\n", __FUNCTION__);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		assert(0 && "programming error");
	}
}
#endif

#ifdef VLAN_SET_MACVLAN_FILTER
static int set_vf_macvlan_filter(uint8_t port_id, uint8_t vf_id, struct ether_addr *address, const char *filter_type, int is_on)
{
	int ret = -1;
	struct rte_eth_mac_filter filter;
	fprintf(stderr, "%s\n", __FUNCTION__);

	assert(filter_type);

	memset(&filter, 0, sizeof(struct rte_eth_mac_filter));

	(void)rte_memcpy(&filter.mac_addr, &address, ETHER_ADDR_LEN);

	/* set VF MAC filter */
	filter.is_vf = 1;

	/* set VF ID */
	filter.dst_id = vf_id;

	if (!strcmp(filter_type, "exact-mac"))
		filter.filter_type = RTE_MAC_PERFECT_MATCH;
	else if (!strcmp(filter_type, "exact-mac-vlan"))
		filter.filter_type = RTE_MACVLAN_PERFECT_MATCH;
	else if (!strcmp(filter_type, "hashmac"))
		filter.filter_type = RTE_MAC_HASH_MATCH;
	else if (!strcmp(filter_type, "hashmac-vlan"))
		filter.filter_type = RTE_MACVLAN_HASH_MATCH;
	else {
		printf("bad filter type");
		return ret;
	}

	if (is_on)
		ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_MACVLAN, RTE_ETH_FILTER_ADD, &filter);
	else
		ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_MACVLAN, RTE_ETH_FILTER_DELETE, &filter);

	if (ret < 0)
		printf("bad set MAC hash parameter, return code = %d\n", ret);

	return ret;
}
#endif

#ifdef VLAN_ANTI_SPOOF
static void set_vf_vlan_anti_spoof(uint8_t port_id, uint32_t vf_id, int is_on)
{
	int ret = -ENOTSUP;

	fprintf(stderr, "%s\n", __FUNCTION__);

	//if (port_id_is_invalid(port_id, ENABLED_WARN))
	//	return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_anti_spoof(port_id, vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_anti_spoof(port_id, vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d\n", vf_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("%s: function not implemented\n", __FUNCTION__);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
	}
}
#endif

#ifdef VLAN_INSERT
static void vf_vlan_insert(uint8_t port_id, uint16_t vf_id, uint16_t vlan_id)
{
	int ret = -ENOTSUP;

	fprintf(stderr, "%s\n", __FUNCTION__);

	//if (port_id_is_invalid(port_id, ENABLED_WARN))
	//	return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_insert(port_id, vf_id, vlan_id);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_insert(port_id, vf_id, vlan_id);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or vlan_id %d\n", vf_id, vlan_id);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("%s: function not implemented\n", __FUNCTION__);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		assert(0 && "programming error");
	}
}
#endif

#ifdef VLAN_RX_FILTER
static void vf_rx_filter_vlan(uint16_t vlan_id, uint8_t port_id, uint64_t vf_mask, int is_add)
{
	int ret = -ENOTSUP;

	fprintf(stderr, "%s\n", __FUNCTION__);

	//if (port_id_is_invalid(port_id, ENABLED_WARN))
	//	return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_filter(port_id, vlan_id, vf_mask, is_add);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_filter(port_id, vlan_id, vf_mask, is_add);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vlan_id %d or vf_mask %" PRIu64 "\n", vlan_id, vf_mask);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("%s: function not implemented of supported\n", __FUNCTION__);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		assert(0 && "programming error");
	}
}
#endif

#ifdef VLAN_STRIP
static void vf_enable_strip_vlan(uint8_t port_id, uint16_t vf_id, int is_on)
{
	int ret = -ENOTSUP;

	fprintf(stderr, "%s\n", __FUNCTION__);

	//if (port_id_is_invalid(port_id, ENABLED_WARN))
	//	return;

#ifdef RTE_LIBRTE_IXGBE_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_ixgbe_set_vf_vlan_stripq(port_id, vf_id, is_on);
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_set_vf_vlan_stripq(port_id, vf_id, is_on);
#endif

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		printf("invalid vf_id %d or is_on %d\n", vf_id, is_on);
		break;
	case -ENODEV:
		printf("invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		printf("%s: function not implemented\n", __FUNCTION__);
		break;
	default:
		printf("programming error: (%s)\n", strerror(-ret));
		assert(0 && "programming error");
	}
}
#endif

static uint8_t get_port_n_rx_queues(const uint8_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue+1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
						" in sequence and must start with 0\n",
						lcore_params[i].port_id);
		}
	}
	return (uint8_t)(++queue);
}

static uint8_t get_port_n_tx_queues(const uint8_t lsi_id, const uint8_t port)
{
	int queue = 0;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].lsi_id == lsi_id && lcore_params[i].port_id != port) {
			queue++;
		}
	}

	return (uint8_t)(queue);
}

static uint8_t get_lsi_id(const uint8_t port_id) {
	unsigned i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port_id) {
			return lcore_params[i].lsi_id;
		}
	}

	return -1;
}

static unsigned is_txq_enabled(const uint8_t lsi_id, const uint8_t port_id, const uint8_t lcore_id)
{
	unsigned i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].lsi_id == lsi_id && lcore_params[i].port_id != port_id &&
		    lcore_params[i].lcore_id == lcore_id) {
			return 1;
		}
	}

	return 0;
}

static int check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			XDPD_ERR("invalid queue number: %hhu\n", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			XDPD_ERR("error: lcore %hhu is not enabled in lcore mask\n", lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
		    (numa_on == 0)) {
			XDPD_WARN("warning: lcore %hhu is on socket %d with numa "
				  "off \n",
				  lcore, socketid);
		}
		sockets.insert(socketid);
	}
	return 0;
}

static int
init_lcore_rx_queues(void)
{
        uint16_t i, nb_rx_queue;
        uint8_t lcore;

        for (i = 0; i < nb_lcore_params; ++i) {
                lcore = lcore_params[i].lcore_id;
                nb_rx_queue = processing_core_tasks[lcore].n_rx_queue;
                if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
                        XDPD_ERR("error: too many queues (%u) for lcore: %u\n",
                                (unsigned)nb_rx_queue + 1, (unsigned)lcore);
                        return -1;
                } else {
                        processing_core_tasks[lcore].rx_queue_list[nb_rx_queue].port_id =
                                lcore_params[i].port_id; // XXX(toanju) this is currently pretty static wrt. port_id
                        processing_core_tasks[lcore].rx_queue_list[nb_rx_queue].queue_id =
                                lcore_params[i].queue_id;
                        processing_core_tasks[lcore].n_rx_queue++; 
                }
		XDPD_INFO("init_lcore_rx_queue i=%d lcore=%d #lcore_queues=%d\n", i, lcore, processing_core_tasks[lcore].n_rx_queue);
        }
        return 0;
}

static int check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if (portid >= nb_ports + GNU_LINUX_DPDK_MAX_KNI_IFACES) {
			XDPD_ERR("port %u is not present on the board\n", portid);
			return -1;
		}
	}
	return 0;
}
static int init_mem(unsigned nb_mbuf)
{
	int socketid;
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE,
				 "Socket %d of lcore %u is out of range %d\n",
				 socketid, lcore_id, NB_SOCKETS);
		}
		if (direct_pools[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			direct_pools[socketid] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
									 RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (direct_pools[socketid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", socketid);
			else
				XDPD_INFO("Allocated mbuf pool on socket %d\n", socketid);
		}
	}
	return 0;
}

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	XDPD_INFO("%s%s", name, buf);
}

//Initializes the pipeline structure and launches the port
static switch_port_t *configure_port(uint8_t port_id)
{
	int ret;
	switch_port_t* port;
	struct core_tasks *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf;
	struct rte_eth_txconf *txconf;
	char port_name[SWITCH_PORT_MAX_LEN_NAME];
	//char queue_name[PORT_QUEUE_MAX_LEN_NAME];
	uint16_t queueid;
	unsigned lcore_id, nb_ports;
	uint32_t n_tx_queue, nb_lcores;
	uint8_t nb_rx_queue, socketid, queue, lsi_id;
	
	//Get info
	rte_eth_dev_info_get(port_id, &dev_info);

	//Hack to "deduce" the maximum speed of the NIC.
	//As of DPDK v1.4 there is not way to retreive such features from
	//the NIC
	XDPD_DEBUG(DRIVER_NAME"[iface_manager] driver_name=%s\n", dev_info.driver_name);
	if(strncmp(dev_info.driver_name, "net_i40e_vf", 10) == 0){
		/* 40G vf */
		snprintf (port_name, SWITCH_PORT_MAX_LEN_NAME, "40gevf%u",port_id);
	} else if(strncmp(dev_info.driver_name, "net_i40e", 8) == 0){
		/* 40G */
		snprintf (port_name, SWITCH_PORT_MAX_LEN_NAME, "40ge%u",port_id);
	} else if(strncmp(dev_info.driver_name, "net_ixgbe", 9) == 0) {
		/* 10G */
		snprintf (port_name, SWITCH_PORT_MAX_LEN_NAME, "10ge%u",port_id);
	} else {
		/* 1G */
		snprintf (port_name, SWITCH_PORT_MAX_LEN_NAME, "ge%u",port_id);
	}

	XDPD_INFO(DRIVER_NAME "[iface_manager] configuring port %s port_id=%d, max_tx_queues=%d, max_rx_queues=%d, "
			      "speed_capa=0x%x\n",
		  port_name, port_id, dev_info.max_tx_queues, dev_info.max_rx_queues, dev_info.speed_capa);

	// Set rx and tx queues
	memset(&port_conf, 0, sizeof(port_conf));

	//Initialize pipeline port
	port = switch_port_init(port_name, false, PORT_TYPE_PHYSICAL, PORT_STATE_NONE);
	if(!port)
		return NULL; 

	//Generate port state
	dpdk_port_state_t* ps = (dpdk_port_state_t*)rte_malloc(NULL,sizeof(dpdk_port_state_t),0);
	
	if(!ps){
		switch_port_destroy(port);
		return NULL;
	}

	port_conf.rxmode.header_split = 0;   /**< Header Split disabled */
	port_conf.rxmode.hw_ip_checksum = 1; /**< IP checksum offload enabled */
	port_conf.rxmode.hw_vlan_strip = 1;  /**< VLAN strip enable. */
	port_conf.rxmode.hw_vlan_extend = 0; /**< Extended VLAN disabled */
	port_conf.rxmode.hw_vlan_filter = 1; /**< VLAN filtering enalbed */
	port_conf.rxmode.hw_strip_crc = 1;   /**< CRC stripped by hardware */
	port_conf.rxmode.jumbo_frame = 0;    /**< Jumbo Frame Support disabled */
	port_conf.rxmode.enable_scatter = 0; /**< Enable scatter packets rx handler */
	port_conf.rxmode.enable_lro = 0;     /**< Enable LRO */

	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.max_rx_pkt_len = IO_MAX_PACKET_SIZE;
	
	// rss
	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = /*ETH_RSS_L2_PAYLOAD |*/ ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;

	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

	nb_ports = rte_eth_dev_count();
	nb_lcores = rte_lcore_count();
	lsi_id = get_lsi_id(port_id);
	nb_rx_queue = get_port_n_rx_queues(port_id);
	n_tx_queue = get_port_n_tx_queues(lsi_id, port_id); // for pf could be rte_lcore_count(); must always equal(=1) for vf

	// check rx
	if (nb_rx_queue > dev_info.max_rx_queues) {
		rte_exit(EXIT_FAILURE, "Fail: nb_rx_queue(%d) is greater than max_rx_queues(%d)\n", nb_rx_queue,
			 dev_info.max_rx_queues);
	}
	if (n_tx_queue > dev_info.max_tx_queues) {
		rte_exit(EXIT_FAILURE, "Fail: n_tx_queue(%d) is greater than max_tx_queues(%d)\n", n_tx_queue,
			 dev_info.max_tx_queues);
	}

	if (n_tx_queue > MAX_TX_QUEUE_PER_PORT) {
		rte_exit(EXIT_FAILURE, "too many tx queues for port %d: %d\n",
			 port_id, n_tx_queue);
	}

	XDPD_INFO("Creating queues: nb_rxq=%d nb_txq=%u...", nb_rx_queue, (unsigned)n_tx_queue);

	ret = rte_eth_dev_configure(port_id, nb_rx_queue, (uint16_t)n_tx_queue,
				    &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, port_id);

#if 0 
	// set pvid
	if (port_pvid[port_id]) {
		XDPD_INFO(" pvid:%d", port_pvid[port_id]);
		ret = rte_eth_dev_set_vlan_pvid(port_id, port_pvid[port_id], 1);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure pvid: err=%d, port=%d\n", ret, port_id);
	}
#endif

	if (!is_zero_ether_addr(port_ether_addr[port_id])) {
#ifdef VLAN_ADD_MAC
		// XXX(tonaju) there is a set mac function as well
		set_vf_mac_addr(port_parent_id_of_vf[port_id], port_vf_id[port_id], port_ether_addr[port_id]);
#endif
		print_ethaddr(" vf-added:", port_ether_addr[port_id]);
		ret = rte_eth_dev_default_mac_addr_set(port_id, port_ether_addr[port_id]);
		//ret = rte_eth_dev_mac_addr_add(port_id, port_ether_addr[port_id], 0);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure ether addr: err=%d, port=%d\n", ret, port_id);
		
		if (port_vf_id[port_id] != -1) {
			fprintf(stderr,
				"params: port_id=%d, port_parent_id_of_vf=%d, port_vf_id=%d, port_pvid=%d\n",
				port_id, port_parent_id_of_vf[port_id], port_vf_id[port_id], port_pvid[port_id]);

			fprintf(stderr, "calling rte_eth_dev_mac_addr_add\n");
			ret = rte_eth_dev_mac_addr_add(port_parent_id_of_vf[port_id], port_ether_addr[port_id],
						       port_vf_id[port_id]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot configure mac on vf: err=%d, port=%d, parent=%d, vf_id=%d\n", ret,
					 port_id, port_parent_id_of_vf[port_id], port_vf_id[port_id]);

#if 0
			XDPD_INFO(" broadcast:1(port %d, parent %d, vf_id %d)", port_id, port_parent_id_of_vf[port_id],
				  port_vf_id[port_id]);
			ret = rte_pmd_i40e_set_vf_broadcast(port_parent_id_of_vf[port_id], port_vf_id[port_id], 1);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot configure broadcast: err=%d, port=%d, parent=%d, vf_id=%d\n", ret,
					 port_id, port_parent_id_of_vf[port_id], port_vf_id[port_id]);

#endif
#ifdef VLAN_ANTI_SPOOF
			set_vf_vlan_anti_spoof(port_parent_id_of_vf[port_id], port_vf_id[port_id], 0);
#endif
#ifdef VLAN_INSERT
			vf_vlan_insert(port_parent_id_of_vf[port_id], port_vf_id[port_id], port_pvid[port_id]);
#endif
#ifdef VLAN_RX_FILTER
			vf_rx_filter_vlan(port_pvid[port_id], port_parent_id_of_vf[port_id],
					  1ULL << port_vf_id[port_id], 1);
#endif
#ifdef VLAN_STRIP
			vf_enable_strip_vlan(port_parent_id_of_vf[port_id], port_vf_id[port_id], 1);
#endif
#ifdef VLAN_SET_MACVLAN_FILTER
			set_vf_macvlan_filter(port_parent_id_of_vf[port_id], port_vf_id[port_id],
					      port_ether_addr[port_id], "exact-mac-vlan", 1);
#endif
		}
			fflush(stderr);
	}

	//Recover MAC address
	rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
	print_ethaddr(" Address:", &ports_eth_addr[port_id]);
	XDPD_INFO(", ");

	ret = init_mem(NB_MBUF);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_mem failed\n");

#if 1
	/* init one TX queue per couple (lcore,port) */
	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (0 == is_txq_enabled(lsi_id, port_id, lcore_id))
			continue;

		if (numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		XDPD_INFO("txq: port_id=%d, queue_id=%d, socket_id=%d, lcore_id=%d, nb_txd=%d\n", port_id, queueid,
			  socketid, lcore_id, nb_txd);

		rte_eth_dev_info_get(port_id, &dev_info);
		txconf = &dev_info.default_txconf;

		if (port_conf.rxmode.jumbo_frame)
			txconf->txq_flags = 0;

		ret = rte_eth_tx_queue_setup(port_id, queueid, nb_txd, socketid, txconf);

		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
					       "port=%d\n",
				 ret, port_id);

		qconf = &processing_core_tasks[lcore_id];
		qconf->tx_queue_id[port_id] = queueid;
		queueid++;

		qconf->tx_port_id[qconf->n_tx_port] = port_id;
		qconf->n_tx_port++;
	}
#else
	/* init one TX queue */
	socketid = (uint8_t)rte_lcore_to_socket_id(rte_get_master_lcore());

	XDPD_INFO("txq: port_id=%d, queue_id=%d, socket_id=%d, nb_txd=%d\n", port_id, 0, socketid, nb_txd);

	rte_eth_dev_info_get(port_id, &dev_info);
	txconf = &dev_info.default_txconf;
	if (port_conf.rxmode.jumbo_frame)
		txconf->txq_flags = 0;

	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, socketid, txconf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
				       "port=%d\n",
			 ret, port_id);

#endif

	//Add TX queues to the pipeline
	//Filling one-by-one the queues 

	/* for(i=0;i<IO_IFACE_NUM_QUEUES;i++){
		
		//Create rofl-pipeline queue state
		snprintf(queue_name, PORT_QUEUE_MAX_LEN_NAME, "%s%d", "queue", i);
		if(switch_port_add_queue(port, i, (char*)&queue_name, IO_IFACE_MAX_PKT_BURST, 0, 0) != ROFL_SUCCESS){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot configure queues on device (pipeline): %s\n", port->name);
			assert(0);
			return NULL;
		}
		
		//Add port_tx_lcore_queue
		snprintf(queue_name, PORT_QUEUE_MAX_LEN_NAME, "%u-q%u", port_id, i);
		port_tx_lcore_queue[port_id][i] = rte_ring_create(queue_name, IO_TX_LCORE_QUEUE_SLOTS , SOCKET_ID_ANY, RING_F_SC_DEQ);
	
		
		if(unlikely( port_tx_lcore_queue[port_id][i] == NULL )){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot create rte_ring for queue on device: %s\n", port->name);
			assert(0);
			return NULL;
		}

	}
	*/

#if 0 // PF
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &processing_core_tasks[lcore_id];
		printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
		fflush(stdout);
		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			uint8_t portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			if (portid != port_id)
				continue;

			if (numa_on)
				socketid =
				    (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("rxq=%d,%d,%d\n", portid, queueid, socketid);
			fflush(stdout);

			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
						     socketid, NULL,
						     direct_pools[socketid]);
			if (ret < 0)
				rte_exit(
				    EXIT_FAILURE,
				    "rte_eth_rx_queue_setup: err=%d, port=%d\n",
				    ret, portid);
		}
	}
#else
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &processing_core_tasks[lcore_id];

		XDPD_INFO("\nInitializing rx queues on lcore %u ... ", lcore_id);
		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			uint8_t portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			if (portid != port_id)
				continue;

			if (numa_on)
				socketid =
				    (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			XDPD_INFO("rxq=%d,%d,%d(%d) ", portid, queueid, socketid, nb_rxd);

			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
						     socketid, NULL,
						     direct_pools[socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: err=%d,"
					 "port=%d\n",
					 ret, portid);
		}
	}
	XDPD_INFO("\n");
#endif

	//Fill-in dpdk port state
	ps->queues_set = false;
	ps->scheduled = false;
	ps->port_id = port_id;
	port->platform_port_state = (platform_port_state_t*)ps;

	unsigned int cpu_socket_id = rte_eth_dev_socket_id(port_id);
	XDPD_INFO(DRIVER_NAME"[iface_manager] Discovered port %s [PCI addr: %04u:%02u:%02u, MAC: %02X:%02X:%02X:%02X:%02X:%02X] id %u (CPU socket: %u)\n", port_name, dev_info.pci_dev->addr.domain, dev_info.pci_dev->addr.bus, dev_info.pci_dev->addr.devid, port->hwaddr[0], port->hwaddr[1], port->hwaddr[2], port->hwaddr[3], port->hwaddr[4], port->hwaddr[5], port_id, (cpu_socket_id == 0xFFFFFFFF)? 0 : cpu_socket_id);

	//Set the port in the phy_port_mapping
	phy_port_mapping[port_id] = port;

	return port;
}

rofl_result_t iface_manager_set_queues(switch_port_t *port)
{
	unsigned int i;
	int ret;
	unsigned int sock_id;
	struct rte_eth_rxconf rx_conf;
	struct rte_eth_txconf tx_conf;

	if (port->type != PORT_TYPE_PHYSICAL)
		return ROFL_SUCCESS;

	//Recover the platform state
	dpdk_port_state_t *ps = (dpdk_port_state_t *)port->platform_port_state;

	memset(&rx_conf, 0, sizeof(rx_conf));
	memset(&tx_conf, 0, sizeof(tx_conf));

	rx_conf.rx_thresh.pthresh = RX_PTHRESH;
	rx_conf.rx_thresh.hthresh = RX_HTHRESH;
	rx_conf.rx_thresh.wthresh = RX_WTHRESH;
	rx_conf.rx_free_thresh = 32;

	tx_conf.tx_thresh.pthresh = TX_PTHRESH;
	tx_conf.tx_thresh.hthresh = TX_HTHRESH;
	tx_conf.tx_thresh.wthresh = TX_WTHRESH;
	tx_conf.tx_free_thresh = 0; /* Use PMD default values */
	tx_conf.tx_rs_thresh = 0; /* Use PMD default values */
	tx_conf.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS;

	//Check first for the socket CPU id
	sock_id = rte_eth_dev_socket_id(ps->port_id);
	if(sock_id == 0xFFFFFFFF)
		sock_id = 0;//Single CPU socket system

	
	if(ps->queues_set)
		return ROFL_SUCCESS;
	
#if 0
	//Setup RX
	if( (ret=rte_eth_rx_queue_setup(port_id, 0, RTE_RX_DESC_DEFAULT, rte_eth_dev_socket_id(port_id), &rx_conf, direct_pools[sock_id])) < 0 ){
		XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot setup RX queue: %s\n", rte_strerror(ret));
		assert(0);
		return ROFL_FAILURE;
	}

	//Setup TX
	for(i=0;i<IO_IFACE_NUM_QUEUES;++i){
		//setup the queue
		if( (ret = rte_eth_tx_queue_setup(port_id, i, RTE_TX_DESC_DEFAULT, sock_id, &tx_conf)) < 0 ){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot setup TX queues: %s\n", rte_strerror(ret));
			assert(0);
			return ROFL_FAILURE;
		}

#if 0
		//bind stats IGB not supporting this???
		if( (ret = rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i)) < 0 ){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot bind TX queue(%u) stats: %s\n", i, rte_strerror(ret));
			assert(0);
			return ROFL_FAILURE;
		}
#endif
	}
#endif

	//Start port
	i = 0;
START_RETRY:
	if((ret=rte_eth_dev_start(ps->port_id)) < 0){
		if(++i != 100) {
			// Circumvent DPDK issues with rte_eth_dev_start
			usleep(300*1000);
			goto START_RETRY;
		}

		XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot start device %u:  %s\n", ps->port_id, rte_strerror(ret));
		assert(0 && "rte_eth_dev_start failed");
		return ROFL_FAILURE; 
	}

	//Set pipeline state to UP
	if(likely(phy_port_mapping[ps->port_id]!=NULL)){
		phy_port_mapping[ps->port_id]->up = true;
	}

	//Set promiscuous mode
	rte_eth_promiscuous_enable(ps->port_id);

	//Enable multicast
	rte_eth_allmulticast_enable(ps->port_id);
	
	//Reset stats
	rte_eth_stats_reset(ps->port_id);

	//Make sure the link is up
	rte_eth_dev_set_link_down(ps->port_id);
	rte_eth_dev_set_link_up(ps->port_id);

	//Set as queues setup
	ps->queues_set=true;
	
	return ROFL_SUCCESS;
}

/*
* Discovers and initializes (including rofl-pipeline state) DPDK-enabled ports.
*/
rofl_result_t iface_manager_discover_system_ports(void){

	uint8_t i;
	switch_port_t* port;

	if (check_lcore_params() < 0) {
		XDPD_ERR(DRIVER_NAME"[iface_manager] check_lcore_params failed\n");
		return ROFL_FAILURE;
	}

	if (init_lcore_rx_queues() < 0) {
		XDPD_ERR(DRIVER_NAME"[iface_manager] init_lcore_rx_queues failed\n");
		return ROFL_FAILURE;
	}

	nb_phy_ports = rte_eth_dev_count();
	XDPD_INFO(DRIVER_NAME"[iface_manager] Found %u DPDK-capable interfaces\n", nb_phy_ports);
	
	if (check_port_config(nb_phy_ports) < 0) {
		XDPD_ERR(DRIVER_NAME "[iface_manager] check_port_config failed\n");
		return ROFL_FAILURE;
	}

	for (i = 0; i < nb_phy_ports; ++i) {
		// only VF ports for now
		if (port_vf_id[i] == -1) {
			continue;
		}

		if(! ( port = configure_port(i) ) ){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Unable to initialize port-id: %u\n", i);
			return ROFL_FAILURE;
		}

		//Add port to the pipeline
		if( physical_switch_add_port(port) != ROFL_SUCCESS ){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Unable to add the switch port to physical switch; perhaps there are no more physical port slots available?\n");
			return ROFL_FAILURE;
		}

	}	

	return ROFL_SUCCESS;
}

/*
* Creates a virtual link port pair. TODO: this function is not thread safe
*/
rofl_result_t iface_manager_create_virtual_port_pair(of_switch_t* lsw1, switch_port_t **vport1, of_switch_t* lsw2, switch_port_t **vport2){

	//Names are composed following vlinkX-Y
	//Where X is the virtual link number (0... N-1)
	//Y is the edge 0 (left) 1 (right) of the connectio
	static unsigned int num_of_vlinks=0;
	char port_name[PORT_QUEUE_MAX_LEN_NAME];
	char queue_name[PORT_QUEUE_MAX_LEN_NAME];
	uint64_t port_capabilities=0x0;
	uint16_t randnum = 0;
	unsigned int i;

	//Init the pipeline ports
	snprintf(port_name,PORT_QUEUE_MAX_LEN_NAME, "vlink%u_%u", num_of_vlinks, 0);

	*vport1 = switch_port_init(port_name, true, PORT_TYPE_VIRTUAL, PORT_STATE_NONE);
	snprintf(port_name,PORT_QUEUE_MAX_LEN_NAME, "vlink%u_%u", num_of_vlinks, 1);

	*vport2 = switch_port_init(port_name, true, PORT_TYPE_VIRTUAL, PORT_STATE_NONE);
	
	if(*vport1 == NULL || *vport2 == NULL){
		XDPD_ERR(DRIVER_NAME"[iface_manager] Unable to allocate memory for virtual ports\n");
		assert(0);
		goto PORT_MANAGER_CREATE_VLINK_PAIR_ERROR;
	}

	//Initalize port features(Marking as 1G)
	port_capabilities |= PORT_FEATURE_1GB_FD;
	switch_port_add_capabilities(&(*vport1)->curr, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport1)->advertised, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport1)->supported, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport1)->peer, (port_features_t)port_capabilities);	

	randnum = (uint16_t)rand();
	(*vport1)->hwaddr[0] = ((uint8_t*)&randnum)[0];
	(*vport1)->hwaddr[1] = ((uint8_t*)&randnum)[1];
	randnum = (uint16_t)rand();
	(*vport1)->hwaddr[2] = ((uint8_t*)&randnum)[0];
	(*vport1)->hwaddr[3] = ((uint8_t*)&randnum)[1];
	randnum = (uint16_t)rand();
	(*vport1)->hwaddr[4] = ((uint8_t*)&randnum)[0];
	(*vport1)->hwaddr[5] = ((uint8_t*)&randnum)[1];

	// locally administered MAC address
	(*vport1)->hwaddr[0] &= ~(1 << 0);
	(*vport1)->hwaddr[0] |=  (1 << 1);

	//Add queues
	for(i=0;i<IO_IFACE_NUM_QUEUES;i++){
		snprintf(queue_name, PORT_QUEUE_MAX_LEN_NAME, "%s%d", "queue", i);
		if(switch_port_add_queue((*vport1), i, (char*)&queue_name, IO_IFACE_MAX_PKT_BURST, 0, 0) != ROFL_SUCCESS){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot configure queues on device (pipeline): %s\n", (*vport1)->name);
			assert(0);
			goto PORT_MANAGER_CREATE_VLINK_PAIR_ERROR;
		}
	}

	switch_port_add_capabilities(&(*vport2)->curr, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport2)->advertised, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport2)->supported, (port_features_t)port_capabilities);	
	switch_port_add_capabilities(&(*vport2)->peer, (port_features_t)port_capabilities);	

	randnum = (uint16_t)rand();
	(*vport2)->hwaddr[0] = ((uint8_t*)&randnum)[0];
	(*vport2)->hwaddr[1] = ((uint8_t*)&randnum)[1];
	randnum = (uint16_t)rand();
	(*vport2)->hwaddr[2] = ((uint8_t*)&randnum)[0];
	(*vport2)->hwaddr[3] = ((uint8_t*)&randnum)[1];
	randnum = (uint16_t)rand();
	(*vport2)->hwaddr[4] = ((uint8_t*)&randnum)[0];
	(*vport2)->hwaddr[5] = ((uint8_t*)&randnum)[1];
	
	// locally administered MAC address
	(*vport2)->hwaddr[0] &= ~(1 << 0);
	(*vport2)->hwaddr[0] |=  (1 << 1);

	//Add queues
	for(i=0;i<IO_IFACE_NUM_QUEUES;i++){
		snprintf(queue_name, PORT_QUEUE_MAX_LEN_NAME, "%s%d", "queue", i);
		if(switch_port_add_queue((*vport2), i, (char*)&queue_name, IO_IFACE_MAX_PKT_BURST, 0, 0) != ROFL_SUCCESS){
			XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot configure queues on device (pipeline): %s\n", (*vport2)->name);
			assert(0);
			goto PORT_MANAGER_CREATE_VLINK_PAIR_ERROR;
		}
	}

	//Interlace them
	(*vport2)->platform_port_state = *vport1;	
	(*vport1)->platform_port_state = *vport2;	


	//Add them to the physical switch
	if( physical_switch_add_port(*vport1) != ROFL_SUCCESS ){
		XDPD_ERR(DRIVER_NAME"[iface_manager] Unable to allocate memory for virtual ports\n");
		assert(0);
		goto PORT_MANAGER_CREATE_VLINK_PAIR_ERROR;	

	}
	if( physical_switch_add_port(*vport2) != ROFL_SUCCESS ){
		XDPD_ERR(DRIVER_NAME"[iface_manager] Unable to allocate memory for virtual ports\n");
		assert(0);
		goto PORT_MANAGER_CREATE_VLINK_PAIR_ERROR;	

	}

	//Increment counter and return
	num_of_vlinks++; 

	return ROFL_SUCCESS;

PORT_MANAGER_CREATE_VLINK_PAIR_ERROR:
	if(*vport1)
		switch_port_destroy(*vport1);
	if(*vport2)
		switch_port_destroy(*vport2);
	return ROFL_FAILURE;
}



/*
* Enable port 
*/
rofl_result_t iface_manager_bring_up(switch_port_t* port){

	unsigned int port_id;
	int ret;
	
	if(unlikely(!port))
		return ROFL_FAILURE;

	if(port->type == PORT_TYPE_VIRTUAL)
	{
		/*
		* Virtual link
		*/
		switch_port_t* port_pair = (switch_port_t*)port->platform_port_state;
		//Set link flag on both ports
		if(port_pair->up){
			port->state &= ~PORT_STATE_LINK_DOWN;
			port_pair->state &= ~PORT_STATE_LINK_DOWN;
		}else{
			port->state |= PORT_STATE_LINK_DOWN;
			port_pair->state |= PORT_STATE_LINK_DOWN;
		}
	}
	else if(port->type == PORT_TYPE_NF_SHMEM)
	{
		/*
		*  DPDK SECONDARY NF
		*/
		if(!port->up)
		{
			//Was down
			if(nf_iface_manager_bring_up_port(port) != ROFL_SUCCESS)
			{
				XDPD_ERR(DRIVER_NAME"[port_manager] Cannot start DPDK SECONDARY NF port: %s\n",port->name);
				assert(0);
				return ROFL_FAILURE; 
			}
		}
	}else if(port->type == PORT_TYPE_NF_EXTERNAL)
	{
		/*
		*	DPDK KNI NF
		*/
		if(!port->up)
		{
			//Was down
			if(nf_iface_manager_bring_up_port(port) != ROFL_SUCCESS)
			{
				XDPD_ERR(DRIVER_NAME"[port_manager] Cannot start DPDK KNI NF port: %s\n",port->name);
				assert(0);
				return ROFL_FAILURE; 
			}
		}
	}else{
		/*
		*  PHYSICAL
		*/
		port_id = ((dpdk_port_state_t*)port->platform_port_state)->port_id;

		//Start port in RTE
		if(!port->up){
			//Was down; simply start
			if((ret=rte_eth_dev_start(port_id)) < 0){
				XDPD_ERR(DRIVER_NAME"[iface_manager] Cannot start device %u:  %s\n", port_id, rte_strerror(ret));
				assert(0);
				return ROFL_FAILURE; 
			}
		}
	}
		
	//Mark the port as being up and return
	port->up = true;
		
	return ROFL_SUCCESS;
}

/*
* Disable port 
*/
rofl_result_t iface_manager_bring_down(switch_port_t* port){

	unsigned int port_id;
	
	if(unlikely(!port))
		return ROFL_FAILURE;
	
	if(port->type == PORT_TYPE_VIRTUAL) {
		/*
		* Virtual link
		*/
		switch_port_t* port_pair = (switch_port_t*)port->platform_port_state;
		port->up = false;

		//Set links as down	
		port->state |= PORT_STATE_LINK_DOWN;
		port_pair->state |= PORT_STATE_LINK_DOWN;
	}
	else if(port->type == PORT_TYPE_NF_SHMEM) {
		/*
		* NF port
		*/
		if(port->up) {
			if(nf_iface_manager_bring_down_port(port) != ROFL_SUCCESS) {
				XDPD_ERR(DRIVER_NAME"[port_manager] Cannot stop DPDK SECONDARY NF port: %s\n",port->name);
				assert(0);
				return ROFL_FAILURE; 
			}
		}		
		port->up = false;
	}else if(port->type == PORT_TYPE_NF_EXTERNAL) {
		/*
		*	KNI NF
		*/
		if(port->up){
			if(nf_iface_manager_bring_down_port(port) != ROFL_SUCCESS) {
				XDPD_ERR(DRIVER_NAME"[port_manager] Cannot stop DPDK KNI NF port: %s\n",port->name);
				assert(0);
				return ROFL_FAILURE; 
			}
		}
		port->up = false;
	}else {
		/*
		*  PHYSICAL
		*/

		port_id = ((dpdk_port_state_t*)port->platform_port_state)->port_id;

		//First mark the port as NOT up, so that cores don't issue
		//RX/TX calls over the port
		port->up = false;

		//Stop port in RTE
		if(port->up){
			//Was  up; stop it
			rte_eth_dev_stop(port_id);
		}
	}

	return ROFL_SUCCESS;
}


/*
* Shutdown all ports in the system 
*/
rofl_result_t iface_manager_destroy(void){

	uint8_t i, num_of_ports;
	num_of_ports = rte_eth_dev_count();
	
	for(i=0;i<num_of_ports;++i){
		rte_eth_dev_stop(i);
		rte_eth_dev_close(i);
		//IVANO - TODO: destroy also NF ports
	}	

	return ROFL_SUCCESS;
}

/*
* Update link states 
*/
void iface_manager_update_links(){

	unsigned int i;
	struct rte_eth_link link;
	switch_port_t* port;
	switch_port_snapshot_t* port_snapshot;
	bool last_link_state;
	
	for(i=0;i<PORT_MANAGER_MAX_PORTS;i++){
		
		port = phy_port_mapping[i];
		
		if(unlikely(port != NULL)){
			rte_eth_link_get_nowait(i,&link);
	
			last_link_state = !((port->state& PORT_STATE_LINK_DOWN) > 0); //up =>1

			//Check if there has been a change
			if(unlikely(last_link_state != link.link_status)){
				if(link.link_status)
					//Up
					port->state = port->state & ~(PORT_STATE_LINK_DOWN); 
				else
					//Down
					port->state = port->state | PORT_STATE_LINK_DOWN;
					
				XDPD_DEBUG(DRIVER_NAME"[port-manager] Port %s is %s, and link is %s\n", port->name, ((port->up) ? "up" : "down"), ((link.link_status) ? "detected" : "not detected"));
				
				//Notify CMM port change
				port_snapshot = physical_switch_get_port_snapshot(port->name); 
				if(hal_cmm_notify_port_status_changed(port_snapshot) != HAL_SUCCESS){
					XDPD_DEBUG(DRIVER_NAME"[iface_manager] Unable to notify port status change for port %s\n", port->name);
				}	
			}
		}
	}
}

/*
* Update port stats (pipeline)
*/
void iface_manager_update_stats(){

	unsigned int i, j;
	struct rte_eth_stats stats;
	switch_port_t* port;

	for(i=0; i<PORT_MANAGER_MAX_PORTS; ++i){

		port = phy_port_mapping[i];

		if(!port)
			continue;

		//Retrieve stats
		rte_eth_stats_get(i, &stats);

		//RX
		port->stats.rx_packets = stats.ipackets;
		port->stats.rx_bytes = stats.ibytes;
		port->stats.rx_errors = stats.ierrors;

		//FIXME: collisions and other errors

		//TX
		port->stats.tx_packets = stats.opackets;
		port->stats.tx_bytes = stats.obytes;
		port->stats.tx_errors = stats.oerrors;

		//TX-queues
		for(j=0; j<IO_IFACE_NUM_QUEUES; ++j){
			port->queues[j].stats.tx_packets = stats.q_opackets[j];
			port->queues[j].stats.tx_bytes = stats.q_obytes[j];
			//port->queues[j].stats.overrun = stats.q_;
		}
	}

}

