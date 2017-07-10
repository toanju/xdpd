/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _PROCESSING_H_
#define _PROCESSING_H_

#include <rofl_datapath.h>
#include "../config.h"
#include <rte_config.h> 
#include <rte_common.h> 
#include <rte_eal.h> 
#include <rte_log.h>
#include <rte_launch.h> 
#include <rte_mempool.h> 
#include <rte_mbuf.h> 
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_launch.h>

#include "../io/dpdk_datapacket.h"

#define PROCESSING_MAX_PORTS_PER_CORE 32
#define PROCESSING_MAX_PORTS 128 

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

// Burst definition(queue)
struct mbuf_burst {
	unsigned len;
	struct rte_mbuf *burst[IO_IFACE_MAX_PKT_BURST];
};

#if 0 /* XXX(toanju) disable queues for now */
// Port queues
typedef struct port_bursts{
	//This are TX-queues of a port
	unsigned int core_id; //core id serving RX/TX on this port
	struct mbuf_burst tx_queues_burst[IO_IFACE_NUM_QUEUES];
}port_bursts_t;
#endif

/**
* Core task list
*/
typedef struct core_tasks{
	bool available;
	bool active;
	volatile unsigned int running_hash;
	
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];

	//This are the TX-queues for ALL ports in the system; index is port_id
	struct mbuf_burst tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned core_tasks_t;

/**
* Processig core tasks 
*/
extern core_tasks_t processing_core_tasks[RTE_MAX_LCORE];
extern struct rte_mempool* direct_pools[NB_SOCKETS];
extern switch_port_t* port_list[PROCESSING_MAX_PORTS];
extern rte_spinlock_t spinlock_conf[RTE_MAX_ETHPORTS];

/**
* Total number of physical ports (scheduled, so usable by the I/O)
*/
extern unsigned int total_num_of_phy_ports;

/**
* Total number of NF ports (scheduled, so usable by the I/O)
*/
extern unsigned int total_num_of_nf_ports;

/**
* Running hash
*/
extern unsigned int running_hash; 


//C++ extern C
ROFL_BEGIN_DECLS

/**
* Initialize data structures for processing to work 
*/
rofl_result_t processing_init(void);

/**
* Destroy data structures for processing to work 
*/
rofl_result_t processing_destroy(void);

/**
* Schedule (physical) port to a core 
*/
rofl_result_t processing_schedule_port(switch_port_t* port);

/**
* Schedule NF port to a core 
*/
rofl_result_t processing_schedule_nf_port(switch_port_t* port);


/**
* Deschedule port to a core 
*/
rofl_result_t processing_deschedule_port(switch_port_t* port);

/**
* Deschedule NF port to a core 
*/
rofl_result_t processing_deschedule_nf_port(switch_port_t* port);


/**
* Packet processing routine for cores 
*/
int processing_core_process_packets(void*);

/**
* Dump core state
*/
void processing_dump_core_states(void);

//C++ extern C
ROFL_END_DECLS

#endif //_PROCESSING_H_
