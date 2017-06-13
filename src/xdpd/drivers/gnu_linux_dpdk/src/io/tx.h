/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _TX_H_
#define _TX_H_

#include "../config.h"
#include <utils/c_logger.h>
#include <rte_config.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <assert.h>
#include "bufferpool.h"
#include "dpdk_datapacket.h"

#include "port_state.h"
#include "iface_manager.h"
#include "../processing/processing.h"

namespace xdpd {
namespace gnu_linux_dpdk {

//
// Packet TX
//

inline void transmit_port_queue_tx_burst(core_tasks_t *task, uint8_t port_id)
{
	uint16_t ret;
	struct rte_mbuf **m_table;
	unsigned len;
	uint16_t queue_id;
	switch_port_t* port;

	queue_id = task->tx_queue_id;
	m_table = (struct rte_mbuf **)task->ports[port_id].tx_queues_burst[queue_id].burst;
	len = task->ports[port_id].tx_queues_burst[queue_id].len;
	port = phy_port_mapping[port_id];

	RTE_LOG(INFO, XDPD, DRIVER_NAME "[io][%s(%u)] Trying to transmit burst on port queue_id %u of length %u\n",
		port->name, port_id, queue_id, len);

	//Send burst
	rte_spinlock_lock(&spinlock_conf[port_id]);
	ret = rte_eth_tx_burst(port_id, queue_id, m_table, len);
	rte_spinlock_unlock(&spinlock_conf[port_id]);

	if (ret)
		RTE_LOG(
		    INFO, XDPD,
		    "[io][%s(%u)] +++ Transmitted %u pkts, on queue_id %u\n",
		    phy_port_mapping[port_id]->name, port_id, ret, queue_id);

	if (unlikely(ret < len)) {
		//Increment errors
		port->stats.tx_dropped += ret;
		port->queues[queue_id].stats.overrun += ret;

		do {
			//Now release the mbuf
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < len);
	}
}

#if 0
inline void
flush_port_queue_tx_burst(switch_port_t* port, unsigned int port_id, struct mbuf_burst* queue, unsigned int queue_id){
	unsigned ret;

	if( queue->len == 0 || unlikely((port->up == false)) ){
		return;
	}

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][%s(%u)] Trying to flush burst(enqueue in lcore ring) on port queue_id %u of length: %u\n", port->name,  port_id, queue_id, queue->len);

	//Enqueue to the lcore (if it'd we us, we could probably call to transmit directly)
	ret = rte_ring_mp_enqueue_burst(port_tx_lcore_queue[port_id][queue_id], (void **)queue->burst, queue->len);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][%s(%u)] --- Flushed %u pkts, on queue id %u\n", port->name, port_id, ret, queue_id);

	if (unlikely(ret < queue->len)) {
		//TODO increase error counters?
		do {
			rte_pktmbuf_free(queue->burst[ret]);
		} while (++ret < queue->len);
	}

	//Reset queue size
	queue->len = 0;
}
#endif

inline void
tx_pkt(switch_port_t* port, unsigned int queue_id, datapacket_t* pkt){

	struct rte_mbuf* mbuf;
	struct mbuf_burst* pkt_burst;
	unsigned int port_id, len, rte_lcore;

	//Get mbuf pointer
	mbuf = ((datapacket_dpdk_t*)pkt->platform_state)->mbuf;
	assert(mbuf);
	port_id = ((dpdk_port_state_t*)port->platform_port_state)->port_id;

	rte_lcore = rte_lcore_id();
	if (rte_lcore == 0xffffffff) rte_lcore=0;

	//Recover core task
	core_tasks_t* tasks = &processing_core_tasks[rte_lcore];

	//Recover burst container (cache)
	pkt_burst = &tasks->ports[port_id].tx_queues_burst[queue_id];
	assert(pkt_burst);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io] Adding packet %p to queue %p (id: %u)\n", pkt, pkt_burst, rte_lcore);

	//Enqueue
	len = pkt_burst->len;
	pkt_burst->burst[len] = mbuf;
	len++;

	//If burst is full => trigger send
	if ( unlikely(!tasks->active) || unlikely(len == IO_IFACE_MAX_PKT_BURST)) { //If buffer is full or mgmt core
		pkt_burst->len = len;
		transmit_port_queue_tx_burst(tasks, port_id);
		len = 0;
	}

	pkt_burst->len = len;

	return;
}


//
// Specific NF port functions
//
#ifdef GNU_LINUX_DPDK_ENABLE_NF

/**
* Shmem port
*/
void inline
flush_shmem_nf_port(switch_port_t* port, rte_ring* queue, struct mbuf_burst* burst){

	unsigned ret;
#ifdef ENABLE_DPDK_SECONDARY_SEMAPHORE
	uint32_t tmp, next_tmp;
#endif
	if( burst->len == 0 || unlikely((port->up == false)) ){
		return;
	}

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][shmem][%s] Trying to flush burst(enqueue in lcore ring) of length: %u\n", port->name,  burst->len);

	//Enqueue to the shmem ring
	ret = rte_ring_mp_enqueue_burst(queue, (void **)burst->burst, burst->len);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][shmem][%s] --- Flushed %u pkts\n", port->name, ret);

#ifdef ENABLE_DPDK_SECONDARY_SEMAPHORE
	unsigned int ret_cpy = ret;
#endif

	if (unlikely(ret < burst->len)) {
		//TODO increase error counters?
		do {
			rte_pktmbuf_free(burst->burst[ret]);
		} while (++ret < burst->len);
	}

#ifdef ENABLE_DPDK_SECONDARY_SEMAPHORE
	dpdk_shmem_port_state *port_state = (dpdk_shmem_port_state_t*)port->platform_port_state;
	if( likely(ret_cpy >0)){
		unsigned int i;

		//The packet has been enqueued

		//XXX port_statistics[port].tx++;

		//Increment the variable containing the number of pkts inserted
		//from the last sem_post
		do{
			tmp = port_state->counter_from_last_flush;
			next_tmp = (tmp + ret_cpy) % PKT_TO_NF_THRESHOLD;
		}while(__sync_bool_compare_and_swap(&(port_state->counter_from_last_flush),tmp,next_tmp) == false);

		//Notify that pkts are available
		for(i=0;i<ret_cpy;++i)
			sem_post(port_state->semaphore);
	}
#endif

	//Reset queue size
	burst->len = 0;
}

inline void
tx_pkt_shmem_nf_port(switch_port_t* port, datapacket_t* pkt)
{
	struct mbuf_burst* pkt_burst;
	unsigned int len, rte_lcore;

	dpdk_shmem_port_state *port_state = (dpdk_shmem_port_state_t*)port->platform_port_state;
	struct rte_mbuf* mbuf;

	//Get mbuf pointer
	mbuf = ((datapacket_dpdk_t*)pkt->platform_state)->mbuf;

	rte_lcore = rte_lcore_id();
        if (rte_lcore == 0xffffffff) rte_lcore=0;

        //Recover core task
        core_tasks_t* tasks = &processing_core_tasks[rte_lcore];
        
	//Recover burst container (cache)
	pkt_burst = &tasks->ports[port_state->state.port_id].tx_queues_burst[0];

	assert(pkt_burst);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][shmem] Adding packet %p to queue %p (id: %u)\n", pkt, pkt_burst, rte_lcore);

	//Enqueue
	len = pkt_burst->len;
	pkt_burst->burst[len] = mbuf;
	len++;

	//If burst is full => trigger send
	if ( unlikely(!tasks->active) || unlikely(len == IO_IFACE_MAX_PKT_BURST)) { //If buffer is full or mgmt core
		pkt_burst->len = len;
		flush_shmem_nf_port(port, port_state->to_nf_queue, pkt_burst);
		return;
	}

	pkt_burst->len = len;
}

/**
* KNI
*/
inline void
transmit_kni_nf_port_burst(core_tasks_t *task, uint8_t port_id)
{
	uint16_t ret;
	struct rte_mbuf **m_table;
	unsigned len;
	uint16_t queue_id;
	switch_port_t* port;
	dpdk_kni_port_state *port_state;

	queue_id = task->tx_queue_id;
	m_table = (struct rte_mbuf **)task->ports[port_id].tx_queues_burst[queue_id].burst;
	len = task->ports[port_id].tx_queues_burst[queue_id].len;
	port = nf_port_mapping[port_id - nb_phy_ports];

	assert(port);

	RTE_LOG(INFO, XDPD, DRIVER_NAME "[io][kni] Trying to transmit burst on KNI port %s of length %u\n", port->name,
		len);

	//Send burst
	port_state = (dpdk_kni_port_state_t*)port->platform_port_state;

	rte_spinlock_lock(&spinlock_conf[port_id]);
	ret = rte_kni_tx_burst(port_state->kni, m_table, len);
	rte_spinlock_unlock(&spinlock_conf[port_id]);

	//XXX port_statistics[port].tx += ret;
	if (ret > 0)
		RTE_LOG(INFO, XDPD, DRIVER_NAME "[io][kni] Transmited %u pkts, on port %s\n", ret,
			port->name);

	if (unlikely(ret < len)) {
		//XXX port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < len);
	}
}

inline void
flush_kni_nf_port_burst(switch_port_t* port, unsigned int port_id, struct mbuf_burst* queue)
{
	unsigned ret;

	if( queue->len == 0 || unlikely((port->up == false)) ){
		return;
	}

	assert((dpdk_kni_port_state_t*)port->platform_port_state != NULL);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][kni] Trying to flush burst(enqueue in lcore ring) on KNI port %s\n", port->name, queue->len);


	ret = rte_ring_mp_enqueue_burst(port_tx_nf_lcore_queue[port_id], (void **)queue->burst, queue->len);

	//XXX port_statistics[port].tx += ret;

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][kni] --- Flushed %u pkts, on KNI port %s\n", port_id, ret, port->name);

	if (unlikely(ret < queue->len))
	{
		//XXX port_statistics[port].dropped += (n - ret);
		do {
			rte_pktmbuf_free(queue->burst[ret]);
		} while (++ret < queue->len);
	}

	//Reset queue size
	queue->len = 0;
}

inline void
tx_pkt_kni_nf_port(switch_port_t* port, datapacket_t* pkt)
{
	struct rte_mbuf* mbuf;
	struct mbuf_burst* pkt_burst;
	unsigned int port_id, len, rte_lcore;

	//Get mbuf pointer
	mbuf = ((datapacket_dpdk_t*)pkt->platform_state)->mbuf;
	port_id = ((dpdk_port_state_t*)port->platform_port_state)->port_id;

	assert(mbuf);

	rte_lcore = rte_lcore_id();
        if (rte_lcore == 0xffffffff) rte_lcore=0;

        //Recover core task
        core_tasks_t* tasks = &processing_core_tasks[rte_lcore];

	//Recover burst container (cache)
	pkt_burst = &tasks->ports[port_id].tx_queues_burst[0];
	assert(pkt_burst);

	XDPD_DEBUG_VERBOSE(DRIVER_NAME"[io][kni] Adding packet %p to queue %p (id: %u)\n", pkt, pkt_burst, rte_lcore);

	//Enqueue
	len = pkt_burst->len;
	pkt_burst->burst[len] = mbuf;
	len++;

	//If burst is full => trigger send
	if ( unlikely(!tasks->active) || unlikely(len == IO_IFACE_MAX_PKT_BURST))
	{
		//If buffer is full or mgmt core
		pkt_burst->len = len;
		transmit_kni_nf_port_burst(tasks, port_id);
		len = 0;
	}

	pkt_burst->len = len;

	return;
}

#endif //GNU_LINUX_DPDK_ENABLE_NF

inline void process_port_tx(core_tasks_t *task, uint8_t port_id)
{
	switch_port_t* port;

	port = port_list[port_id];
	assert(port_id == ((dpdk_port_state_t*)port->platform_port_state)->port_id);

	switch(port->type){
	case PORT_TYPE_PHYSICAL:
		transmit_port_queue_tx_burst(task, port_id);
		break;
#ifdef GNU_LINUX_DPDK_ENABLE_NF
	case PORT_TYPE_NF_EXTERNAL:
		transmit_kni_nf_port_burst(task, port_id);
		break;
	case PORT_TYPE_NF_SHMEM:
		assert(0 && "missing implementation");
		break;
#endif
	default:
		assert(0 && "invalid branch");
		break;
	}
}

//
// vlink specific functions
//

/**
* Transmit a packet through a vlink
*/
void tx_pkt_vlink(switch_port_t* vlink, datapacket_t* pkt);

}// namespace xdpd::gnu_linux_dpdk
}// namespace xdpd

#endif //_TX_H_
