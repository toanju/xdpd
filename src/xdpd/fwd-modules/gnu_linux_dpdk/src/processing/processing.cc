#include "processing.h"
#include <rofl/common/utils/c_logger.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>

#include "assert.h"
#include "../util/compiler_assert.h"
#include "../io/tx_rx.h"

#include "../io/port_state.h"
#include "../io/port_manager.h"
#include <rofl/datapath/pipeline/openflow/of_switch.h>


using namespace xdpd::gnu_linux;
using namespace xdpd::gnu_linux_dpdk;

//
// Processing state 
//
static unsigned int current_core_index;
static unsigned int max_cores;
static rte_spinlock_t mutex;
core_tasks_t processing_cores[RTE_MAX_LCORE];
unsigned int total_num_of_ports = 0;


static void processing_dump_cores_state(void){

#ifdef DEBUG
	unsigned int i;
	enum rte_lcore_role_t role;
	enum rte_lcore_state_t state;

	return;

	for(i=0; i < RTE_MAX_LCORE; ++i){
		role = rte_eal_lcore_role(i);
		state = rte_eal_get_lcore_state(i);
		
		ROFL_DEBUG("Core %u ROLE:", i);
		switch(role){
			case ROLE_RTE:
				ROFL_DEBUG(" RTE");
				break;
			case ROLE_OFF:
				ROFL_DEBUG(" OFF");
				break;
			default:
				assert(0);
				ROFL_DEBUG(" Unknown");
				break;
		}
		
		ROFL_DEBUG(" state:");
		switch(state){
			case WAIT:
				ROFL_DEBUG(" WAIT");
				break;
			case RUNNING:
				ROFL_DEBUG(" RUNNING");
				break;
			case FINISHED:
				ROFL_DEBUG(" FINISHED");
				break;
			default:
				assert(0);
				ROFL_DEBUG(" UNKNOWN");
				break;
		}
		ROFL_DEBUG("\n");
	}
#endif	
}

/*
* Initialize data structures for processing to work 
*/
rofl_result_t processing_init(void){

	unsigned int i;
	struct rte_config* config;
	enum rte_lcore_role_t role;

	//Cleanup
	memset(processing_cores,0,sizeof(core_tasks_t)*RTE_MAX_LCORE);	

	//Init 
	current_core_index = 0;
	config = rte_eal_get_configuration();
	max_cores = config->lcore_count;
	rte_spinlock_init(&mutex);
		
	ROFL_DEBUG("Processing init: %u logical cores guessed from rte_eal_get_configuration(). Master is: %u\n", config->lcore_count, config->master_lcore);

	//Define available cores 
	for(i=0; i < RTE_MAX_LCORE; ++i){
		role = rte_eal_lcore_role(i);
		if(role == ROLE_RTE && i != config->master_lcore){
			processing_cores[i].available = true;
			ROFL_DEBUG("Marking core %u as available\n",i);
		}
	}

	processing_dump_cores_state();	

	return ROFL_SUCCESS;
}


/*
* Destroy data structures for processing to work 
*/
rofl_result_t processing_destroy(void){

	unsigned int i;

	ROFL_DEBUG("Shutting down all active cores\n");
	
	//Stop all cores and wait for them to complete execution tasks
	for(i=0;i<RTE_MAX_LCORE;++i){
		if(processing_cores[i].available && processing_cores[i].active){
			ROFL_DEBUG("Shutting down active core %u\n",i);
			processing_cores[i].active = false;
			//Join core
			rte_eal_wait_lcore(i);
		}
	}
	return ROFL_SUCCESS;
}


int processing_core_process_packets(void* not_used){

	unsigned int i, port_id;
	int j;
	switch_port_t* port;
	port_queues_t* port_queues;	
        uint64_t diff_tsc, prev_tsc;
	struct rte_mbuf* pkt_burst[IO_IFACE_MAX_PKT_BURST]={0};
	core_tasks_t* tasks = &processing_cores[rte_lcore_id()];

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * IO_BURST_TX_DRAIN_US;

	//Parsing and pipeline extra state
	datapacket_t pkt;
	datapacketx86 pkt_x86;
	dpdk_pkt_platform_state_t pkt_state;

	//Init values and assign
	pkt.platform_state = (platform_datapacket_state_t*)&pkt_state;
	pkt_state.pktx86 = &pkt_x86; 
	pkt_state.mbuf = NULL;

	//Set flag to active
	tasks->active = true;
	
	//Last drain tsc
	prev_tsc = 0;

	while(likely(tasks->active)){

		//Calc diff
		diff_tsc = prev_tsc - rte_rdtsc();  

		//Drain TX if necessary	
		if(unlikely(diff_tsc > drain_tsc)){

			for(i=0; i<MAX_PORTS; ++i){
				if(likely(!tasks->all_ports[i].present))
					continue;
				port_queues = &tasks->all_ports[i];
				port = port_mapping[i];

				if(unlikely(!port))
					continue;

				//Process TX
				for( j=(IO_IFACE_NUM_QUEUES-1); j >=0 ; j-- ){
					process_port_queue_tx(port, i, &port_queues->tx_queues[j], j);
				}
			}
		}

		//Process RX
		for(i=0;i<tasks->num_of_rx_ports;++i){
			port = tasks->port_list[i];
			if(likely(port != NULL) && likely(port->up)){ //This CAN happen while deschedulings

				port_id = ((dpdk_port_state_t*)port->platform_port_state)->port_id;

				//Process RX&pipeline 
				process_port_rx(port, port_id, pkt_burst, &pkt, &pkt_state);
			}
		}
	}
	
	tasks->active = false;

	return (int)ROFL_SUCCESS; 
}


//
//Port scheduling
//

/*
* Schedule port. Shedule port to an available core (RR)
*/
rofl_result_t processing_schedule_port(switch_port_t* port){

	unsigned int i, index, *num_of_ports;
	dpdk_port_state_t* port_state = (dpdk_port_state_t*)port->platform_port_state;	

	rte_spinlock_lock(&mutex);

	if(total_num_of_ports == MAX_PORTS){
		ROFL_ERR("Already MAX_PORTSAll cores are full. No available port slots\n");
		rte_spinlock_unlock(&mutex);
		return ROFL_FAILURE;
	}

	//Select core
	for(current_core_index++, index=current_core_index;;){
		if( processing_cores[current_core_index].available == true && processing_cores[current_core_index].num_of_rx_ports != MAX_PORTS_PER_CORE )
			break;

		//Circular increment
		if(current_core_index+1 == RTE_MAX_LCORE)
			current_core_index=0; 
		else
			current_core_index++;
	
		//We've already checked all positions. No core free. Return
		if(current_core_index == index){
			//All full 
			ROFL_ERR("All cores are full. No available port slots\n");
			assert(0);		
			rte_spinlock_unlock(&mutex);
			return ROFL_FAILURE;
		}
	}

	ROFL_DEBUG("Selected core %u for scheduling port %s(%p)\n", current_core_index, port->name, port); 

	num_of_ports = &processing_cores[current_core_index].num_of_rx_ports;

	//Assign port and exit
	if(processing_cores[current_core_index].port_list[*num_of_ports] != NULL){
		ROFL_ERR("Corrupted state on the core task list\n");
		assert(0);
		rte_spinlock_unlock(&mutex);
		return ROFL_FAILURE;
	}

	//FIXME: check if already scheduled
	if( port_manager_set_queues(current_core_index, port_state->port_id) != ROFL_SUCCESS){
		assert(0);
		return ROFL_FAILURE;
	}


	//Store attachment info (back reference)
	port_state->core_id = current_core_index; 
	port_state->core_port_slot = *num_of_ports;
	
	processing_cores[current_core_index].port_list[*num_of_ports] = port;
	(*num_of_ports)++;
	
	index = current_core_index;

	//Mark port as present (and scheduled) on all cores (TX)
	for(i=0;i<RTE_MAX_LCORE;++i){
		processing_cores[i].all_ports[port_state->port_id].present = true;
	}

	//Increment total counter
	total_num_of_ports++;
	
	rte_spinlock_unlock(&mutex);

	if(!processing_cores[index].active){
		if(rte_eal_get_lcore_state(index) != WAIT){
			assert(0);
			rte_panic("Core status corrupted!");
		}
		
		ROFL_DEBUG("Launching core %u due to scheduling action of port %p\n", index, port);

		//Launch
		ROFL_DEBUG_VERBOSE("Pre-launching core %u due to scheduling action of port %p\n", index, port);
		if( rte_eal_remote_launch(processing_core_process_packets, NULL, index) < 0)
			rte_panic("Unable to launch core %u! Status was NOT wait (race-condition?)", index);
		ROFL_DEBUG_VERBOSE("Post-launching core %u due to scheduling action of port %p\n", index, port);
	}
	
	port_state->scheduled = true;
		
	return ROFL_SUCCESS;
}

/*
* Deschedule port to a core 
*/
rofl_result_t processing_deschedule_port(switch_port_t* port){

	unsigned int i;
	dpdk_port_state_t* port_state = (dpdk_port_state_t*)port->platform_port_state;	
	core_tasks_t* core_task = &processing_cores[port_state->core_id];

	if(port_state->scheduled == false){
		ROFL_ERR("Tyring to descheduled an unscheduled port\n");
		assert(0);
		return ROFL_FAILURE;
	}

	rte_spinlock_lock(&mutex);

	//This loop copies from descheduled port, all the rest of the ports
	//one up, so that list of ports is contiguous (0...N-1)

	for(i=(core_task->num_of_rx_ports-1); i > port_state->core_port_slot; i--)
		core_task->port_list[i-1] = core_task->port_list[i];	
	
	//Cleanup the last position
	core_task->num_of_rx_ports--;
	core_task->port_list[core_task->num_of_rx_ports] = NULL;

	//There are no more ports, so simply stop core
	if(core_task->num_of_rx_ports == 0){
		if(rte_eal_get_lcore_state(port_state->core_id) != RUNNING){
			ROFL_ERR("Corrupted state; port was marked as active, but EAL informs it was not running..\n");
			assert(0);
			
		}
		
		ROFL_DEBUG("Shutting down core %u, since port list is empty\n",i);
		
		core_task->active = false;
		
		//Wait for core to stop
		rte_eal_wait_lcore(port_state->core_id);
	}
	
	//Decrement total counter
	total_num_of_ports--;
	
	//Mark port as NOT present anymore (descheduled) on all cores (TX)
	for(i=0;i<RTE_MAX_LCORE;++i){
		processing_cores[i].all_ports[port_state->port_id].present = false;
	}

	rte_spinlock_unlock(&mutex);	
	
	port_state->scheduled = false;

	return ROFL_SUCCESS;
}

/*
* Dump core state
*/
void processing_dump_core_state(void){

	unsigned int i,j;
	core_tasks_t* core_task;
	
	for(i=0;i<max_cores;++i){
		core_task = &processing_cores[i];
		if(!core_task->available)
			continue;

		//Print basic info	
		ROFL_ERR("Core: %u ",i);
		
		if(!core_task->active)
			ROFL_DEBUG("IN");
		ROFL_DEBUG("ACTIVE port-list:[");
	
		for(j=0;j<core_task->num_of_rx_ports;++j){
			if(core_task->port_list[j] == NULL){
				ROFL_DEBUG("error_NULL,");
				continue;
			}
			ROFL_DEBUG("%s,",core_task->port_list[j]->name);
		}
		ROFL_DEBUG("]\n");
	}
}



