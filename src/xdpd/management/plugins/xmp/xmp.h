/*
 * xmp.h
 *
 *  Created on: 11.01.2014
 *      Author: andreas
 */

#ifndef XDPD_MANAGER_H_
#define XDPD_MANAGER_H_

#include <inttypes.h>
#include <rofl/common/csocket.h>
#include <deque>

#include "../../switch_manager.h"
#include "../../port_manager.h"
#include "../../plugin_manager.h"

#include "cxmpmsg.h"

namespace xdpd {
namespace mgmt {
namespace protocol {

class xmp : public rofl::ciosrv,
		public rofl::csocket_env,
		public plugin
{
	rofl::csocket*						socket;			// listening socket
	rofl::cparams						socket_params;
	enum rofl::csocket::socket_type_t 	socket_type;

	std::set<rofl::csocket*>			workers;	// socket instances for doing work
	rofl::cmemory						*fragment;
	unsigned int						msg_bytes_read;


#define MGMT_PORT_UDP_ADDR	"127.0.0.1"
#define MGMT_PORT_UDP_PORT	"8444"

public:

	xmp();

	virtual ~xmp();

	virtual void init();

	virtual std::string get_name(void){
		return std::string("xmp");
	};

protected:

	/*
	 * overloaded from ciosrv
	 */

	virtual void
	handle_timeout(
			int opaque, void *data = (void*)0);

protected:

	/*
	 * overloaded from csocket_owner
	 */

	virtual void
	handle_listen(rofl::csocket& socket, int newsd);

	virtual void
	handle_accepted(rofl::csocket& socket);

	virtual void
	handle_accept_refused(rofl::csocket& socket);

	virtual void
	handle_connected(rofl::csocket& socket) {};

	virtual void
	handle_connect_refused(rofl::csocket& socket) {};

	virtual void
	handle_connect_failed(rofl::csocket& socket) {};

	virtual void
	handle_write(rofl::csocket& socket) {};

	virtual void
	handle_read(rofl::csocket& socket);

	virtual void
	handle_closed(rofl::csocket& socket);


	/**
	 * overloaded from plugin
	 */
	virtual std::vector<rofl::coption> get_options(void);


private:

	void
	handle_request(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_attach(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_detach(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_enable(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_disable(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_list(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_port_info(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_list(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_info(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_create(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_destroy(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_connect_to_controller(rofl::csocket& socket, cxmpmsg& msg);

	void
	handle_lsi_cross_connect(rofl::csocket& socket, cxmpmsg& msg);

	int
	controller_connect(uint64_t dpid, std::deque<cxmpie*>::const_iterator iter, std::deque<cxmpie*>::const_iterator end);
};

}; // end of namespace protocol
}; // end of namespace mgmt
}; // end of namespace xdpd



#endif /* XDPD_MANAGER_H_ */
