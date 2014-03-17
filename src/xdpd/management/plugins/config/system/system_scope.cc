#include "system_scope.h"
#include <vector>
#include <stdlib.h>
#include <inttypes.h>
#include <rofl/common/logging.h>
#include "../../../system_manager.h"

using namespace xdpd;
using namespace rofl;

#define LOGGING_LEVEL "logging-level"
#define DRIVER_EXTRA_PARAMS "driver-extra-params"


system_scope::system_scope(std::string name, bool mandatory):scope(name, mandatory){
	
	//Register parameters
	register_parameter(LOGGING_LEVEL);
	register_parameter(DRIVER_EXTRA_PARAMS);

	//Register subscopes
	//None for the moment
}

/* Case insensitive */
void system_scope::post_validate(libconfig::Setting& setting, bool dry_run){

	int logging_level=-1;

	//Parse mode
	if(setting.exists(LOGGING_LEVEL)){
		std::string log_level = setting[LOGGING_LEVEL];

		//Validate
		if(log_level == "EMERG")
			logging_level = logging::EMERG;
		else if(log_level == "ALERT")
			logging_level = logging::ALERT;
		else if(log_level == "CRIT")
			logging_level = logging::CRIT;
		else if(log_level == "ERROR")
			logging_level = logging::ERROR;
		else if(log_level == "WARN")
			logging_level = logging::WARN;
		else if(log_level == "NOTICE")
			logging_level = logging::NOTICE;
		else if(log_level == "INFO")
			logging_level = logging::INFO;
		else if(log_level == "DEBUG")
			logging_level = logging::DBG; 
		else if(log_level == "TRACE")
			logging_level = logging::TRACE;
		else
 			ROFL_WARN("%s: Invalid logging level '%s'.\n", setting.getPath().c_str(), log_level.c_str());
		
	}	
	//Execute
	if(!dry_run && logging_level!=-1){
		//Set logging
		system_manager::set_logging_debug_level(logging_level);
	}
}
