#pragma once

#include "jconf.hpp"

#include "xmrstak/misc/console.hpp"
#include "xmrstak/jconf.hpp"
#include "xmrstak/misc/configEditor.hpp"
#include "xmrstak/params.hpp"
#include "xmrstak/backend/cryptonight.hpp"
#include <string>

#include <unistd.h>

namespace xmrstak
{
namespace cpu
{
// Mask bits between h and l and return the value
// This enables us to put in values exactly like in the manual
// For example EBX[31:22] is get_masked(cpu_info[1], 31, 22)
inline int32_t get_masked(int32_t val, int32_t h, int32_t l)
{
	val &= (0x7FFFFFFF >> (31-(h-l))) << l;
	return val >> l;
}

class autoAdjust
{
public:

	bool printConfig()
	{
		size_t hashMemSizeKB;
		size_t halfHashMemSizeKB;

		configEditor configTpl{};

		// load the template of the backend config into a char variable
		const char *tpl =
			#include "./config.tpl"
		;
		configTpl.set( std::string(tpl) );

		std::string conf;

		
		if(!detectL3Size() || L3KB_size < halfHashMemSizeKB || L3KB_size > (halfHashMemSizeKB * 2048u))
		{
			if(L3KB_size < halfHashMemSizeKB || L3KB_size > (halfHashMemSizeKB * 2048))
				printer::inst()->print_msg(L0, "Autoconf failed: L3 size sanity check failed - %u KB.", L3KB_size);

			conf += std::string("    { \"low_power_mode\" : false, \"be_mode\" : true, \"affine_to_cpu\" : false },\n");
			printer::inst()->print_msg(L0, "No hwloc library. Created config for a single thread. Please try to add new ones until the hashrate slows down.");
		}
		else
		{
			printer::inst()->print_msg(L0, "Autoconf L3 size detected at %u KB.", L3KB_size);

			detectCPUConf();

			printer::inst()->print_msg(L0, "Autoconf core count detected as %u on %s.", corecnt,
				linux_layout ? "Linux" : "Windows");

			uint32_t aff_id = 0;
			for(uint32_t i=0; i < corecnt; i++)
			{
				bool double_mode;

				if(L3KB_size <= 0)
					break;

				double_mode = L3KB_size / hashMemSizeKB > (int32_t)(corecnt-i);

				conf += std::string("    { \"low_power_mode\" : ");
				conf += std::string(double_mode ? "true" : "false");
				conf += std::string(", \"be_mode\" : true, \"affine_to_cpu\" : ");
				conf += std::to_string(aff_id);
				conf += std::string(" },\n");

				if(!linux_layout || old_amd)
				{
					aff_id += 2;

					if(aff_id >= corecnt)
						aff_id = 1;
				}
				else
					aff_id++;

				if(double_mode)
					L3KB_size -= hashMemSizeKB * 2u;
				else
					L3KB_size -= hashMemSizeKB;
			}
		}

		configTpl.replace("CPUCONFIG",conf);
		configTpl.write(params::inst().configFileCPU);
		printer::inst()->print_msg(L0, "CPU configuration stored in file '%s'", params::inst().configFileCPU.c_str());

		return true;
	}

private:
	bool detectL3Size()
	{
	  return false;
  }

	void detectCPUConf()
	{
		corecnt = sysconf(_SC_NPROCESSORS_ONLN);
		linux_layout = true;
	}

	int32_t L3KB_size = 0;
	uint32_t corecnt;
	bool old_amd = false;
	bool linux_layout;
};

} // namespace cpu
} // namepsace xmrstak
