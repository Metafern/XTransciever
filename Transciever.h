#pragma once
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "PacketManager.h"

namespace xtx {
	
	

	class Reciever {
	private:
		std::string listen_ip1;
		std::string listen_ip2;
		int cookie;
		
	public:
		void Start(std::string ip1, std::string ip2, std::string primary_switch_ip, std::string searchfilter);
	};

}