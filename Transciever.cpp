#include "Transciever.h"


using namespace std;
using namespace pcpp;
using namespace xtx;


struct tx_utils
{
	Parser parser;
	pcpp::PcapLiveDevice* reciever;
	std::string switch_ip;
	bool isPrimary = false;
} cookie1, cookie2;

std::string primary_ip;
int counter = 0;

void onPacket(RawPacket* rawpacket, PcapLiveDevice* in, void* cookie) {
	
	tx_utils* tx_util = (tx_utils*) cookie;
	printf("Packet %d found on interface %s!\n", counter++, tx_util->switch_ip.c_str());
	Packet packet(rawpacket);
	IPv4Layer* ipLayer = packet.getLayerOfType<IPv4Layer>();




	Parser* parser = &tx_util->parser;
	PcapLiveDevice* out = tx_util->reciever;
	parser->OnPacket(&packet, primary_ip);

	//only send packet to primary side if it was not originally broadcast from that side (to prevent feedback)
	if (tx_util->isPrimary) {
		if (ipLayer->getSrcIpAddress().toString().compare(tx_util->switch_ip) == 0) {
			out->sendPacket(&packet);
			return;
		}
	}

	//only send packet to secondary side if it was not originally broadcast from that side (to prevent feedback)
	else {
		if (ipLayer->getSrcIpAddress().toString().compare(tx_util->switch_ip) != 0) {
			out->stopCapture();
			out->sendPacket(&packet);
			return;
		}
	}
}

void Reciever::Start(string ip1, string ip2, string primary_switch_ip, string searchfilter) { //ip1 is primary

	primary_ip = primary_switch_ip; //not to be confused with cookie1/2->switch_ip

	if (ip1.compare(ip2) == 0) { printf("\nGiven IPs are the same.\n"); exit(1); }

	listen_ip1 = ip1;
	listen_ip2 = ip2;

	cookie1.reciever = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ip1.c_str());
	cookie2.reciever = PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ip2.c_str());

	printf("Starting\n");
	if (cookie1.reciever == nullptr || cookie2.reciever == nullptr)
	{
		printf("Invalid IP. Are you sure you're connected?\n");
		exit(1);
	}
	if (!cookie1.reciever->open() || !cookie2.reciever->open())
	{
		printf("Unable to open device %s\n", cookie1.reciever->getDesc());
		exit(1);
	}
	if (!cookie1.reciever->setFilter(searchfilter) || !cookie2.reciever->setFilter(searchfilter)) {
		printf("Could not set filter\n");
		exit(1);
	}

	cookie1.isPrimary = true;
	cookie1.switch_ip = primary_switch_ip;
	
	cookie1.reciever->startCapture(onPacket, &cookie2);
	cookie2.reciever->startCapture(onPacket, &cookie1);
	while (true) {} //just wait forever; will be changed later
}
