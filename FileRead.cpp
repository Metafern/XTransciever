#include "FileRead.h"
#include "stdlib.h"
#include "PcapFileDevice.h"
#include "PacketManager.h"
#include "PlatformSpecificUtils.h"
#include <IPv4Layer.h>
#include <Packet.h>
#include "PcapLiveDeviceList.h"

void Read::Start() {
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("packets.pcap");

	// verify that a reader interface was indeed created
	if (reader == NULL)
	{
		printf("Cannot determine reader for file type\n");
		exit(1);
	}
	if (!reader->open())
	{
		printf("Cannot open input.pcap for reading\n");
		exit(1);
	}

	pcpp::RawPacket rawPacket;
	pcpp::Packet packet(&rawPacket);
	Parser parser;
	std::string ip = "10.13.0.115";
	int count = 0;
	printf("\nBeginning...\n");
	while (reader->getNextPacket(rawPacket))
	{
		parser.OnPacket(&packet, ip);
		count++;
	}
	printf("\nDone! Got %d Packets.\n", count);
}