#include "Transciever.h"
#include <stdio.h>
#include "FileRead.h"
using namespace xtx;
using namespace std;


int main() {
	Reciever r;
	string searchfilter = "((src or dst portrange 49152-49155) or (src or dst port 30000)) and (udp)";
	string interfaceIPAddr2 = "10.0.0.224"; //secondary (the ip your switch isn't on)
	string interfaceIPAddr1 = "192.168.1.101"; //primary (the ip your switch is on)

	string switch_ip = "10.13.0.115"; //your switch ip

	r.Start(interfaceIPAddr1, interfaceIPAddr2, switch_ip, searchfilter);


	//FileRead was used for debugging. It reads a pcap file (specified in Read::Start()) instead of real time packet parsing. 
	Read f; 
	//f.Start();

}