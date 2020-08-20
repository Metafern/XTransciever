#pragma once
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <fstream>
#include <iostream>
#include <PayloadLayer.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

class Parser {
public:
	enum PacketTypes {
		PIA_MSG = 50,
		BROWSE_REQUEST = 0,
		BROWSE_REPLY = 1
	};
	
	const uint8_t GAME_KEY[16] = { 112, 49, 102, 114, 88, 113, 120, 109, 101, 67, 90, 87, 70, 118, 48, 88 }; //Game specific key used for encryption
	int srcIP;
	int dstIP;

	std::string srcIP_str;
	std::string inject_ip;

	size_t message_len;
	uint8_t message[2048];
	uint8_t message_new[2048];
	uint8_t decrypted[2048];
	uint8_t encrypted[2048];
	int data_len;
	uint8_t session_key[16];

	uint8_t nonce[12];
	uint8_t tag[16];

	const uint8_t magic_prefix = 1;
	const uint8_t magic1 = 0x62;
	const uint8_t magic2 = 0x67;
	const uint8_t magic3 = 0x69;
	const uint8_t pkmn_header[2] = { 0xd8, 0x02 };
	const int ek8_len = 0x158;
	
	uint8_t original_pkmn[0x158];
	uint8_t inject_pkmn[0x158];

	bool does_original_exist = false;

	void OnPacket(pcpp::Packet* packet, std::string input_ip);
private:
	bool DecryptPia(); //returns pointer to decrypted
	void ParseBrowseReply();
	void SetSessionKey(uint8_t mod_param[]);
	void TryInject();
	bool EncryptPia();
	bool FindPokemon(uint8_t message[], int message_len, int pointer);
	bool InjectPokemon(uint8_t message[], int pointer);

};