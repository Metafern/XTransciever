#include "PacketManager.h"

using namespace pcpp;
using namespace std;
void Parser::OnPacket(Packet* packet, string input_ip) {

	//Parse the rawpacket into a packet
	PayloadLayer* payload = packet->getLayerOfType<PayloadLayer>();
	if (payload == nullptr) { return; }

	IPv4Layer* ipLayer = packet->getLayerOfType<IPv4Layer>();

	srcIP = ipLayer->getSrcIpAddress().toInt();
	dstIP = ipLayer->getDstIpAddress().toInt();

	srcIP_str = ipLayer->getSrcIpAddress().toString();
	inject_ip = input_ip;

	uint8_t* message_pointer = payload->getData();
	message_len = payload->getPayloadLen();

	for (int i = 0; i < message_len; i++) {
		message[i] = *(message_pointer + i);
	}
	
	switch (message[0]) {
	case PIA_MSG:
		if (DecryptPia()) {
			if (FindPokemon(decrypted, data_len, 0)) {
				EncryptPia();
			}
		}
		break;
	
	case BROWSE_REPLY:
		ParseBrowseReply(); //Used to get session key (used for encryption/decryption)
		break;
	
	case BROWSE_REQUEST: //Don't really care about the browse request- for future use maybe
		break;
	}

	//set the (maybe) edited packet payload
	for (int i = 0; i < message_len; i++) {
		*(message_pointer + i) = message[i];
	}
}

bool Parser::DecryptPia() { //returns false on decryption failure
	if (message[4] >> 7 == 0) { return true; } //Packet isn't encrypted

	//Nonce business
	nonce[0] = (srcIP >> 0) & 0xFF;
	nonce[1] = (srcIP >> 8) & 0xFF;
	nonce[2] = (srcIP >> 16) & 0xFF;
	nonce[3] = (srcIP >> 24) & 0xFF;
	nonce[4] = message[5];
	for (int i = 1; i < 8; i++) {
		nonce[i+4] = message[i+8];
	}
	for (int i = 0; i < 16; i++) {
		tag[i] = message[i + 16];
	}

	data_len = message_len - 32; //remove pia header

	for (int i = 0; i < data_len; i++) {
		encrypted[i] = message[i+32];
	}

	int decrypted_len;

	//Start decryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key, nonce);
	EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, encrypted, data_len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);


	if (EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &decrypted_len) == 0) {
		//printf("Error in Decryption\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

bool Parser::EncryptPia() {
	if (message[4] >> 7 == 0) { return true; } //not encrypted to begin with

	int encrypted_len;

	//Start encryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key, nonce);
	EVP_EncryptUpdate(ctx, encrypted, &encrypted_len, decrypted, data_len);


	if (EVP_EncryptFinal_ex(ctx, encrypted + data_len, &encrypted_len) != 1) {
		printf("Error in Encryption\n");
		return false;
	}

	uint8_t new_tag[16];
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, new_tag);

	//set the authentication tag
	for (int i = 16; i < 32; i++) {
		message[i] = new_tag[i - 16];
	}

	//set the new encrypted data
	for (int i = 0; i < data_len; i++) {
		message[i + 32] = encrypted[i];
	}

	return true;
}

void Parser::ParseBrowseReply() {
	if (message_len != 1402) { return; } //Safety check; all browse reply packets are 1402 bytes long
	//Checking for a matching session id is not yet implemented, so some errors may arise when attempting to use this program in a room with more than two switches
	uint8_t session_param[32];
	for (int i = 0; i < 32; i++) {
		session_param[i] = message[1270 + i];
	}
	session_param[31] += 1;
	SetSessionKey(session_param); //This is all we care about
}

void Parser::SetSessionKey(uint8_t mod_param[]) //creates hash of the given array and sets session key to it
{
	HMAC_CTX *ctx = HMAC_CTX_new();
	unsigned int hmac_len;
	uint8_t session_key_ext[32] = {};
	HMAC_Init_ex(ctx, GAME_KEY, 16, EVP_sha256(), nullptr);

	HMAC_Update(ctx, mod_param, 32);
	HMAC_Final(ctx, session_key_ext, &hmac_len);

	for (int i = 0; i < 16; i++) {
		session_key[i] = session_key_ext[i];
	}
}

void Parser::TryInject() {
	//unused for now
}

bool Parser::FindPokemon(uint8_t message[], int message_len, int pointer) {
	bool hasPokemon = false;
	for (int i = 0; i < message_len; i++) {

		if (message[i] == magic_prefix) {
			if (message[i + 1] == magic1) {
				if (message[i + 15] == pkmn_header[0] && message[i + 16] == pkmn_header[1]) {

					InjectPokemon(message, i + 17);
					hasPokemon = true;
				}
			}
			else if (message[i + 1] == magic2) {
				if (message[i + 20] == pkmn_header[0] && message[i + 21] == pkmn_header[1]) {

					InjectPokemon(message, i + 22);
					hasPokemon = true;
				}
			}
			else if (message[i + 1] == magic3) {
				if (message[i + 22] == pkmn_header[0] && message[i + 23] == pkmn_header[1]) {

					InjectPokemon(message, i + 24);
					hasPokemon = true;
				}
			}
		}
	}
	return hasPokemon;
}

bool Parser::InjectPokemon(uint8_t message[], int pointer) {

	ifstream in("Inject.ek8", ios::out | ios::binary);
	printf("Pokemon Found! Starting Injection...\n");
	if (!in) {
		printf("\nCannot open file!");
		exit(1);
		return false;
	}

	for (int i = 0; i < ek8_len; i++) {
		in.read((char*)&inject_pkmn[i], sizeof(uint8_t));
	}

	if (srcIP_str.compare(inject_ip) != 0) { //check if message is being sent to the injection switch
		if (!does_original_exist) { //set the original traded pokemon (used for safety check)
			does_original_exist = true;
			for (int i = 0; i < ek8_len; i++) {
				original_pkmn[i] = message[pointer + i];
			}
		}

		for (int i = 0; i < ek8_len; i++) {
			if (message[pointer + i] != original_pkmn[i]) { return true; }
		}

		for (int i = 0; i < ek8_len; i++) {
			message[pointer + i] = inject_pkmn[i];
		}
		return true;
	}
	else {
		bool is_modified = true; 
		for (int i = 0; i < ek8_len; i++) {
			if (message[pointer + i] != inject_pkmn[i]) { is_modified = false; }
		}
		if (is_modified) {
			for (int i = 0; i < ek8_len; i++) {
				message[pointer + i] = original_pkmn[i];
			}
			return true;
		}
	}

	

	for (int i = 0; i < ek8_len; i++) {
		message[i + pointer] == inject_pkmn[i];
	}
	return true;
}