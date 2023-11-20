#ifndef _DLP_H_
#define _DLP_H_

#include <3ds.h>

// DLP protocol/etc structures; values are in big endian.

#define DLP_IS_BIG_ENDIAN __attribute__((packed, scalar_storage_order("big-endian")))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define DLP_HTONL(x) __builtin_bswap32((x))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define DLP_HTONL(x) (x)
#else
#error Compiling for an architecture with an unsupported endianness
#endif

// Checksum seed value for DLP checksum calculation.
typedef union _DlpChecksumSeed {
	u32 dword;
	u8 bytes[sizeof(u32)];
} DlpChecksumSeed;

// DLP protocol version number.
typedef enum {
	PROTOCOL_VERSION_1_0 = 0x0100, // Original protocol version.
	PROTOCOL_VERSION_1_1 = 0x0101, // Adds DlpSpectatorInitial::updateDisabled and DlpSpectatorInitial::cver
	PROTOCOL_VERSION_CURRENT = PROTOCOL_VERSION_1_1
} DlpProtocolVersion;

// DLP packet type.
typedef enum {
	PACKET_TYPE_SPECTATOR = 1, // Spectator packet.
	PACKET_TYPE_HANDSHAKE, // Connection handshake packet.
	PACKET_TYPE_WANTED_TITLES, // Wanted titles packet.
	PACKET_TYPE_TITLE_CHUNK, // Title data chunk packet.
	PACKET_TYPE_PROGRESS, // Progress info packet.
	PACKET_TYPE_DISCONNECT, // Disconnect packet.
} DlpPacketType;

// DLP protocol data channel.
typedef enum {
	DATA_CHANNEL_SPECTATOR = 1,
	DATA_CHANNEL_MAIN = 2
} DlpDataChannel;

// DLP connection type.
typedef enum {
	CONNECTION_UNKNOWN = 0, // Unknown type (for initial packets only)
	CONNECTION_CHILD = 1, // Connected for transferring DLP child.
	CONNECTION_SYSUPDATE = 2, // Connected for transferring sysupdate.
} DlpConnectionType;

// DLP spectator packet index.
typedef enum {
	SPECTATOR_INDEX_INITIAL = 0,
	SPECTATOR_INDEX_ICON_FIRST = 1,
	SPECTATOR_INDEX_UPDATE_FIRST = 4
} DlpSpectatorIndex;

// DLP download progress status.
typedef enum {
	PROGRESS_COMPLETE = 1, // Download of this CIA chunk is complete.
	PROGRESS_RETRY, // Download of this CIA chunk is incomplete and missing packets need to be resent.
	PROGRESS_IGNORE // Client isn't interested in the CIA index for which progress was requested.
} DlpProgressStatus;

// DLP disconnect operation.
typedef enum {
	OPERATION_FINISH_UPDATE = 8, // Reboots to finish the system update, back into dlplay client and reconnects.
	OPERATION_START_CHILD = 9 // Starts the dlplay child application.
} DlpDisconnectOperation;

// Various protocol constants.
enum {
	DLP_CIA_BLOCK_SIZE = 512 * 1024, // Size of each CIA block.
	DLP_CIA_PACKET_SIZE = 1440, // Size of CIA data in each packet.
	DLP_CIA_BLOCK_PACKETS = (DLP_CIA_BLOCK_SIZE / DLP_CIA_PACKET_SIZE) + ((DLP_CIA_BLOCK_SIZE % DLP_CIA_PACKET_SIZE) != 0), // Number of packets in each CIA block.
	DLP_MAXNODES = UDS_MAXNODES - 1, // Maximum player count (1 player slot is used up by the spectator channel)
	DLP_SEND_RETRIES = 4, // Times to retry sending a packet if the uds error was the nonfatal one.
	DLP_TIME_TO_WAIT_FOR_RESPONSE = 200, // Time in milliseconds to wait for a response before resending a request.
};

// DLP protocol variant of the CVer version.bin (major,minor,build elements are in the opposite endianness)
typedef struct _DlpCVer {
	u8 major;
	u8 minor;
	u8 build;
	u8 unused_3;
	char region;
	u8 unused_5[3];
} DlpCVer;

// DLP system update title.
typedef struct DLP_IS_BIG_ENDIAN _DlpUpdateTitle {
	u64 titleId; // TitleID of title to update.
	u16 titleVersion; // Title version of title to update.
	u16 unused_A;
	u32 size; // File size of title. (cia?)
} DlpUpdateTitle;

// Packet header, DLP packets start with this.
typedef struct DLP_IS_BIG_ENDIAN _DlpPacketHeader {
	u8 type; // DlpPacketType
	u8 unused_1[3];
	u16 length;
	u16 protocolVersion; // DlpProtocolVersion
	u32 checksum;
} DlpPacketHeader;

// Spectator header, DLP spectator packets start with this.
typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorHeader {
	DlpPacketHeader header;
	u8 index; // index of packet, see DlpSpectatorIndex for the important indices
	u8 count; // Total number of spectator packets.
	bool afterSystemUpdate; // Set to true if we're doing a firmlaunch/etc back into dlplay after updating the system through dlp.
	u8 reserved_F;
} DlpSpectatorHeader;

// Body of initial spectator packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorInitial {
	u64 titleId; // TitleID of DLP child.
	u16 titleVersion; // Title version of DLP child.
	bool allow3d; // Original DLP sets this from SMDH flags bit 2: "Allow use of 3D? (For use with parental Controls. An application can use the 3D affect, even when this flag isn't set)"
	u8 region; // CFG_Region
	size_t chunkSize; // Size of chunks to transfer when sending a CIA
	u8 maxPlayerCount; // Maximum number of players able to join the dlplay
	u8 cverVariation; // The Variation value from the CVer titleID, should always be 2 for NATIVE_FIRM
	u16 cverTitleVersion; // Title version of CVer
	bool updateDisabled; // if true, updating system by dlp is disabled. Added in protocol version 0x0101
	u8 unused_14[3];
	u8 smdh_rating[0x10]; // Region specific game ratings from SMDH
	u32 ciaTransferSize; // return value of AM:GetTransferSizeFromCia
	u32 ciaImportSize; // titleInfo->size from AM:GetProgramInfoFromCia
	u16 shortDescription[0x40]; // short name from SMDH
	u16 longDescription[0x80]; // long name from SMDH
	u16 icon[0x9c]; // First part of icon data from SMDH
	DlpCVer cver; // CVer with first 3 bytes endianness swapped. Added in protocol version 0x0101
} DlpSpectatorInitial;

// Body of additional icon-data spectator packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorIcon {
	u16 icon[0x2cc]; // Additional part of icon data from SMDH
} DlpSpectatorIcon;

// Body of system update spectator packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorSystemUpdate {
	u16 titlesTotal; // Total number of titles in the system update.
	u16 titlesCount; // Number of titles in this spectator packet.
	u16 titlesIndex; // Index into the array of title data to write to.
	u16 unused_6;
	DlpUpdateTitle titles[90]; // Title list.
} DlpSpectatorSystemUpdate;

// Spectator packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpSpectatorPacket {
	DlpSpectatorHeader header;
	union DLP_IS_BIG_ENDIAN {
		DlpSpectatorInitial initial;
		DlpSpectatorIcon icon;
		DlpSpectatorSystemUpdate update;
	};
} DlpSpectatorPacket;

// Header of main packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainHeader {
	DlpPacketHeader header;
	bool serverToClient; // true when sending a packet from server to client; false otherwise; client cannot send a request packet to the server, only a response packet.
	u8 seq; // Sequence number, starts at 0 and server increments before sending the next packet; client's response must have identical sequence number
	u16 nonce; // Set initially to zero, use the value from the handshake response when that's obtained.
	u8 connectionType; // DlpConnectionType
	u8 unused_11[3];
} DlpMainHeader;

// Body of connection handshake response packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainHandshakeResponse {
	bool isFake; // true if fake client (for testing), false if "real" dlp application
	u8 unused_1;
	u16 nonce; // New nonce to use in future packets.
} DlpMainHandshakeResponse;

// Body of wanted titles response packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainWantedTitlesResponse {
	u16 length; // Size in bytes of bit-field.
	u8 unused_2[2];
	u8 bitfield[32]; // Bitfield of 32 * 8 bits; each bit refers to an index in the title list (for a connection of type child only bit 0 is valid); if a bit is set the client wants that title.
} DlpMainWantedTitlesResponse;

// Body of title chunk request packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainTitleChunkRequest {
	u16 titleIndex; // Index of the title whose CIA is included in this packet.
	u16 chunkIndex; // Index of the CIA chunk included in this packet.
	u16 packetOffset; // Offset (in packets) inside the chunk where the data should be written to.
	u16 length; // Length of CIA data (must be <= DLP_CIA_PACKET_SIZE)
	u8 data[DLP_CIA_PACKET_SIZE]; // Chunk of data from CIA (at file offset (chunkIndex*sizeof(chunk))+(packetOffset*sizeof(data)))
} DlpMainTitleChunkRequest;

// Body of progress request.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainProgressRequest {
	u16 titleIndex; // Index of the title to get progress of
	u16 chunkIndex; // Index of the CIA chunk to get progress of
} DlpMainProgressRequest;

// Body of progress response.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainProgressResponse {
	u8 status; // DlpProgressStatus
	bool notComplete; // if true, download is not fully complete. false only makes sense when status == PROGRESS_COMPLETE
	u16 titleIndex; // Index of the title which should be transferred next
	u16 chunkIndex; // Index of the CIA chunk which should be transferred next
	u16 length; // Size in bytes of bit-field.
	u8 bitfield[48]; // Bitfield of 48 * 8 bits; each bit refers to an index of a packet, if set then that packet needs to be transferred.
} DlpMainProgressResponse;

// Body of disconnect request.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainDisconnectRequest {
	u8 udsPsk[9]; // UDS PSK to be sent to the dlp child.
	u8 operation; // DlpDisconnectOperation
	u8 unused_A[2];
} DlpMainDisconnectRequest;

// Body of disconnect response
typedef struct DLP_IS_BIG_ENDIAN _DlpMainDisconnectResponse {
	u8 operation; // DlpDisconnectOperation
	u8 unused_1[3];
} DlpMainDisconnectResponse;

// Main packet.
typedef struct DLP_IS_BIG_ENDIAN _DlpMainPacket {
	DlpMainHeader header;
	union DLP_IS_BIG_ENDIAN {
		DlpMainHandshakeResponse handshake;
		DlpMainWantedTitlesResponse wantedTitles;
		DlpMainTitleChunkRequest titleChunk;
		DlpMainProgressRequest progressRequest;
		DlpMainProgressResponse progressResponse;
		DlpMainDisconnectRequest disconnectRequest;
		DlpMainDisconnectResponse disconnectResponse;
	};
} DlpMainPacket;

typedef union DLP_IS_BIG_ENDIAN _DlpMainPacketBuffer {
	u8 data[UDS_DATAFRAME_MAXSIZE];
	DlpMainPacket packet;
} DlpMainPacketBuffer;

#endif