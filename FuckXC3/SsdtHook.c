

#include "struct.h"
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

typedef int(*LDE_DISASM)(void *p, int dw);
extern LDE_DISASM	LDE;
extern VOID KiSystemCallRet();
extern VOID ObpCreateHandle_1();
extern VOID ObpCreateHandle_2();
extern SYMBOLS_INFO SymbolsInfo;


ULONG_PTR	KiSystemCall64;
ULONG_PTR	jmp_ObpCreateHandle_1;
ULONG_PTR	jmp_ObpCreateHandle_2;

VOID change_system_call64(BOOLEAN open)
{
// 	static ori_system_call64[16] = { 0 };
// 	if (open == TRUE)
// 	{
// 		char opcode[16] = { 0x55,
// 			0x48, 0xb8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
// 			0x48, 0x87, 0x04, 0x24,
// 			0xc3 };
// 		RtlCopyMemory(ori_system_call64, (PBYTE)KiSystemCall64 + 0x280, 16);
// 		jne_KiSystemCall64 = ((ULONG_PTR)KiSystemCall64 + 0x4e0);
// 		PerfGlobalGroupMask_8 = (*(PULONG)((PUCHAR)KiSystemCall64 + 0x280 + 2) + \
// 			(ULONG_PTR)KiSystemCall64 + 0x280 + 10);
// 		*(PULONG_PTR)(opcode + 3) = (ULONG_PTR)KiSystemCallRet;
// 
// 		sale_change(((PBYTE)KiSystemCall64 + 0x280), opcode, 16);
// 	}
// 	else
// 	{
// 		sale_change(((PBYTE)KiSystemCall64 + 0x280), ori_system_call64, 16);
// 	}
}


//功能:调试权限
VOID chang_VaildAccessMask(
	IN BOOLEAN open)
{
	static ULONG change_size_ObpCreateHandle1 = 0;				//ObpCreateHandle被修改了N字节
	static PUCHAR ori_head_ObpCreateHandle1 = NULL;				//ObpCreateHandle的前N字节数组
	static PVOID ori_addr_ObpCreateHandle1 = NULL;				//ObpCreateHandle的原函数

	static ULONG change_size_ObpCreateHandle2 = 0;				//ObpCreateHandle被修改了N字节
	static PUCHAR ori_head_ObpCreateHandle2 = NULL;				//ObpCreateHandle的前N字节数组
	static PVOID ori_addr_ObpCreateHandle2 = NULL;				//ObpCreateHandle的原函数

	jmp_ObpCreateHandle_1 = SymbolsInfo.ObpCreateHandle + 0x136;
	jmp_ObpCreateHandle_2 = SymbolsInfo.ObpCreateHandle + 0x1d8;

	if (open == TRUE)
	{
		ori_head_ObpCreateHandle1 = sale_hook(SymbolsInfo.ObpCreateHandle + 0x11a, (PVOID)ObpCreateHandle_1,
			&ori_addr_ObpCreateHandle1, &change_size_ObpCreateHandle1);
		ori_head_ObpCreateHandle2 = sale_hook(SymbolsInfo.ObpCreateHandle + 0x1bc, (PVOID)ObpCreateHandle_2,
			&ori_addr_ObpCreateHandle2, &change_size_ObpCreateHandle2);
		((POBJECT_TYPE_S)*(PULONG64)SymbolsInfo.DbgkDebugObjectType)->TypeInfo.ValidAccessMask = 0;
	}
	else
	{
		sale_unhook(SymbolsInfo.ObpCreateHandle + 0x11a, ori_head_ObpCreateHandle1, change_size_ObpCreateHandle1);
		sale_unhook(SymbolsInfo.ObpCreateHandle + 0x1bc, ori_head_ObpCreateHandle2, change_size_ObpCreateHandle2);
		((POBJECT_TYPE_S)*(PULONG64)SymbolsInfo.DbgkDebugObjectType)->TypeInfo.ValidAccessMask = 0x1f000f;
	}
}

//功能:调试端口移位
VOID change_debugport_offset(
	IN BOOLEAN open)
{
	DWORD changge_offset;
	DWORD old_offset = 0x1F0;
	DWORD new_offset = 0x298;

	ULONG_PTR jnz_DbgkCopyProcessDebugPort = (((SymbolsInfo.DbgkCopyProcessDebugPort + 0x44) + \
		*(PDWORD)(SymbolsInfo.DbgkCopyProcessDebugPort + 0x44 + 2) + 6) & 0xffffff00ffffffff);


	if (open == TRUE)
	{
		changge_offset = new_offset;
	}
	else
	{
		changge_offset = old_offset;
	}
	sale_change(SymbolsInfo.DbgkCopyProcessDebugPort + 0x20, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkCopyProcessDebugPort + 0x40, &changge_offset, 4);
	sale_change(jnz_DbgkCopyProcessDebugPort + 0x38 + 3, &changge_offset, 4);
	sale_change(jnz_DbgkCopyProcessDebugPort + 0x142 + 3, &changge_offset, 4);
	
	sale_change(SymbolsInfo.DbgkpSetProcessDebugObject + 0xB5, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpSetProcessDebugObject + 0xCA, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpSetProcessDebugObject + 0xF2, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpSetProcessDebugObject + 0x1EB, &changge_offset, 4);


	//	sale_change(SymbolsInfo.DbgkpMarkProcessPeb + 0x9e, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkCreateThread + 0x54, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkCreateThread + 0x68, &changge_offset, 4);

	//	sale_change(SymbolsInfo.DbgkpQueueMessage + 0x89, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpQueueMessage + 0xe6, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkMapViewOfSection + 0x44, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkUnMapViewOfSection + 0x31, &changge_offset, 4);

	sale_change(SymbolsInfo.DbgkExitThread + 0x2D, &changge_offset, 4);
	sale_change(SymbolsInfo.PspExitThread + 0x15A, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkExitProcess + 0x2A, &changge_offset, 4);
	sale_change(SymbolsInfo.PspProcessDelete + 0xE3, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkForwardException + 0x69, &changge_offset, 4);
	sale_change(SymbolsInfo.KiDispatchException + 0x23C, &changge_offset, 4);
	sale_change(SymbolsInfo.PspTerminateAllThreads + 0x13b, &changge_offset, 4);

	sale_change(SymbolsInfo.DbgkClearProcessDebugObject + 0x60, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkClearProcessDebugObject + 0x76, &changge_offset, 4);


	sale_change(SymbolsInfo.DbgkpCloseObject + 0xD9, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpCloseObject + 0x12B, &changge_offset, 4);
	sale_change(SymbolsInfo.DbgkpCloseObject + 0x122, &changge_offset, 4);
}

// 功能: 
// VOID change_windbg_hook(
// 	IN BOOLEAN open)
// {
// 	typedef struct _DispatchWindbg
// 	{
// 		UCHAR KdDebuggerEnabled_KdPollBreakIn[6];
// 		UCHAR KdDebuggerEnabled_KeUpdateRunTime[2];
// 		UCHAR KdDebuggerEnabled_KeUpdateSystemTime1[2];
// 		UCHAR KdDebuggerEnabled_KeUpdateSystemTime2[2];
// 		UCHAR KdDebuggerEnabled_KdCheckForDebugBreak[2];
// 		UCHAR KdDebuggerEnabled_NtSystemDebugControl[2];
// 		UCHAR KdDebuggerEnabled_KeEnterKernelDebugger[1];
// 		UCHAR KdDebuggerEnabled_KdSystemDebugControl[6];
// 
// 		UCHAR KdPitchDebugger_KdPollBreakIn[6];
// 		UCHAR KdPitchDebugger_KeUpdateRunTime[2];
// 		UCHAR KdPitchDebugger_KeUpdateSystemTime[2];
// 		UCHAR KdPitchDebugger_KdCheckForDebugBreak[2];
// 		UCHAR KdPitchDebugger_KdSystemDebugControl[6];
// 
// 
// 		UCHAR KdpBootedNodebug_KdSystemDebugControl[6];
// 
// 		ULONG64 KiDebugSwitchRoutine;
// 		UCHAR kdbazisValue[2];
// 
// 		UCHAR KdpSetContext[2];
// 		UCHAR KdExitDebugger[2];
// 		UCHAR KdpControlCPressed[7];
// 
// 	}DispatchWindbg;
// 
// 
// 	static DispatchWindbg WINDBG;
// 	KIRQL irql;
// 	UCHAR nop[7];
// 	const UCHAR cc = 0xcc;
// 	const ULONG zero = 0;
// 	const UCHAR eb = 0xeb;
// 	USHORT b190 = 0xb190;
// 	const ULONG one = 1;
// 	const USHORT e180 = 0xe180;
// 
// 	ULONG Data;
// 	PKUSER_SHARED_DATA shared = 0xFFFFF78000000000;
// 
// 	RtlFillMemory(nop, 7, 0x90);
// 
// 	if (open == FALSE)
// 	{
// 		//KdpBootedNodebug
// 		sale_change((SymbolsInfo.KdSystemDebugControl + 0x2e), WINDBG.KdpBootedNodebug_KdSystemDebugControl, 6);
// 
// 		//KdPitchDebugger
// 		sale_change((SymbolsInfo.KdPollBreakIn + 0xc), WINDBG.KdPitchDebugger_KdPollBreakIn, 6);
// 		sale_change((SymbolsInfo.KeUpdateRunTime + 0x138), WINDBG.KdPitchDebugger_KeUpdateRunTime, 2);
// 		sale_change((SymbolsInfo.KeUpdateSystemTime + 0x3fd), WINDBG.KdPitchDebugger_KeUpdateSystemTime, 2);
// 		sale_change((SymbolsInfo.KdCheckForDebugBreak + 0xb), WINDBG.KdPitchDebugger_KdCheckForDebugBreak, 2);
// 		sale_change((SymbolsInfo.KdSystemDebugControl + 0x3b), WINDBG.KdPitchDebugger_KdSystemDebugControl, 6);
// 
// 		//KdDebuggerEnabled
// 		sale_change((SymbolsInfo.KdPollBreakIn + 0x21), WINDBG.KdDebuggerEnabled_KdPollBreakIn, 6);
// 		sale_change((SymbolsInfo.KeUpdateSystemTime + 0x1e3), WINDBG.KdDebuggerEnabled_KeUpdateSystemTime1, 2);
// 		sale_change((SymbolsInfo.KeUpdateSystemTime + 0x382), WINDBG.KdDebuggerEnabled_KeUpdateSystemTime2, 2);
// 		sale_change((SymbolsInfo.KdCheckForDebugBreak + 0x14), WINDBG.KdDebuggerEnabled_KdCheckForDebugBreak, 2);
// 		//	sale_change((SymbolsInfo.KdSystemDebugControl + 0x48), WINDBG.KdDebuggerEnabled_KdSystemDebugControl, 6);
// 		sale_change((SymbolsInfo.KeEnterKernelDebugger + 0x1e), WINDBG.KdDebuggerEnabled_KeEnterKernelDebugger, 1);
// 
// 		//kdbazis! + 1824
// 		//fffff800`01610824 80e101          and     cl,1
// 		//-----------------------------------------------
// 		//fffff800`01610824 90              nop
// 		//fffff800`01610825 b101            mov     cl, 1
// 		sale_change((KdbazisBase + 0x1824), &e180, 2);
// 
// 		sale_change((SymbolsInfo.KdEnterDebugger + 0x13e + 6), &one, 4);
// 
// 		sale_change((SymbolsInfo.KdpGetContext + 0xcb + 6), &one, 1);
// 		sale_change((SymbolsInfo.KdpSetContext + 0x43), WINDBG.KdpSetContext, 2);
// 
// 		sale_change((SymbolsInfo.KdExitDebugger + 0x16), WINDBG.KdExitDebugger, 2);
// 		sale_change((SymbolsInfo.KdPollBreakIn - 0x2D22B), WINDBG.KdpControlCPressed, 7);
// 
// 		//mov     cs:KdEnteredDebugger, 1nome
// 		sale_change((SymbolsInfo.KdEnterDebugger + 0x13e + 6), &one, 4);
// 
// 		sale_change((SymbolsInfo.KdEnterDebugger + 0xf2), &one, 1);
// 
// 		sale_change((SymbolsInfo.KdPollBreakIn - 0x2D290 + 6), &one, 1);
// 
// 		irql = cli();
// 		*(PULONG64)SymbolsInfo.KiDebugSwitchRoutine = WINDBG.KiDebugSwitchRoutine;
// 
// 		*KdDebuggerEnabled = TRUE;
// 		*KdDebuggerNotPresent = FALSE;
// 		*KdEnteredDebugger = TRUE;
// 		shared->KdDebuggerEnabled = FALSE;
// 		*(PUCHAR)SymbolsInfo.KdPitchDebugger = FALSE;
// 		*(PUCHAR)SymbolsInfo.KdpBootedNodebug = FALSE;
// 
// 		SymbolsInfo.KdpContext->KdpDefaultRetries = 20;
// 		*(PBOOLEAN)SymbolsInfo.KdBlockEnable = FALSE;
// 		//	*(PBOOLEAN)SymbolsInfo.KdAutoEnableOnEvent = TRUE;
// 		//	*(PBOOLEAN)SymbolsInfo.KdIgnoreUmExceptions = TRUE;
// 		//	*(PBOOLEAN)SymbolsInfo.KdPreviouslyEnabled = TRUE;
// 		*(PBOOLEAN)SymbolsInfo.KdBreakAfterSymbolLoad = TRUE;
// 		*(PBOOLEAN)SymbolsInfo.KdpDebuggerStructuresInitialized = TRUE;
// 
// 		*(PBOOLEAN)SymbolsInfo.KdpPortLocked = TRUE;
// 		*(PBOOLEAN)SymbolsInfo.KdpContextSent = TRUE;
// 		*(PBOOLEAN)SymbolsInfo.KdpControlCPressed = TRUE;
// 
// 		sti(irql);
// 		return;
// 	}
// 
// 
// 	if (*KdDebuggerEnabled == FALSE)
// 	{
// 		DbgPrint("windbg 没开\n");
// 		return;
// 	}
// 
// 	// 	KdpDebuggerLockRet1 = SymbolsInfo.KdPollBreakIn + 0xbe;
// 	// 	KdpDebuggerLockRet2 = SymbolsInfo.KdPollBreakIn + 0x110;
// 	// 	KdpDebuggerLockRet3 = SymbolsInfo.KdpPortUnlock + 0x2B;
// 	// 	KdpDebuggerLockRet4 = SymbolsInfo.KdpPortLock + 0x5d;
// 	// 	KdpDebuggerLockRet5 = SymbolsInfo.KdpPortLock + 0x66;
// 	// 	KdpDebuggerLockRet6 = SymbolsInfo.KdEnterDebugger + 0xe9;
// 	// 
// 	// 	KdpDebuggerLockPoint1 = SymbolsInfo.KdPollBreakIn + 0xb5;
// 	// 	KdpDebuggerLockPoint2 = SymbolsInfo.KdPollBreakIn + 0x108;
// 	// 	KdpDebuggerLockPoint3 = SymbolsInfo.KdpPortUnlock + 0x22;
// 	// 	KdpDebuggerLockPoint4 = SymbolsInfo.KdpPortLock + 0x53;
// 	// 	KdpDebuggerLockPoint5 = SymbolsInfo.KdpPortLock + 0x5f;
// 	// 	KdpDebuggerLockPoint6 = SymbolsInfo.KdEnterDebugger + 0xdf;
// 
// 	//	KdpDebuggerLock = SymbolsInfo.KdpDebuggerLock;
// 
// 	//KdpBootedNodebug
// 	RtlCopyMemory(WINDBG.KdpBootedNodebug_KdSystemDebugControl, (SymbolsInfo.KdSystemDebugControl + 0x2e), 6);
// 
// 	//KdPitchDebugger
// 	RtlCopyMemory(WINDBG.KdPitchDebugger_KdPollBreakIn, (SymbolsInfo.KdPollBreakIn + 0xc), 6);
// 	RtlCopyMemory(WINDBG.KdPitchDebugger_KeUpdateRunTime, (SymbolsInfo.KeUpdateRunTime + 0x138), 2);
// 	RtlCopyMemory(WINDBG.KdPitchDebugger_KeUpdateSystemTime, (SymbolsInfo.KeUpdateSystemTime + 0x3fd), 2);
// 	RtlCopyMemory(WINDBG.KdPitchDebugger_KdCheckForDebugBreak, (SymbolsInfo.KdCheckForDebugBreak + 0xb), 2);
// 	RtlCopyMemory(WINDBG.KdPitchDebugger_KdSystemDebugControl, (SymbolsInfo.KdSystemDebugControl + 0x3b), 6);
// 
// 	//KdDebuggerEnabled
// 	WINDBG.KdDebuggerEnabled_KeEnterKernelDebugger[0] = *(PUCHAR)(SymbolsInfo.KeEnterKernelDebugger + 0x1e);
// 	RtlCopyMemory(WINDBG.KdDebuggerEnabled_KdPollBreakIn, (SymbolsInfo.KdPollBreakIn + 0x21), 6);
// 	RtlCopyMemory(WINDBG.KdDebuggerEnabled_KeUpdateSystemTime1, (SymbolsInfo.KeUpdateSystemTime + 0x1e3), 2);
// 	RtlCopyMemory(WINDBG.KdDebuggerEnabled_KeUpdateSystemTime2, (SymbolsInfo.KeUpdateSystemTime + 0x382), 2);
// 	RtlCopyMemory(WINDBG.KdDebuggerEnabled_KdCheckForDebugBreak, (SymbolsInfo.KdCheckForDebugBreak + 0x14), 2);
// 	RtlCopyMemory(WINDBG.KdDebuggerEnabled_KdSystemDebugControl, (SymbolsInfo.KdSystemDebugControl + 0x48), 6);
// 
// 	RtlCopyMemory(WINDBG.KdpSetContext, (SymbolsInfo.KdpSetContext + 0x43), 2);
// 	RtlCopyMemory(WINDBG.KdExitDebugger, (SymbolsInfo.KdExitDebugger + 0x16), 2);
// 	RtlCopyMemory(WINDBG.KdpControlCPressed, (SymbolsInfo.KdPollBreakIn - 0x2D22B), 7);
// 
// 	SymbolsInfo.KiDebugSwitchRoutine = \
// 		*(PULONG64)SymbolsInfo.KiDebugSwitchRoutine;
// 
// 	//KdpBootedNodebug
// 	sale_change((SymbolsInfo.KdSystemDebugControl + 0x2e), nop, 6);
// 
// 	//KdPitchDebugger
// 	sale_change((SymbolsInfo.KdPollBreakIn + 0xc), nop, 6);
// 	sale_change((SymbolsInfo.KeUpdateRunTime + 0x138), nop, 2);
// 	sale_change((SymbolsInfo.KeUpdateSystemTime + 0x3fd), nop, 2);
// 	sale_change((SymbolsInfo.KdCheckForDebugBreak + 0xb), nop, 2);
// 	sale_change((SymbolsInfo.KdSystemDebugControl + 0x3b), nop, 6);
// 
// 	//KdDebuggerEnabled
// 	sale_change((SymbolsInfo.KeEnterKernelDebugger + 0x1e), &eb, 1);
// 	sale_change((SymbolsInfo.KdPollBreakIn + 0x21), nop, 6);
// 	sale_change((SymbolsInfo.KeUpdateSystemTime + 0x1e3), nop, 2);
// 	sale_change((SymbolsInfo.KeUpdateSystemTime + 0x382), nop, 2);
// 	sale_change((SymbolsInfo.KdCheckForDebugBreak + 0x14), nop, 2);
// 	//	sale_change((SymbolsInfo.KdSystemDebugControl + 0x48), nop, 6);
// 
// 	//	RtlFillMemory((SymbolsInfo.NtSystemDebugControl + 0x1a3), 2, 0x90);
// 	//	RtlCopyMemory(WINDBG.KdDebuggerEnabled_NtSystemDebugControl, (SymbolsInfo.NtSystemDebugControl + 0x1a3), 2);
// 
// 	//kdbazis! + 1824
// 	//fffff800`01610824 80e101          and     cl,1
// 	//-----------------------------------------------
// 	//fffff800`01610824 90              nop
// 	//fffff800`01610825 b101            mov     cl, 1
// 	sale_change((KdbazisBase + 0x1824), &b190, 2);
// 
// 	//mov     cs:KdEnteredDebugger, 1nome
// 	sale_change((SymbolsInfo.KdEnterDebugger + 0x13e + 6), &zero, 4);
// 
// 
// 	sale_change((SymbolsInfo.KdpSetContext + 0x43), nop, 2);
// 	//mov     byte ptr[nt!KdpContextSent(fffff800`01a8ab04)], 1
// 	sale_change((SymbolsInfo.KdpGetContext + 0xcb + 6), &zero, 1);
// 
// 
// 	sale_change((SymbolsInfo.KdExitDebugger + 0x16), nop, 2);
// 	sale_change((SymbolsInfo.KdPollBreakIn - 0x2D22B), nop, 7);
// 	sale_change((SymbolsInfo.KdPollBreakIn - 0x2D290 + 6), &zero, 1);
// 
// 	//mov     bl, 1
// 	sale_change((SymbolsInfo.KdEnterDebugger + 0xf2), &zero, 1);
// 
// 	irql = cli();
// 
// 	*KdDebuggerEnabled = FALSE;
// 	*KdDebuggerNotPresent = TRUE;
// 	*KdEnteredDebugger = FALSE;
// 	shared->KdDebuggerEnabled = FALSE;
// 	*(PUCHAR)SymbolsInfo.KdPitchDebugger = TRUE;
// 	*(PUCHAR)SymbolsInfo.KdpBootedNodebug = TRUE;
// 
// 	SymbolsInfo.KdpContext->KdpDefaultRetries = 0;
// 	*(PBOOLEAN)SymbolsInfo.KdBlockEnable = TRUE;
// 	*(PULONG64)SymbolsInfo.KiDebugSwitchRoutine = NULL;
// 	*(PBOOLEAN)SymbolsInfo.KdAutoEnableOnEvent = FALSE;
// 	*(PBOOLEAN)SymbolsInfo.KdIgnoreUmExceptions = FALSE;
// 	*(PBOOLEAN)SymbolsInfo.KdPreviouslyEnabled = FALSE;
// 	*(PBOOLEAN)SymbolsInfo.KdBreakAfterSymbolLoad = FALSE;
// 	*(PBOOLEAN)SymbolsInfo.KdpDebuggerStructuresInitialized = FALSE;
// 
// 	*(PBOOLEAN)SymbolsInfo.KdpPortLocked = 0;
// 	*(PBOOLEAN)SymbolsInfo.KdpContextSent = 0;
// 	*(PBOOLEAN)SymbolsInfo.KdpControlCPressed = 0;
// 	*(PULONG64)SymbolsInfo.KiDebugRoutine = SymbolsInfo.KdpStub;
// 	sti(irql);
// 
// }





//功能: 去除进.线程、模块回调
VOID change_disable_callback(
	IN BOOLEAN open)
{
	WORD nop = 0x9090;
	WORD callrax = 0xd0ff;
	if (open == TRUE)
	{
		//Process
		sale_change(SymbolsInfo.PspInsertThread + 0x618, &nop, 2);
		sale_change(SymbolsInfo.PspExitProcess + 0x154, &nop, 2);

		//LoadImage
		sale_change(SymbolsInfo.PsCallImageNotifyRoutines + 0xda, &nop, 2);

		//Thread
		sale_change(SymbolsInfo.PspInsertThread - 0x33051, &nop, 2);
		sale_change(SymbolsInfo.PspInsertThread - 0x33051 - 0x7d3, &nop, 2);
	}
	else
	{
		//Process
		sale_change(SymbolsInfo.PspInsertThread + 0x618, &callrax, 2);
		sale_change(SymbolsInfo.PspExitProcess + 0x154, &callrax, 2);

		//LoadImage
		sale_change(SymbolsInfo.PsCallImageNotifyRoutines + 0xda, &callrax, 2);

		//Thread
		sale_change(SymbolsInfo.PspInsertThread - 0x33051, &callrax, 2);
		sale_change(SymbolsInfo.PspInsertThread - 0x33051 - 0x7d3, &callrax, 2);
	}

}

//功能: 接管KiSystemCall64
ULONG_PTR FASTCALL change_system_fun(ULONG_PTR Rip)
{
	ULONG_PTR NewRip = Rip;
	return NewRip;
}


//功能: 补丁长度 //传入: 地址，所需的最小长度
ULONG GetPatchSize(
	IN PBYTE Address, 
	IN ULONG MinLen)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount < MinLen)        //<=原来这里是小于等于，现在改为小于
	{
		Len = LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}


//功能: 补丁长度 //传入: 地址，所需的最小长度
ULONG GetPatchSize2(
	IN PBYTE Address)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount <= 14)        //至少需要14字节
	{
		Len = LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}


//传入: hook地址，接管地址，原始数据地址，补丁长度；返回：原来头N字节的数据
PVOID sale_hook(
	IN PVOID hook_addr,
	IN PVOID Proxy_ApiAddress,
	OUT PVOID *Original_ApiAddress, 
	OUT PDWORD PatchSize)
{

	KIRQL irql;
	UINT64 tmpv;
	PVOID Msct;
	PMDL MdlForFunc;
	PVOID head_n_byte, ori_func;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmp_code_orifunc[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	//How many bytes shoule be patch
	*PatchSize = GetPatchSize2((PUCHAR)hook_addr);
	//step 1: Read current data
	head_n_byte = kmalloc(*PatchSize);
	irql = cli();
	memcpy(head_n_byte, hook_addr, *PatchSize);
	sti(irql);
	//step 2: Create ori function
	ori_func = kmalloc(*PatchSize + 14);        //原始机器码+跳转机器码
	RtlFillMemory(ori_func, *PatchSize + 14, 0x90);
	tmpv = (ULONG64)hook_addr + *PatchSize;        //跳转到没被打补丁的那个字节
	memcpy(jmp_code_orifunc + 6, &tmpv, 8);
	memcpy((PUCHAR)ori_func, head_n_byte, *PatchSize);
	memcpy((PUCHAR)ori_func + *PatchSize, jmp_code_orifunc, 14);
	*Original_ApiAddress = ori_func;
	//step 3: fill jmp code
	tmpv = (UINT64)Proxy_ApiAddress;
	memcpy(jmp_code + 6, &tmpv, 8);

	MdlForFunc = MmCreateMdl(NULL, hook_addr, *PatchSize);

	if (MdlForFunc)
	{
		MmBuildMdlForNonPagedPool(MdlForFunc);
		MdlForFunc->MdlFlags = MdlForFunc->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
		__try
		{
			MmProbeAndLockPages(MdlForFunc, KernelMode, IoWriteAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			kfree(ori_func);
			IoFreeMdl(MdlForFunc);
			return NULL;
		}
		Msct = MmMapLockedPagesSpecifyCache(MdlForFunc, KernelMode, MmWriteCombined, NULL, FALSE, 0);
		irql = KeRaiseIrqlToDpcLevel();

		RtlFillMemory(Msct, *PatchSize, 0x90);
		RtlCopyMemory(Msct, jmp_code, 14);

		KeLowerIrql(irql);
		MmUnmapLockedPages(Msct, MdlForFunc);
		MmUnlockPages(MdlForFunc);
		IoFreeMdl(MdlForFunc);
	}

	return head_n_byte;
}


//传入:hook地址，原始数据，补丁长度
VOID sale_unhook(
	IN PVOID ApiAddress, 
	IN PVOID OriCode, 
	IN ULONG PatchSize)
{
	PMDL MdlForFunc;
	PVOID Msct;
	KIRQL f_oldirql;
	if (OriCode == NULL)
	{
		return;
	}
	MdlForFunc = MmCreateMdl(NULL, ApiAddress, PatchSize);
	if (MdlForFunc)
	{
		MmBuildMdlForNonPagedPool(MdlForFunc);
		MdlForFunc->MdlFlags = MdlForFunc->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
		__try
		{
			MmProbeAndLockPages(MdlForFunc, KernelMode, IoWriteAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(MdlForFunc);
			kfree(OriCode);
			return;
		}
		Msct = MmMapLockedPagesSpecifyCache(MdlForFunc, KernelMode, MmWriteCombined, NULL, FALSE, 0);
		f_oldirql = KeRaiseIrqlToDpcLevel();

		RtlCopyMemory(Msct, OriCode, PatchSize);

		KeLowerIrql(f_oldirql);
		MmUnmapLockedPages(Msct, MdlForFunc);
		MmUnlockPages(MdlForFunc);
		IoFreeMdl(MdlForFunc);
	}
	kfree(OriCode);
}

