/*
WIN64驱动开发模板
作者：Tesla.Angela
*/


#include "init.h"
#include "struct.h"
#include "LDE64x6412.h"

#include "fltKernel.h" 


PVOID	g_start_obfile = NULL;
PVOID	g_start_obprocess = NULL;
BOOLEAN g_start_hook = FALSE;
BOOLEAN g_start_windbg = FALSE;
BOOLEAN g_delete_driver = FALSE;
BOOLEAN g_start_file = FALSE;
BOOLEAN g_start_process = FALSE;
BOOLEAN g_disable_callback = FALSE;
BOOLEAN g_thread_callback = FALSE;


NTSTATUS g_start_cmst;
LARGE_INTEGER g_start_cmhandle;


PBYTE	KiSuspendThread = NULL;


ULONG_PTR	SelfdriverBase = 0;
ULONG_PTR	Selfdriverlimit = 0;
PEPROCESS	CsrssProcess = NULL;
PEPROCESS	SystemProcess = NULL;
PEPROCESS	win32k_Process = NULL;
PDRIVER_OBJECT Selfdriverobject = NULL;


extern ULONG_PTR ParseFile;

typedef int(*LDE_DISASM)(void *, int);
LDE_DISASM		LDE;
SYMBOLS_INFO	SymbolsInfo = { 0 };



#define	DEVICE_NAME			L"\\Device\\FacKProtects"
#define LINK_NAME			L"\\DosDevices\\FacKProtects"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\FacKProtects"


//功能:关中断,调升IRQL
KIRQL cli()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

//功能:开中断,回复IRQL
void sti(
	IN KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

//功能:初始化反汇编引擎
void LDE_init()
{
	LDE = ExAllocatePool(NonPagedPool, 12800);
	memcpy(LDE, szShellCode, 12800);
}

//功能:初始化导出函数
VOID InitFunName()
{
	ObCheckObjectAccess = GetProcAddress(L"ObCheckObjectAccess");
}

//功能:初始化符号函数
VOID InitSymbolsAddr(
	IN PSYMBOLS_INFO InBuffer)
{
	QNtClose = read_ssdt_funaddr(12);
	NtContinue = read_ssdt_funaddr(64);
	QNtCreateFile = read_ssdt_funaddr(82);
	QNtQueryObject = read_ssdt_funaddr(13);
	NtQueryValueKey = read_ssdt_funaddr(20);
	NtQueueApcThread = read_ssdt_funaddr(66);
	NtYieldExecution = read_ssdt_funaddr(67);
	NtSuspendProcess = read_ssdt_funaddr(378);
	NtCreateThreadEx = read_ssdt_funaddr(165);
	NtQuerySystemTime = read_ssdt_funaddr(87);
	NtSetDebugFilterState = read_ssdt_funaddr(337);
	NtQueryPerformanceCounter = read_ssdt_funaddr(46);
}


VOID DriverUnload(
	IN PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;
	LARGE_INTEGER liInterval;

	g_delete_driver = TRUE;

	liInterval.QuadPart = -10 * 1000 * 1000 * 2; ////延迟5秒钟运行  ;
	KeDelayExecutionThread(KernelMode, TRUE, &liInterval);

	if (g_start_hook)
	{
		change_ssdt_hook(FALSE);
		change_shadow_service(FALSE);
	
		chang_VaildAccessMask(FALSE);
		change_anitanit_debug(FALSE);
		change_debugport_offset(FALSE);
	}

	if (g_disable_callback)
	{
		change_disable_callback(FALSE);

	}	

	if (g_start_file)
	{
		ObUnRegisterCallbacks(g_start_obfile);
	}

	if (g_start_process)
	{
		ObUnRegisterCallbacks(g_start_obprocess);
	}

	if (NT_SUCCESS(g_start_cmst))
	{
		CmUnRegisterCallback(g_start_cmhandle);
	}



	UnLoadDisablePatchGuard();
	ExFreePool(LDE);

	DbgPrint("[KrnlHW64]DriverUnload\n");

	//删除符号连接和设备
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
}


NTSTATUS DispatchCreate(
	IN PDEVICE_OBJECT pDevObj, 
	IN PIRP pIrp)
{
	DbgPrint("[KrnlHW64]DispatchCreate\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(
	IN PDEVICE_OBJECT pDevObj, 
	IN PIRP pIrp)
{
	DbgPrint("[KrnlHW64]DispatchClose\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchIoctl(
	IN PDEVICE_OBJECT pDevObj, 
	IN PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;

	ULONG InSize;
	ULONG OutSize;
	HANDLE Handle;
	ULONG ControlCode;
	PSYMBOLS_INFO InBuffer;
	PIO_STACK_LOCATION Irpstack = IoGetCurrentIrpStackLocation(pIrp);
	InBuffer = pIrp->AssociatedIrp.SystemBuffer;
	ControlCode = Irpstack->Parameters.DeviceIoControl.IoControlCode;
	InSize = Irpstack->Parameters.DeviceIoControl.InputBufferLength;
	OutSize = Irpstack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (ControlCode)
	{
	case IOCTL_SymbolsInfo:
		if (g_start_hook) break;
		//DbgBreakPoint();
		__try
		{
			InitDisablePatchGuard();
			SymbolsInfo = *InBuffer;
			
			change_shadow_service(TRUE);
			InitSymbolsAddr(InBuffer);
			change_ssdt_hook(TRUE);
						chang_VaildAccessMask(TRUE);
			change_anitanit_debug(TRUE);
			change_debugport_offset(TRUE);
			
			g_start_hook = TRUE;

 			PsCreateSystemThread(
 				&Handle,
 				THREAD_ALL_ACCESS,
 				NULL,
 				NULL,
 				NULL,
 				(PKSTART_ROUTINE)ProcessBreakChain,
 				NULL);

			DbgPrint("Come on efforts\n");
		}
		__except (1)
		{
			Status = STATUS_UNSUCCESSFUL;
		}
		break;

	
	case IOCTL_CallBack :
		if (!g_start_hook) break;
		__try
		{
			
			if (!g_disable_callback)
			{
				change_disable_callback(g_disable_callback = TRUE);
			}
			else
			{
				change_disable_callback(g_disable_callback = FALSE);
			}
		}
		__except (1)
		{
			Status = STATUS_UNSUCCESSFUL;
		}
		break;

	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
	}

	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = OutSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}



NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObj, 
	IN PUNICODE_STRING pRegistryString)
{
	PVOID nt_imagebase;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;

	Selfdriverobject = pDriverObj;
	
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);

	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	DbgPrint("[KrnlHW64]DriverEntry\n");

	SelfdriverBase = pDriverObj->DriverStart;
	Selfdriverlimit = pDriverObj->DriverSize;

	LDE_init();
	InitFunName();
	BypassCheckSign(pDriverObj);
	nt_imagebase = GetDirverBase("ntdll.dll");

	ZwReadVirtualMemory = GetNtKrnlFuncAddress(nt_imagebase, TRUE, "ZwReadVirtualMemory");
	ZwWriteVirtualMemory = GetNtKrnlFuncAddress(nt_imagebase, TRUE, "ZwWriteVirtualMemory");
	ZwProtectVirtualMemory = GetNtKrnlFuncAddress(nt_imagebase, TRUE, "ZwProtectVirtualMemory");
	ZwQueryInformationProcess = GetNtKrnlFuncAddress(nt_imagebase, TRUE, "ZwQueryInformationProcess");
	

	//HideDriver("kdbazis.dll", pDriverObj);
	SystemProcess = PsGetCurrentProcess();
	PsLookupProcessByProcessName("csrss.exe", &CsrssProcess);
	PsLookupProcessByProcessName("explorer.exe", &win32k_Process);

	KiSuspendThread = ExAllocatePool(NonPagedPoolMustSucceed, sizeof(BYTE));
	*KiSuspendThread = 0xc3;
	
	g_start_file = RegisterFileCallBack();
	g_start_process = RegisterProcessCallBack();
	g_start_cmst = CmRegisterCallback(RegistryCallBack, NULL, &g_start_cmhandle);

	
	if (NT_SUCCESS(status))
	{
		g_thread_callback = TRUE;
	}

	return STATUS_SUCCESS;
}



