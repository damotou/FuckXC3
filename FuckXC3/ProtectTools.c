
#include "struct.h"

#define debug_pott_offset	0x298
//#define debug_pott_offset	0x1f0








DWORD	changge_size_NtClose = 0;									//NtClose被修改了N字节
PUCHAR	ori_head_NtClose = NULL;									//NtClose的前N字节数组
PVOID	ori_addr_NtClose = NULL;									//NtClose的原函数

DWORD	changge_size_NtContinue = 0;								//NtContinue被修改了N字节
PUCHAR	ori_head_NtContinue = NULL;									//NtContinue的前N字节数组
PVOID	ori_addr_NtContinue = NULL;									//NtContinue的原函数

DWORD	changge_size_NtQueryObject = 0;								//NtQueryObject被修改了N字节
PUCHAR	ori_head_NtQueryObject = NULL;								//NtQueryObject的前N字节数组
PVOID	ori_addr_NtQueryObject = NULL;								//NtQueryObject的原函数

DWORD	changge_size_NtOpenProcess = 0;								//NtOpenProcess被修改了N字节
PUCHAR	ori_head_NtOpenProcess = NULL;								//NtOpenProcess的前N字节数组
PVOID	ori_addr_NtOpenProcess = NULL;								//NtOpenProcess的原函数

DWORD	changge_size_NtQuerySystemTime = 0;							//NtQuerySystemTime被修改了N字节
PBYTE	ori_head_NtQuerySystemTime = NULL;							//NtQuerySystemTime的前N字节数组
PVOID	ori_addr_NtQuerySystemTime = NULL;							//NtQuerySystemTime的原函数

DWORD	changge_size_NtCreateFile = 0;								//NtCreateFile被修改了N字节
PBYTE	ori_head_NtCreateFile = NULL;								//NtCreateFile的前N字节数组
PVOID	ori_addr_NtCreateFile = NULL;								//NtCreateFile的原函数


DWORD	changge_size_NtYieldExecution = 0;							//NtYieldExecution被修改了N字节
PBYTE	ori_head_NtYieldExecution = NULL;							//NtYieldExecution的前N字节数组
PVOID	ori_addr_NtYieldExecution = NULL;							//NtYieldExecution的原函数

DWORD	changge_size_NtQueueApcThread = 0;							//NtQueueApcThread被修改了N字节
PBYTE	ori_head_NtQueueApcThread = NULL;							//NtQueueApcThread的前N字节数组
PVOID	ori_addr_NtQueueApcThread = NULL;							//NtQueueApcThread的原函数

DWORD	changge_size_NtSystemDebugControl = 0;						//NtSystemDebugControl被修改了N字节
PUCHAR	ori_head_NtSystemDebugControl = NULL;						//NtSystemDebugControl的前N字节数组
PVOID	ori_addr_NtSystemDebugControl = NULL;						//NtSystemDebugControl的原函数

DWORD	changge_size_NtOpenFile = 0;								//NtOpenFile被修改了N字节
PUCHAR	ori_head_NtOpenFile = NULL;									//NtOpenFile的前N字节数组
PVOID	ori_addr_NtOpenFile = NULL;									//NtOpenFile的原函数

DWORD	changge_size_NtCreateThreadEx = 0;							//NtCreateThreadEx被修改了N字节
PBYTE	ori_head_NtCreateThreadEx = NULL;							//NtCreateThreadEx的前N字节数组
PVOID	ori_addr_NtCreateThreadEx = NULL;							//NtCreateThreadEx的原函数

DWORD	changge_size_NtQueryDirectoryFile = 0;						//NtCreateThreadEx被修改了N字节
PBYTE	ori_head_NtQueryDirectoryFile = NULL;						//NtCreateThreadEx的前N字节数组
PVOID	ori_addr_NtQueryDirectoryFile = NULL;						//NtCreateThreadEx的原函数

DWORD	changge_size_NtSetDebugFilterState = 0;						//NtSetDebugFilterState被修改了N字节
PBYTE	ori_head_NtSetDebugFilterState = NULL;						//NtSetDebugFilterState的前N字节数组
PVOID	ori_addr_NtSetDebugFilterState = NULL;						//NtSetDebugFilterState的原函数

DWORD	changge_size_NtQuerySystemInformation = 0;					//NtQuerySystemInformation被修改了N字节
PBYTE	ori_head_NtQuerySystemInformation = NULL;					//NtQuerySystemInformation的前N字节数组
PVOID	ori_addr_NtQuerySystemInformation = NULL;					//NtQuerySystemInformation的原函数

DWORD	changge_size_NtQueryInformationThread = 0;					//NtQueryInformationThread被修改了N字节
PBYTE	ori_head_NtQueryInformationThread = NULL;					//NtQueryInformationThread的前N字节数组
PVOID	ori_addr_NtQueryInformationThread = NULL;					//NtQueryInformationThread的原函数

DWORD	changge_size_NtQueryInformationProcess = 0;					//NtQueryInformationProcess被修改了N字节
PBYTE	ori_head_NtQueryInformationProcess = NULL;					//NtQueryInformationProcess的前N字节数组
PVOID	ori_addr_NtQueryInformationProcess = NULL;					//NtQueryInformationProcess的原函数

DWORD	changge_size_NtSetInformationProcess = 0;					//NtSetInformationProcess被修改了N字节
PBYTE	ori_head_NtSetInformationProcess = NULL;					//NtSetInformationProcess的前N字节数组
PVOID	ori_addr_NtSetInformationProcess = NULL;					//NtSetInformationProcess的原函数

DWORD	changge_size_NtQueryPerformanceCounter = 0;					//NtQueryPerformanceCounter被修改了N字节
PBYTE	ori_head_NtQueryPerformanceCounter = NULL;					//NtQueryPerformanceCounter的前N字节数组
PVOID	ori_addr_NtQueryPerformanceCounter = NULL;					//NtQueryPerformanceCounter的原函数


DWORD	changge_size_NtUserGetDC = 0;								//NtUserGetDC被修改了N字节
PBYTE	ori_head_NtUserGetDC = NULL;								//NtUserGetDC的前N字节数组
PVOID	ori_addr_NtUserGetDC = NULL;								//NtUserGetDC的原函数

DWORD	changge_size_NtUserGetDCEx = 0;										//NtUserGetDCEx被修改了N字节
PBYTE	ori_head_NtUserGetDCEx = NULL;										//NtUserGetDCEx的前N字节数组
PVOID	ori_addr_NtUserGetDCEx = NULL;										//NtUserGetDCEx的原函数

DWORD	changge_size_NtUserGetWindowDC = 0;									//NtUserGetWindowDC被修改了N字节
PBYTE	ori_head_NtUserGetWindowDC = NULL;									//NtUserGetWindowDC的前N字节数组
PVOID	ori_addr_NtUserGetWindowDC = NULL;									//NtUserGetWindowDC的原函数


DWORD	changge_size_NtGdiGetPixel = 0;										//NtGdiGetPixel被修改了N字节
PBYTE	ori_head_NtGdiGetPixel = NULL;										//NtGdiGetPixel的前N字节数组
PVOID	ori_addr_NtGdiGetPixel = NULL;										//NtGdiGetPixel的原函数

DWORD	changge_size_NtUserBlockInput = 0;									//NtUserBlockInput被修改了N字节
PBYTE	ori_head_NtUserBlockInput = NULL;									//NtUserBlockInput的前N字节数组
PVOID	ori_addr_NtUserBlockInput = NULL;									//NtUserBlockInput的原函数

DWORD	changge_size_NtUserFindWindowEx = 0;								//NtUserFindWindowEx被修改了N字节
PBYTE	ori_head_NtUserFindWindowEx = NULL;									//NtUserFindWindowEx的前N字节数组
PVOID	ori_addr_NtUserFindWindowEx = NULL;									//NtUserFindWindowEx的原函数

DWORD	changge_size_NtUserBuildHwndList = 0;								//NtUserBuildHwndList被修改了N字节
PBYTE	ori_head_NtUserBuildHwndList = NULL;								//NtUserBuildHwndList的前N字节数组
PVOID	ori_addr_NtUserBuildHwndList = NULL;								//NtUserBuildHwndList的原函数

DWORD	changge_size_NtUserWindowFromPoint = 0;								//NtUserWindowFromPoint被修改了N字节
PBYTE	ori_head_NtUserWindowFromPoint = NULL;								//NtUserWindowFromPoint的前N字节数组
PVOID	ori_addr_NtUserWindowFromPoint = NULL;								//NtUserWindowFromPoint的原函数

DWORD	changge_size_NtUserGetForegroundWindow = 0;							//NtUserGetForegroundWindow被修改了N字节
PBYTE	ori_head_NtUserGetForegroundWindow = NULL;							//NtUserGetForegroundWindow的前N字节数组
PVOID	ori_addr_NtUserGetForegroundWindow = NULL;							//NtUserGetForegroundWindow的原函数

DWORD	changge_size_NtUserWindowFromPhysicalPoint = 0;						//NtUserWindowFromPhysicalPoint被修改了N字节
PBYTE	ori_head_NtUserWindowFromPhysicalPoint = NULL;						//NtUserWindowFromPhysicalPoint的前N字节数组
PVOID	ori_addr_NtUserWindowFromPhysicalPoint = NULL;						//NtUserWindowFromPhysicalPoint的原函数

#define ERROR_INVALID_WINDOW_HANDLE 1400L

#define MAX_PROTECT 21


typedef DWORD(FASTCALL *Q_NtUserCallOneParam)(DWORD, DWORD);

typedef HDC(FASTCALL *Q_NtUserGetDC)(HWND);
typedef HDC(FASTCALL *Q_NtUserGetWindowDC)(HWND);
typedef INT_PTR(FASTCALL *Q_ValidateHwnd)(HWND hwnd);
typedef DWORD(FASTCALL *Q_NtUserGetForegroundWindow)();
typedef DWORD(FASTCALL *Q_NtGdiGetPixel)(HDC, int, int);
typedef HWND(FASTCALL *Q_NtUserWindowFromPoint)(INT_PTR);
typedef HDC(FASTCALL *Q_NtUserGetDCEx)(HWND, HANDLE, ULONG);
typedef INT_PTR(FASTCALL *Q_NtUserGetClassName)(HWND, LPTSTR, int);
typedef INT_PTR(FASTCALL *Q_NtUserWindowFromPhysicalPoint)(INT_PTR);
typedef INT_PTR(FASTCALL *Q_NtUserPhysicalToLogicalPoint)(HWND, INT_PTR);
typedef NTSTATUS(FASTCALL *Q_NtUserBuildHwndList)(DWORD, DWORD, DWORD, DWORD, UINT, HWND*, DWORD*);
typedef INT_PTR(FASTCALL *Q_NtUserMessageCall)(INT_PTR, unsigned int, INT_PTR, INT_PTR, INT_PTR, int);
typedef NTSTATUS(FASTCALL *Q_NtUserFindWindowEx)(HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, ULONG);


INT_PTR		FASTCALL _ValidateHwnd(HWND hwnd);
NTSTATUS	FASTCALL _NtUserBlockInput(BOOLEAN);
DWORD		FASTCALL _NtGdiGetPixel(HDC, int, int);
DWORD		FASTCALL _NtUserGetForegroundWindow();
HWND		FASTCALL _NtUserWindowFromPoint(INT_PTR);
INT_PTR		FASTCALL _NtUserGetClassName(HWND, LPTSTR, int);
INT_PTR		FASTCALL _NtUserWindowFromPhysicalPoint(INT_PTR);
INT_PTR		FASTCALL _NtUserMessageCall(INT_PTR, UINT, INT_PTR, INT_PTR, INT_PTR, int);
NTSTATUS	FASTCALL _NtUserBuildHwndList(HDESK, HWND, ULONG, DWORD, UINT, HWND*, ULONG*);
NTSTATUS	FASTCALL _NtUserFindWindowEx(HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, ULONG);

NTSTATUS FASTCALL NtSetInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);



#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

ULONG_PTR NtUserGetDC;
ULONG_PTR NtGdiBitBlt;
ULONG_PTR ValidateHwnd;
ULONG_PTR NtGdiGetPixel;
ULONG_PTR NtUserGetDCEx;
ULONG_PTR NtGdiStretchBlt;
ULONG_PTR NtUserBlockInput;
ULONG_PTR NtUserGetWindowDC;
ULONG_PTR NtUserQueryWindow;
ULONG_PTR NtUserGetClassName;
ULONG_PTR NtUserFindWindowEx;
ULONG_PTR NtUserCallOneParam;
ULONG_PTR NtUserBuildHwndList;
ULONG_PTR NtUserWindowFromPoint;
ULONG_PTR NtUserGetForegroundWindow;
ULONG_PTR NtUserWindowFromPhysicalPoint;

#define PROCESS_COUNT 13

extern BOOLEAN		g_start_hook;
extern PEPROCESS	SystemProcess;
extern PEPROCESS	CsrssProcess;
extern PEPROCESS	win32k_Process;
extern PBYTE		KiSuspendThread;
extern PVOID		g_start_obfile;
extern PVOID		g_start_obprocess;
extern BOOLEAN		g_delete_driver;
extern ULONG_PTR	NtQueueApcThread;
extern POBJECT_TYPE* IoDeviceObjectType;
extern POBJECT_TYPE* IoDriverObjectType;
extern PDRIVER_OBJECT Selfdriverobject;
extern char AccessProcess[PROCESS_COUNT][20];
extern SAVE_DEBUG_REGISTERS ArrayDebugRegister[100]; //Max 100 threads


ULONG_PTR	QNtClose;
ULONG_PTR	QNtCreateFile;
ULONG_PTR	QNtQueryObject;
ULONG_PTR	NtQueueApcThread;
ULONG_PTR	NtSetDebugFilterState;

ULONG_PTR NtContinue = NULL;
ULONG_PTR QNtQueryObject = NULL;
ULONG_PTR NtQueryValueKey = NULL;
ULONG_PTR NtYieldExecution = NULL;
ULONG_PTR NtCreateThreadEx = NULL;
ULONG_PTR NtSuspendProcess = NULL;
ULONG_PTR NtQuerySystemTime = NULL;
ULONG_PTR ObCheckObjectAccess = NULL;
ULONG_PTR NtQueryPerformanceCounter = NULL;
PDRIVER_DISPATCH NtfsCreateDispatch = NULL;

LARGE_INTEGER NativeSysTime = { 0 };
DWORD ValueProcessBreakOnTermination = 0;
BOOLEAN IsProcessHandleTracingEnabled = FALSE;
DWORD ValueProcessDebugFlags = PROCESS_DEBUG_INHERIT;

DWORD	changge_size_ValidateHwnd = 0;								//ValidateHwnd被修改了N字节
PUCHAR	ori_head_ValidateHwnd = NULL;								//ValidateHwnd的前N字节数组
PVOID	ori_addr_ValidateHwnd = NULL;								//ValidateHwnd的原函数

DWORD changge_size_ObCheckObjectAccess = 0;							//ObCheckObjectAccess被修改了N字节
PBYTE ori_head_ObCheckObjectAccess = NULL;							//ObCheckObjectAccess的前N字节数组
PVOID ori_addr_ObCheckObjectAccess = NULL;							//ObCheckObjectAccess的原函数

DWORD changge_size_DbgkForwardException = 0;						//DbgkForwardException被修改了N字节
PBYTE ori_head_DbgkForwardException = NULL;							//DbgkForwardException的前N字节数组
PVOID ori_addr_DbgkForwardException = NULL;							//DbgkForwardException的原函数

DWORD changge_size_ObpCallPreOperationCallbacks = 0;				//ObpCallPreOperationCallbacks被修改了N字节
PBYTE ori_head_ObpCallPreOperationCallbacks = NULL;					//ObpCallPreOperationCallbacks的前N字节数组
PVOID ori_addr_ObpCallPreOperationCallbacks = NULL;					//ObpCallPreOperationCallbacks的原函数


#define ProtectTools1		"MDebug.exe"
#define ProtectTools2		"Ollydbg.exe"
#define ProtectTools3		"[LCG].exe"
#define ProtectTools4		"HawkOD.exe"
#define ProtectTools5		"FackTpProtect"
#define ProtectTools6		"apimonitor"
#define ProtectTools7		"PCHunter64.exe"
#define ProtectTools8		"windbg32.exe"	
#define ProtectTools9		"x32dbg.exe"	
#define ProtectTools10		"cheatengine"
#define ProtectTools11		"吾爱破解[LCG].exe"	
#define ProtectTools12		"5410.exe"	

#define VMwareTools1		"vmacthlp"
#define VMwareTools2		"VGAuthService"

#define PassGame1			"DNF.exe"
#define PassGame2			"GaneApp.exe"
#define PassGame3			"Client.exe"
#define PassGame4			"cstrike-online.exe"
#define PassGame5			"KartRider.exe"
#define PassGame6			"CA.exe"


#define ProtectImageName1  "smss"
#define ProtectImageName2  "explorer"
#define ProtectImageName3  "dwm.exe"


BOOLEAN ISProtectDebuger(
	IN DWORD ProcessId)
{
	BOOL bret = FALSE;
	NTSTATUS Ntstatus;
	PEPROCESS Process;
	Ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Process);//获取EPROCESS
	if (NT_SUCCESS(Ntstatus))
	{
		if ((_stricmp(PsGetProcessImageFileName(Process), ProtectTools1) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools2) == 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools3) != 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools4) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools8) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools9) == 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools10) != 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools11) == 0) ||\
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools12) == 0))
		{
			bret = TRUE;
		}
		ObDereferenceObject(Process);
	}
	return bret;
}

BOOLEAN ISProtectTools(
	IN DWORD ProcessId)
{
	BOOL bret = FALSE;
	NTSTATUS Ntstatus;
	PEPROCESS Process;
	Ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Process);//获取EPROCESS
	if (NT_SUCCESS(Ntstatus))
	{
		if ((_stricmp(PsGetProcessImageFileName(Process), ProtectTools1) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools2) == 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools3) != 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools4) == 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools5) != 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools6) != 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools7) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools8) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools9) == 0) || \
			(strstr(PsGetProcessImageFileName(Process), ProtectTools10) != 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools11) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), ProtectTools12) == 0))
		{
			bret = TRUE;
		}
		ObDereferenceObject(Process);
	}
	return bret;
}

BOOLEAN ISVMwareTools(
	IN DWORD ProcessId)
{
	BOOL bret = FALSE;
	NTSTATUS Ntstatus;
	PEPROCESS Process;
	Ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Process);//获取EPROCESS
	if (NT_SUCCESS(Ntstatus))
	{
		if ((strstr(PsGetProcessImageFileName(Process), VMwareTools1)) || \
			(strstr(PsGetProcessImageFileName(Process), VMwareTools2)))
		{
			bret = TRUE;
		}
		ObDereferenceObject(Process);
	}
	return bret;
}

BOOLEAN IsWhiteList(
	IN DWORD ProcessId)
{
	BOOL bret = FALSE;
	NTSTATUS Ntstatus;
	PEPROCESS Process;
	Ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Process);//获取EPROCESS
	if (NT_SUCCESS(Ntstatus))
	{
		if (strstr(PsGetProcessImageFileName(Process), ProtectImageName1) ||
			strstr(PsGetProcessImageFileName(Process), ProtectImageName2) ||
			(_stricmp(PsGetProcessImageFileName(Process), ProtectImageName3) == 0))
		{
			bret = TRUE;
		}
		ObDereferenceObject(Process);
	}
	return bret;
}

BOOLEAN ISAttachProcess(
	IN PEPROCESS Process)
{
	if (MmIsAddressValid(Process + debug_pott_offset) && \
		*(PULONG_PTR)((PBYTE)Process + debug_pott_offset))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN IsWindowClassBad(
	IN PUNICODE_STRING lpszClass)
{
	WCHAR nameCopy[400];
	static const WCHAR * BadWindowClassList[] =
	{
		L"OLLYDBG",
		L"Zeta Debugger",
		L"Rock Debugger",
		L"ObsidianGUI",
		L"ID", //Immunity Debugger
		L"WinDbgFrameClass", //WinDBG
		L"idawindow",
		L"tnavbox",
		L"idaview",
		L"tgrzoom"
		L"Cheat",
		L"Engine",
		L"Previous",
		L"首次扫描",
		L"再次扫描",
		L"撤销扫描",
		L"内存浏览",
		L"手动添加地址"
	};

	if (!lpszClass || lpszClass->Length == 0 || !lpszClass->Buffer)
	{
		return FALSE;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (lpszClass->Length > (sizeof(nameCopy) - sizeof(WCHAR)))
	{
		return FALSE;
	}
	memcpy(nameCopy, lpszClass->Buffer, lpszClass->Length);

	for (int i = 0; i < _countof(BadWindowClassList); i++)
	{
		if (wcsistr(nameCopy, BadWindowClassList[i]))
		{
			return TRUE;
		}
	}

	return FALSE;

}

BOOLEAN IsWindowNameBad(
	IN PUNICODE_STRING lpszWindow)
{
	WCHAR nameCopy[400];
	static const WCHAR * BadWindowTextList[] =
	{
		L"OLLYDBG",
		L"ida",
		L"disassembly",
		L"scylla",
		L"Debug",
		L"[CPU",
		L"Immunity",
		L"Windbg",
		L"x32_dbg",
		L"5410",
		L"Windbg",
		L"Import reconstructor"
		L"Cheat",
		L"Engine",
		L"Previous",
		L"首次扫描",
		L"再次扫描",
		L"撤销扫描",
		L"内存浏览",
		L"手动添加地址"
	};

	if (!lpszWindow || lpszWindow->Length == 0 || !lpszWindow->Buffer)
	{
		return FALSE;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (lpszWindow->Length > (sizeof(nameCopy) - sizeof(WCHAR)))
	{
		return FALSE;
	}
	memcpy(nameCopy, lpszWindow->Buffer, lpszWindow->Length);

	for (int i = 0; i < _countof(BadWindowTextList); i++)
	{
		if (wcsistr(nameCopy, BadWindowTextList[i]))
		{
			return TRUE;
		}
	}

	return FALSE;

}

BOOLEAN IsProcessBad(
	IN PUNICODE_STRING process)
{
	WCHAR nameCopy[400];
	static const WCHAR * BadProcessnameList[] =
	{
		L"ollydbg.exe",
		L"MDebug.exe",
		L"HawkOD.exe",
		L"idaw.exe",
		L"idaw64.exe",
		L"HawkOD.exe",
		L"PCHunter64.exe",
		L"cheatengine.exe",
		L"FackTpProtect.exe",
		L"5410.exe",
		L"x32dbg.exe",
		L"windbg.exe",
		L"吾爱破解[LCG].exe",};


	if (!process || process->Length == 0 || !process->Buffer)
	{
		return FALSE;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (process->Length > (sizeof(nameCopy) - sizeof(WCHAR)))
	{
		return FALSE;
	}

	memcpy(nameCopy, process->Buffer, process->Length);

	for (int i = 0; i < _countof(BadProcessnameList); i++)
	{
		if (!wcsistr(nameCopy, BadProcessnameList[i]))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN FASTCALL IsPassGame(
	IN DWORD ProcessId)
{
	BOOL bret = FALSE;
	NTSTATUS Ntstatus;
	PEPROCESS Process;
	Ntstatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&Process);//获取EPROCESS
	if (NT_SUCCESS(Ntstatus))
	{
		if ((_stricmp(PsGetProcessImageFileName(Process), PassGame1) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), PassGame2) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), PassGame3) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), PassGame4) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), PassGame5) == 0) || \
			(_stricmp(PsGetProcessImageFileName(Process), PassGame6) == 0))
		{
			bret = TRUE;
		}
		ObDereferenceObject(Process);
	}
	return bret;
}

void FilterProcess(
	IN PSYSTEM_PROCESS_INFORMATION pInfo)
{
	PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

	while (TRUE)
	{
		if (IsProcessBad(&pInfo->ImageName) || ISProtectTools(pInfo->ProcessId))
		{
			if (pInfo->ImageName.Buffer)
				RtlZeroMemory(pInfo->ImageName.Buffer, pInfo->ImageName.Length);

			if (pInfo->NextEntryOffset == 0) //last element
			{
				pPrev->NextEntryOffset = 0;
			}
			else
			{
				pPrev->NextEntryOffset += pInfo->NextEntryOffset;
			}
		}
		else
		{
			pPrev = pInfo;
		}

		if (pInfo->NextEntryOffset == 0)
		{
			break;
		}
		else
		{
			pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
		}
	}
}

void FilterObject(
	IN POBJECT_TYPE_INFORMATION pObject)
{
	UNICODE_STRING DebugObject;
	RtlInitUnicodeString(&DebugObject, L"DebugObject");

	if (pObject->TypeName.Length == 0 || pObject->TypeName.Buffer == 0)
	{
		return;
	}

	if (RtlEqualUnicodeString(&pObject->TypeName, &DebugObject, FALSE)) //DebugObject
	{
		pObject->TotalNumberOfObjects = 0;
		pObject->TotalNumberOfHandles = 0;
	}
}

void FilterObjects(
	IN POBJECT_TYPES_INFORMATION pObjectTypes)
{
	POBJECT_TYPE_INFORMATION pObject = pObjectTypes->TypeInformation;
	for (ULONG i = 0; i < pObjectTypes->NumberOfTypes; i++)
	{
		FilterObject(pObject);

		pObject = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
	}
}

NTSTATUS RemoveProcessFromSysProcessInfo(
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength)
{
	//
	// Check the size of the base container
	//

	PSYSTEM_PROCESS_INFORMATION moduleInfo, prevPointer, currPointer, nextPointer;
	if (SystemInformationLength < sizeof(SYSTEM_PROCESS_INFORMATION))
		return STATUS_INFO_LENGTH_MISMATCH;

	//
	// Get a pointer to the modules and loop each index
	//
	 moduleInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

	 prevPointer = NULL;
	 currPointer = NULL;
     nextPointer = NULL;

	for (;;)
	{
		//
		// Does this process match?
		//
		if (ISProtectTools(moduleInfo->ProcessId))
			currPointer = moduleInfo;

		//
		// Validate pointer
		//
		if (moduleInfo->NextEntryOffset == 0)
			break;

		ULONG_PTR nextIndex = (ULONG_PTR)moduleInfo + moduleInfo->NextEntryOffset;
		ULONG_PTR maxOffset = (ULONG_PTR)FIELD_OFFSET(SYSTEM_PROCESS_INFORMATION, ParentProcessId);
#define IS_IN_BOUNDS(var, start, size) (((ULONG_PTR)(var)) < ((ULONG_PTR)start + (size)))
		if (!IS_IN_BOUNDS(nextIndex + maxOffset, SystemInformation, SystemInformationLength))
			break;

		//
		// If this flag was set, get the next pointer in the list and exit
		//
		if (currPointer)
		{
			nextPointer = (PSYSTEM_PROCESS_INFORMATION)nextIndex;
			break;
		}

		//
		// Move to next index
		//
		prevPointer = moduleInfo;
		moduleInfo = (PSYSTEM_PROCESS_INFORMATION)nextIndex;
	}

	if (!currPointer)
		return STATUS_NOT_FOUND;

	//
	// Was there a previous pointer?
	//
	if (prevPointer)
	{
		//
		// Link it to the next, or set it to 0
		//
		if (nextPointer)
			prevPointer->NextEntryOffset = (ULONG)((ULONG_PTR)nextPointer - (ULONG_PTR)prevPointer);
		else
			prevPointer->NextEntryOffset = 0;
	}

	//
	// Calculate the size of the target entry and zero it
	//
	SIZE_T zeroLength = 0;

	if (nextPointer)
	{
		//
		// There was another entry after this, so determine
		// the delta between them
		//
		zeroLength = (ULONG_PTR)nextPointer - (ULONG_PTR)currPointer;
	}
	else
	{
		//
		// Data is from 'currPointer' to SystemInformation buffer end
		//
		zeroLength = ((ULONG_PTR)SystemInformation + SystemInformationLength) - (ULONG_PTR)currPointer;
	}

	RtlSecureZeroMemory(currPointer, zeroLength);
	return STATUS_SUCCESS;
}

DWORD HwndToProcessId(
	IN HWND hwnd)
{
	QWORD unknown = ((Q_ValidateHwnd)ori_addr_ValidateHwnd)(hwnd);
	if (!unknown)return 0;
	if (_bittest((const signed __int32 *)(unknown + 288), 0xAu))
	{
		return *(DWORD*)(unknown + 296);
	}
	else
	{
		
		return PsGetThreadProcessId(*(QWORD*)*(QWORD**)(unknown + 16));
	}
}


HWND FASTCALL _NtUserGetWindowFromDC(
	IN HDC hdc)
{
	return (HWND)(((Q_NtUserCallOneParam)NtUserCallOneParam)((ULONG)hdc, 0x03));
}


//函数检索指定坐标点的像素的RGB颜色值
DWORD FASTCALL _NtGdiGetPixel(
	IN HDC hDC,
	IN int XPos,
	IN int YPos)
{
	HWND hd;
	ULONG ProcessID;
	hd = _NtUserGetWindowFromDC(hDC);
	if (!ISProtectTools((DWORD)PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		ProcessID = HwndToProcessId(hd);
		if (ISProtectTools(ProcessID))
		{
			return 0;
		}
	}

	return ((Q_NtGdiGetPixel)ori_addr_NtGdiGetPixel)(hDC, XPos, YPos);
}

HWND FASTCALL _NtUserWindowFromPoint(
	IN INT_PTR a1)
{
	HWND hwnd;
	DWORD ProcessID;
	hwnd = ((Q_NtUserWindowFromPoint)ori_addr_NtUserWindowFromPoint)(a1);

	if (!ISProtectTools((DWORD)PsGetCurrentProcessId()) && 
		!IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		ProcessID = HwndToProcessId(hwnd);
		if (ProcessID == NULL || ISProtectTools(ProcessID))
		{
			return 0;
		}
	}
	return hwnd;
}

NTSTATUS FASTCALL _NtUserFindWindowEx(
	IN HWND a1,
	IN HWND a2,
	IN PUNICODE_STRING a3,
	IN PUNICODE_STRING a4,
	IN ULONG a5)
{

	HWND result;
	result = ((Q_NtUserFindWindowEx)ori_addr_NtUserFindWindowEx)(a1, a2, a3, a4, a5);
	if (result == NULL)
	{
		return 0;
	}

	if (IsWindowClassBad(a3) || IsWindowNameBad(a4))
	{
		return 0;
	}

	if (!ISProtectTools(PsGetCurrentProcessId()))
	{
		ULONG ProcessID = HwndToProcessId(result);
		if (ISProtectTools(ProcessID))
		{
			return 0;
		}

	}

	return result;

}


DWORD FASTCALL _NtUserGetForegroundWindow()
{	
	return 0;
}


NTSTATUS FASTCALL _NtUserBuildHwndList(
	IN HDESK hdesk,
	IN HWND hwndNext,
	IN ULONG fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT ULONG* pcHwndNeeded)
{
	NTSTATUS result;
	result = ((Q_NtUserBuildHwndList)ori_addr_NtUserBuildHwndList)(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

	if (result == STATUS_SUCCESS &&
		!ISProtectTools(PsGetCurrentProcessId()))
	{
		for (UINT i = 0; i < *pcHwndNeeded; i++)
		{
			if (phwndFirst[i] != 0)
			{
				DWORD ProcessID = HwndToProcessId((HWND)phwndFirst[i]);
				if (ISProtectTools(ProcessID) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
				{
					phwndFirst[i] += 66;
				}
			}
		}

	}

	return result;

}


INT_PTR FASTCALL _NtUserWindowFromPhysicalPoint(
	IN INT_PTR a1)
{
	HWND hd;
	ULONG processId;
	if (a1 == NULL)
	{
		return 0;

	}
	hd = ((Q_NtUserWindowFromPhysicalPoint)ori_addr_NtUserWindowFromPhysicalPoint)(a1);
	if (hd == NULL)
	{
		return 0;
	}
	if (!ISProtectTools(PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		processId = HwndToProcessId((HWND)hd);
		if (ISProtectTools(processId))
		{
			return 0;
		}
	}
	return hd;
}

HDC FASTCALL _NtUserGetDC(
	IN HWND hWnd)
{
	if (!ISProtectTools(PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		DWORD processId = HwndToProcessId(hWnd);
		if (ISProtectTools(processId))
		{
			return 0;
		}
	}
	return ((Q_NtUserGetDC)ori_addr_NtUserGetDC)(hWnd);
}

HDC FASTCALL _NtUserGetDCEx(
	IN HWND hWnd,
	IN HANDLE hRegion,
	IN ULONG Flags)
{
	if (!ISProtectTools(PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		DWORD processId = HwndToProcessId(hWnd);
		if (ISProtectTools(processId))
		{
			return 0;
		}
	}
	return ((Q_NtUserGetDCEx)ori_addr_NtUserGetDCEx)(hWnd, hRegion, Flags);
}


HDC FASTCALL _NtUserGetWindowDC(
	IN HWND hWnd)
{
	if (!ISProtectTools(PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		DWORD processId = HwndToProcessId(hWnd);
		if (ISProtectTools(processId))
		{
			return 0;
		}
	}
	return ((Q_NtUserGetWindowDC)ori_addr_NtUserGetWindowDC)(hWnd);
}


NTSTATUS FASTCALL _NtUserBlockInput(
	IN BOOLEAN fBlockIt)
{
	typedef NTSTATUS(FASTCALL *Q_NtUserBlockInput)(BOOLEAN);
	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		static BOOL isBlocked = FALSE;
		if (isBlocked == FALSE && fBlockIt != FALSE)
		{
			isBlocked = TRUE;
			return TRUE;
		}
		else if (isBlocked != FALSE && fBlockIt == FALSE)
		{
			isBlocked = FALSE;
			return TRUE;
		}
	}
	else
	{
		return ((Q_NtUserBlockInput)ori_addr_NtUserBlockInput)(fBlockIt);
	}
}

INT_PTR FASTCALL _ValidateHwnd(
	IN HWND hwnd)
{
	if (!ISProtectTools((DWORD)PsGetCurrentProcessId()) && !IsWhiteList((DWORD)PsGetCurrentProcessId()))
	{
		DWORD ProcessID = HwndToProcessId(hwnd);
		if (ISProtectTools(ProcessID))
		{
			return NULL;
		}
	}

	return ((Q_ValidateHwnd)ori_addr_ValidateHwnd)(hwnd);
}






//功能:注册进程回调
BOOLEAN RegisterProcessCallBack()
{

	typedef struct _OB_CALLBACK
	{
		LIST_ENTRY ListEntry;
		ULONG64 Unknown;
		ULONG64 ObHandle;
		ULONG64 ObjTypeAddr;
		ULONG64 PreCall;
		ULONG64 PostCall;
	} OB_CALLBACK, *POB_CALLBACK;
	NTSTATUS status = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"lalala");
	obReg.OperationRegistration = &opReg;
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&ProcessCallback;

	status = ObRegisterCallbacks(&obReg, &g_start_obprocess);
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}

//功能:进程回调处理函数
OB_PREOP_CALLBACK_STATUS ProcessCallback(
	IN PVOID RegistrationContext,
	IN POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId(pOperationInformation->Object);
	//char szProcName[16] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	//strcpy(szProcName, GetProcessNameByProcessId(pid));
	if (ISProtectTools(pid) && !ISProtectTools((DWORD)PsGetCurrentProcess()))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)//进程终止
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)//openprocess
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)//内存读
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)//内存写
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

//功能:文件回调处理函数
OB_PREOP_CALLBACK_STATUS FileCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNICODE_STRING DosName;
	PFILE_OBJECT fileo = OperationInformation->Object;
	ACCESS_MASK amask = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

	static WCHAR* protect[] =
	{ L"HawkOD",
	L"Ollydbg",
	L"x32dbg",
	L"5410",
	L"吾爱破解",
	L"PCHunter64",
	L"Cheat Engine",
	L"CE64",
	L"cheatengine" };

	if (!IsPassGame(PsGetCurrentProcessId()))
	{
		return OB_PREOP_SUCCESS;
	}
// 	for (int i = 0; i < PROCESS_COUNT; i++)
// 	{
// 		if (_stricmp(PsGetProcessImageFileName(PsGetCurrentProcess()), AccessProcess[i]) == 0) //检查信任列表
// 		{
// 			return OB_PREOP_SUCCESS;
// 		}
// 	}


	UNREFERENCED_PARAMETER(RegistrationContext);
	if (OperationInformation->ObjectType != *IoFileObjectType)
		return OB_PREOP_SUCCESS;
	if (fileo->FileName.Buffer == NULL ||
		!MmIsAddressValid(fileo->FileName.Buffer) ||
		fileo->DeviceObject == NULL ||
		!MmIsAddressValid(fileo->DeviceObject))                //过滤1：无效指针
		return OB_PREOP_SUCCESS;
	if (!_wcsicmp(fileo->FileName.Buffer, L"\\Endpoint") ||
		!_wcsicmp(fileo->FileName.Buffer, L"?") ||
		!_wcsicmp(fileo->FileName.Buffer, L"\\.\\.")
//		|| !_wcsicmp(fileo->FileName.Buffer, L"\\")
		)                        //过滤2：无效路径
		return OB_PREOP_SUCCESS;

	
	__try
	{
		RtlVolumeDeviceToDosName(fileo->DeviceObject, &DosName);

		for (int i = 0; i < _countof(protect); i++)
		{
			if (wcsistr(fileo->FileName.Buffer, protect[i]))
			{
				fileo->Size = 1;
				OperationInformation->ObjectType = *PsProcessType;
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = DELETE;
				return OB_PREOP_SUCCESS;
			}
		}

	}
	__except (1){}

	return OB_PREOP_SUCCESS;
}

//功能:注册文件回调
BOOLEAN RegisterFileCallBack()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	PLDR_DATA_TABLE_ENTRY ldr;

	// enable IoFileObjectType
	((POBJECT_TYPE_S)*IoFileObjectType)->TypeInfo.SupportsObjectCallbacks = TRUE;

	// init callbacks
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	obReg.OperationRegistration = &opReg;
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = IoFileObjectType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FileCallback;

	// register callbacks
	status = ObRegisterCallbacks(&obReg, &g_start_obfile);
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}


//功能:注册表回调处理函数
NTSTATUS RegistryCallBack(
	IN PVOID CallbackContext,
	IN  PVOID Argument1,
	IN  PVOID Argument2)
{
	BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING, PVOID);
	//定义变量
	NTSTATUS CallbackStatus = STATUS_SUCCESS;

	// 	if (_stricmp("regedit.exe", (const char*)PsGetProcessImageFileName(PsGetCurrentProcess())) != 0)
	// 		return CallbackStatus;
#define REGISTRY_POOL_TAG 'pRE'
	ULONG uRegNotifStyle;
	UNICODE_STRING registryPath;
	//static WCHAR* protectname = L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";

	static WCHAR* protectname = L"UserAssist";
	static WCHAR* protectname2 = L"Count";
	registryPath.Length = 0;
	registryPath.MaximumLength = 2048 * sizeof(WCHAR);
	registryPath.Buffer = ExAllocatePoolWithTag(NonPagedPoolMustSucceed, registryPath.MaximumLength, REGISTRY_POOL_TAG);
	RtlZeroMemory(registryPath.Buffer, registryPath.MaximumLength);
	//设置变量
	uRegNotifStyle = (ULONG)Argument1;//REG_NOTIFY_CLASS

	//操作类型
	switch (uRegNotifStyle)
	{

	case RegNtPreOpenKeyEx:
	case RegNtPreCreateKeyEx:        //即将打开的注册表项
	{
		PREG_CREATE_KEY_INFORMATION pRegCreateKeyEx = (PREG_CREATE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegCreateKeyEx->RootObject);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtPostCreateKey:
	{
		PREG_POST_CREATE_KEY_INFORMATION createKey = (PREG_POST_CREATE_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(createKey->Status))
		{
			GetRegistryObjectCompleteName(&registryPath, *(PVOID*)createKey->Object);

			if (wcsistr(registryPath.Buffer, protectname) || \
				wcsistr(registryPath.Buffer, protectname2))
			{
				CallbackStatus = STATUS_CALLBACK_BYPASS;
			}
		}
		break;
	}

	case RegNtPostOpenKey:
	{
		PREG_POST_OPEN_KEY_INFORMATION openKey = (PREG_POST_OPEN_KEY_INFORMATION)Argument2;
		if (NT_SUCCESS(openKey->Status))
		{
			GetRegistryObjectCompleteName(&registryPath, *(PVOID*)openKey->Object);

			if (wcsistr(registryPath.Buffer, protectname) || \
				wcsistr(registryPath.Buffer, protectname2))
			{
				CallbackStatus = STATUS_CALLBACK_BYPASS;
			}
		}
		break;
	}

	
	case RegNtQueryKey:                //将要查询的键
	{
		PREG_QUERY_KEY_INFORMATION pRegQueryKey = (PREG_QUERY_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegQueryKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtQueryValueKey:
	{
		PREG_QUERY_VALUE_KEY_INFORMATION queryValueKey = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, queryValueKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtEnumerateKey:                //子项被列举的关键
	{
		PREG_ENUMERATE_KEY_INFORMATION pRegEnumerateKey = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegEnumerateKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtEnumerateValueKey:
	{
		PREG_ENUMERATE_VALUE_KEY_INFORMATION enumerateValueKey = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, enumerateValueKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtPreSetValueKey:             //注册表项的值输入一个新的设置
	{
		PREG_SET_VALUE_KEY_INFORMATION pRegSetValueKeyInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegSetValueKeyInfo->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtPreDeleteValueKey:        //注册表项的值被删除
	{
		PREG_DELETE_VALUE_KEY_INFORMATION pRegDeleteValueKey = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegDeleteValueKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	case RegNtPreDeleteKey:                        //注册表项被删除
	{
		PREG_DELETE_KEY_INFORMATION pRegDeleteKey = (PREG_DELETE_KEY_INFORMATION)Argument2;
		GetRegistryObjectCompleteName(&registryPath, pRegDeleteKey->Object);

		if (wcsistr(registryPath.Buffer, protectname) || \
			wcsistr(registryPath.Buffer, protectname2))
		{
			CallbackStatus = STATUS_CALLBACK_BYPASS;
		}
		break;
	}

	default:
		break;
	}

	ExFreePoolWithTag(registryPath.Buffer, REGISTRY_POOL_TAG);
	return CallbackStatus;
}





//功能:保护进程短链
VOID ProcessBreakChain()
{
	KIRQL irql;
	int i = 0;
	PLIST_ENTRY entry;
	LARGE_INTEGER liInterval;
	PEPROCESS_S SystemProcess;


	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);
	if (!NT_SUCCESS(Status))
	{
		SystemProcess = PsGetCurrentProcess();
	}
	else
	{
		ObfDereferenceObject(SystemProcess);
	}

	while (1)
	{
		if (g_delete_driver == TRUE)
			break;

		for (entry = SystemProcess->ActiveProcessLinks.Flink; entry != &entry; entry = entry->Flink)
		{
			if (g_delete_driver == TRUE)
				break;
			PEPROCESS_S  Process = (PEPROCESS_S)((PBYTE)entry - 0x188);
			if (ISProtectTools(PsGetProcessId(Process)) || ISVMwareTools(PsGetProcessId(Process)))
			{
				__try
				{
					irql = cli();
					RemoveEntryList(entry);
					sti(irql);
				}
				__except (1){}
			}
		}

		if (g_delete_driver == TRUE)
			break;

		liInterval.QuadPart = -10 * 1000 * 1000 * 2; ////延迟2秒钟运行  ;
		KeDelayExecutionThread(KernelMode, TRUE, &liInterval);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}


//功能:过滤非执行CALLBACK进程
NTSTATUS FASTCALL _ObpCallPreOperationCallbacks(
	ULONG_PTR a1,
	ULONG_PTR a2,
	ULONG_PTR a3)
{
	if ((ISProtectTools(PsGetCurrentProcessId())))
	{
		return STATUS_SUCCESS;
	}
	typedef INT_PTR(FASTCALL *Q_ObpCallPreOperationCallbacks)(INT_PTR, INT_PTR, INT_PTR);
	return ((Q_ObpCallPreOperationCallbacks)ori_addr_ObpCallPreOperationCallbacks)(a1, a2, a3);
}

//功能:过滤游戏打开保护进程权限
BOOLEAN FASTCALL _ObCheckObjectAccess(
	IN PVOID Object,
	IN OUT PACCESS_STATE AccessState,
	IN BOOLEAN TypeMutexLocked,
	IN KPROCESSOR_MODE AccessMode,
	OUT PNTSTATUS AccessStatus)
{
	for (int i = 0; i < PROCESS_COUNT; i++)
	{
		if (_stricmp(PsGetProcessImageFileName(PsGetCurrentProcess()), AccessProcess[i]) == 0) //检查信任列表
		{
			goto __ret__;
		}
	}
	if (!ISProtectTools(PsGetCurrentProcessId()) && MmIsAddressValid(Object))
	{
		if (IsProcess(Object) && ISProtectTools(PsGetProcessId(Object)))
		{
			*AccessStatus = STATUS_ACCESS_DENIED;
			return FALSE;
		}
		else if (IsThread(Object) && ISProtectTools(PsGetThreadProcessId(Object)))
		{
			*AccessStatus = STATUS_ACCESS_DENIED;
			return FALSE;
		}
	}
__ret__:
	return ((BOOLEAN(FASTCALL*)(PVOID, PACCESS_STATE, BOOLEAN, KPROCESSOR_MODE, PNTSTATUS))\
		ori_addr_ObCheckObjectAccess)(
		Object, AccessState, TypeMutexLocked,
		AccessMode, AccessStatus);
}

NTSTATUS FASTCALL _NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK AccessMask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId)
{
	PEPROCESS Process = NULL;
	typedef NTSTATUS(FASTCALL *Q_NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
	if (ProcessHandle != NtCurrentProcess())
	{
		Process = HandleToProcess(ProcessHandle);
	}

	if (ISAttachProcess(PsGetCurrentProcess()) && Process != NULL && \
		!_stricmp(PsGetProcessImageFileName(Process), "csrss.exe"))
	{
		return STATUS_ACCESS_DENIED;
	}
	
	return ((Q_NtOpenProcess)ori_addr_NtOpenProcess)(ProcessHandle, AccessMask, ObjectAttributes, ClientId);;
}

NTSTATUS FASTCALL _NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength   OPTIONAL)
{
	NTSTATUS Status;
	typedef NTSTATUS(FASTCALL *Q_NtQueryInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

	Status = ((Q_NtQueryInformationThread)ori_addr_NtQueryInformationThread)\
		(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

	__try
	{

		if (ThreadInformationClass == ThreadWow64Context &&
			ThreadInformationLength == 0x2CC &&
			ThreadInformation != NULL &&
			ThreadHandle != NULL)//ThreadWow64Context 
		{
			PETHREAD Thread = NULL;
			PWOW64_CONTEXT Context = ThreadInformation;

			if (ThreadHandle != NtCurrentThread())
			{
				Thread = HandleToThread(ThreadHandle);
			}

			//游戏或辅助进程获取CONTEXT
			if ((ISAttachProcess(PsGetCurrentProcess()) && \
				ThreadHandle == NtCurrentThread()) || \
				(Thread != NULL && \
				ISAttachProcess(PsGetThreadProcess(Thread))))
			{
				Context->Dr0 = 0;
				Context->Dr1 = 0;
				Context->Dr2 = 0;
				Context->Dr3 = 0;
				Context->Dr6 = 0;
				Context->Dr7 = 0;
			}
		}

	}
	__except (1){}
	return Status;
}


NTSTATUS FASTCALL _NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength)
{
	NTSTATUS status;
	PVOID	Object;
	typedef NTSTATUS(FASTCALL *Q_NtSetInformationThread)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

	status = ObReferenceObjectByHandle(ThreadHandle, GENERIC_READ, 0, KernelMode, &Object, NULL);
	if (NT_SUCCESS(status))
	{
		ObDereferenceObject(Object);		
	}

	if(ThreadInformationClass != ThreadHideFromDebugger)
	{
		status = ((Q_NtSetInformationThread)SymbolsInfo.NtSetInformationThread)\
			(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
	}
	
	return status;
}




NTSTATUS FASTCALL _NtClose(
	IN HANDLE ObjectHandle)
{
	typedef NTSTATUS(FASTCALL *Q_NtClose)(HANDLE);

	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		//使用一个无效的句柄调用 NtClose 将会产生一个STATUS_INVALID_HANDLE (0xC0000008) 异常。
		PVOID Object;
		NTSTATUS Status;
		Status = ((Q_NtClose)ori_addr_NtClose)(ObjectHandle);
		if (Status == STATUS_INVALID_HANDLE)
		{
			Status = STATUS_SUCCESS;
		}
	}
	else
	{
		return ((Q_NtClose)ori_addr_NtClose)(ObjectHandle);
	}
}


VOID remote_breackpoint(
	IN PEPROCESS Process,
	OUT PVOID* StartRoutine,
	IN PBYTE opcode_buffer,
	IN BOOLEAN iswow64)
{

	static BYTE new_opcode[] = { 0xcc,							//int	  3
		0x6a, 0x00,										//push    0                 
		0x6a, 0xfe,										//push	  -0x2				; ExitStatus
		0xe8, 0x90, 0x90, 0x90, 0x90 };					//call    _RtlExitUserThread@4 ; RtlExitUserThread(x)

	int num = 0;
	DWORD addr[2] = { 0 };
	HANDLE hProcess = NULL;
	PBYTE _DbgBreakPoint = NULL;
	PBYTE _RtlExitUserThread = NULL;

	for (int i = 0; i < 0x50; i++)
	{
		if ((iswow64 && opcode_buffer[i] == 0xe8 && opcode_buffer[i - 1] == 0) || 
			(!iswow64 && opcode_buffer[i] == 0xe8))
		{
			addr[num] = ((PBYTE)*StartRoutine + 12 + i) + 5 + *(PDWORD)((PBYTE)opcode_buffer + i + 1);
			if (++num == 2)
			{
				break;
			}
		}
	}

	if (addr[0] == 0 || addr[1] == 0)
	{
		return;
	}

	_DbgBreakPoint = (PBYTE)addr[0];
	_RtlExitUserThread = (PBYTE)addr[1];
	_DbgBreakPoint += 2;

	*(PDWORD)(new_opcode + 6) = (DWORD)(_RtlExitUserThread - _DbgBreakPoint - 10);
	if (hProcess = MyOpenProcess(PsGetProcessId(Process)))
	{
		//change_game_code
		DWORD oldprotect;
		MyZwProtectVirtualMemory(hProcess, _DbgBreakPoint, 10, PAGE_EXECUTE_READWRITE, &oldprotect);
		MyZwWriteVirtualMemory(hProcess, _DbgBreakPoint, new_opcode, 10);
		MyZwProtectVirtualMemory(hProcess, _DbgBreakPoint, 10, oldprotect, &oldprotect);
		*StartRoutine = _DbgBreakPoint;
		ZwClose(hProcess);
	}
}

VOID change_remote_breakpoint(
	IN PEPROCESS Process, 
	OUT PVOID* StartRoutine)
{
	BYTE opcode_buffer[0x50] = { 0 };
	static BYTE opcode_32[13] = {
		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,				//mov     eax, large fs:18h
		0x8B, 0x40, 0x30,								//mov     eax, [eax+30h]
		0x80, 0x78, 0x02, 0x00							//cmp     byte ptr [eax+2], 0
	};

	static BYTE opcode_64[9] = {
		0x00,											//xx
		0x48, 0x8B, 0x48, 0x60,							//mov     rcx, [rax + 60h]
		0x80, 0x79, 0x02, 0x00,							//cmp     byte ptr[rcx + 2], 0
	};

	MyZwReadVirtualMemory(NtCurrentProcess(), (PBYTE)*StartRoutine + 12, &opcode_buffer, 0x50);

	for (int i = 0; i < 13; i++)
	{
		if (opcode_32[i] != opcode_buffer[i])
			goto __x64__;
	}

	remote_breackpoint(Process, StartRoutine, opcode_buffer, TRUE);
	return;

	__x64__:
	for (int i = 0; i < 9; i++)
	{
		if (opcode_64[i] != opcode_buffer[i])
			return;
	}

	remote_breackpoint(Process, StartRoutine, opcode_buffer, FALSE);
	return;
}


NTSTATUS FASTCALL _NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartContext,
	IN ULONG CreateThreadFlags,
	IN SIZE_T ZeroBits OPTIONAL,
	IN SIZE_T StackSize OPTIONAL,
	IN SIZE_T MaximumStackSize OPTIONAL,
	IN PVOID AttributeList)
{
	typedef NTSTATUS(FASTCALL *Q_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

	if (CreateThreadFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
	{
		CreateThreadFlags ^= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	}

	if (ISProtectTools(PsGetCurrentProcessId()))
	{
		PEPROCESS Process = NULL;
		if (ProcessHandle != NtCurrentProcess())
			Process = HandleToProcess(ProcessHandle);
		if (Process != NULL && ISAttachProcess(Process))
		{
			change_remote_breakpoint(Process, &StartRoutine);
		}
	}
	
	__ret__:
	return ((Q_NtCreateThreadEx)ori_addr_NtCreateThreadEx)(ThreadHandle, DesiredAccess, ObjectAttributes, \
		ProcessHandle, StartRoutine, StartContext, CreateThreadFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);	
}


NTSTATUS FASTCALL _NtQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength)
{
	typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
	{
		ULONG SessionId;
		ULONG BufferLength;
		PVOID Buffer;
	} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

	NTSTATUS Status;
	typedef NTSTATUS(FASTCALL *Q_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

	Status = ((Q_NtQuerySystemInformation)ori_addr_NtQuerySystemInformation)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	if (!NT_SUCCESS(Status) || !MmIsAddressValid(SystemInformation))
	{
		return Status;
	}

	__try
	{
		if (SystemInformationClass == SystemProcessesAndThreadsInformation)
		{
			RemoveProcessFromSysProcessInfo(SystemInformation, SystemInformationLength);
		}
 		else if (SystemInformationClass == SystemSessionProcessesInformation)
		{
			if (SystemInformation && SystemInformationLength >= sizeof(SYSTEM_SESSION_PROCESS_INFORMATION))
			{
				PSYSTEM_SESSION_PROCESS_INFORMATION sessInfo = (PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation;
				if (sessInfo->Buffer)
					RemoveProcessFromSysProcessInfo(sessInfo->Buffer, sessInfo->BufferLength);
			}
		}
		else if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->DebuggerEnabled = 0;
			((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->DebuggerNotPresent = 1;
		}
		else if (SystemInformationClass == 149)//SystemKernelDebuggerInformationEx
		{
			typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
			{
				BOOLEAN BootedDebug;
				BOOLEAN DebuggerEnabled;
				BOOLEAN DebuggerPresent;
			} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX debugInfoEx = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation;
			debugInfoEx->BootedDebug = FALSE;
			debugInfoEx->DebuggerEnabled = FALSE;
			debugInfoEx->DebuggerPresent = FALSE;
		}
		else if (SystemInformationClass == SystemHandleInformation)
		{
			PSYSTEM_HANDLE_INFORMATION_EX pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)SystemInformation;

			for (int i = 0; i < pSysHandleInfo->NumberOfHandles; i++)
			{
				if (ISProtectTools(pSysHandleInfo->Information[i].ProcessID))
				{
					RtlZeroMemory(&pSysHandleInfo->Information[i], 16);
				}
			}
		}
		else if (SystemInformationClass == SystemModuleInformation)
		{
			PSYSTEM_MODULE_INFORMATION moduleinfo = SystemInformation;
			for (DWORD i = 0; i < moduleinfo->Count; i++)
			{
				PBYTE findstr = moduleinfo->Module[i].ImageName + moduleinfo->Module[i].ModuleNameOffset;
				if (strstr(findstr, "PCHunter64al") ||
					strstr(findstr, "dbk64.sys") ||
					strstr(findstr, "dbk32.sys"))
				{
					DWORD length = strlen(findstr);
					memset(findstr, '\0', length + 1);
					memcpy(findstr, "calc.exe", strlen("kdcom.exe") + 1);
					moduleinfo->Module[i].Size = moduleinfo->Module[i-1].Size;
				}
			}

		}
	}
	__except (1)
	{
		Status = GetExceptionCode();
	}
	return Status;
}


NTSTATUS FASTCALL _NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{

	if (ProcessInformationClass == ProcessTimes && ISAttachProcess(PsGetCurrentProcess()))
	{
		return STATUS_ACCESS_DENIED;
	}

	typedef NTSTATUS(FASTCALL *Q_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	NTSTATUS Status = ((Q_NtQueryInformationProcess)ori_addr_NtQueryInformationProcess)(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);

	if (!NT_SUCCESS(Status) || !MmIsAddressValid(ProcessInformation))
	{
		return Status;
	}
	__try
	{
		PEPROCESS Process = NULL;
		if (ProcessHandle != NtCurrentProcess())
			Process = HandleToProcess(ProcessHandle);

		if (ProcessInformationClass == ProcessBasicInformation)
		{

			if ((ISAttachProcess(PsGetCurrentProcess()) && ProcessHandle == NtCurrentProcess()) ||
				(Process != NULL && ISAttachProcess(HandleToProcess(ProcessHandle))))
			{
				if (ISProtectTools(((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId))
					((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = PsGetProcessId(win32k_Process);
			}
			return Status;
		}

		switch (ProcessInformationClass)
		{
		case ProcessDebugPort:
		{
			*(PHANDLE)ProcessInformation = 0;
			break;
		}
		case ProcessDebugObjectHandle:
		{
			*((HANDLE *)ProcessInformation) = 0;
			return STATUS_PORT_NOT_SET;
		}
		case ProcessDebugFlags:
		{
			if ((ISAttachProcess(PsGetCurrentProcess()) && ProcessHandle == NtCurrentProcess()) ||
				(Process != NULL && ISAttachProcess(HandleToProcess(ProcessHandle))))
			{
				*((ULONG*)ProcessInformation) = ((ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0) ? 0 : PROCESS_DEBUG_INHERIT;
			}
			else
			{
				*((ULONG*)ProcessInformation) = 0;
			}
			break;
		}
		case ProcessBreakOnTermination:
		{
			*((PDWORD)ProcessInformation) = ValueProcessBreakOnTermination;
			break;
		}
		case ProcessHandleTracing:
		{
			if (!IsProcessHandleTracingEnabled)
				return STATUS_INVALID_PARAMETER;
			else
				return STATUS_SUCCESS;
		}
		}

	}
	__except (1)
	{
		return GetExceptionCode();
	}

	return Status;
}

NTSTATUS FASTCALL _NtSetInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN DWORD ProcessInformationLength)
{
	PEPROCESS Process = NULL;
	typedef NTSTATUS (FASTCALL *Q_NtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
	if (!MmIsAddressValid(ProcessInformation))
	{
		goto __ret__;
	}

	if (ProcessHandle != NtCurrentProcess())
	{
		Process = HandleToProcess(ProcessHandle);
	}
	
	if ((ProcessHandle == NtCurrentProcess() && ISAttachProcess(PsGetCurrentProcess())) || 
		(Process != NULL && ISAttachProcess(Process)))
	{
		if (ProcessInformationClass == ProcessBreakOnTermination)
		{
			if (ProcessInformationLength != sizeof(ULONG))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			}
			if (ProcessInformation == NULL)
			{
				return STATUS_ACCESS_VIOLATION;
			}
// 			 A process must have debug privileges enabled to set the ProcessBreakOnTermination flag
// 			if (!HasDebugPrivileges(NtCurrentProcess()))
// 			{
// 				return STATUS_PRIVILEGE_NOT_HELD;
// 			}
			ValueProcessBreakOnTermination = *((PDWORD)ProcessInformation);
			return STATUS_SUCCESS;
		}

		//不允许更改调试继承标志，并跟踪要在NtQIP中报告的新值
		if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (ProcessInformationLength != sizeof(ULONG))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			if (ProcessInformation == NULL)
			{
				return STATUS_ACCESS_VIOLATION;
			}

			ULONG Flags = *(ULONG*)ProcessInformation;
			if ((Flags & (~PROCESS_DEBUG_INHERIT)) != 0)
			{
				return STATUS_INVALID_PARAMETER;
			}

			if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
			{
				ValueProcessDebugFlags &= ~PROCESS_NO_DEBUG_INHERIT;
			}
			else
			{
				ValueProcessDebugFlags |= PROCESS_NO_DEBUG_INHERIT;
			}
			return STATUS_SUCCESS;
		}

		//PROCESS_HANDLE_TRACING_ENABLE -> ULONG, PROCESS_HANDLE_TRACING_ENABLE_EX -> ULONG,ULONG
		if (ProcessInformationClass == ProcessHandleTracing)
		{
			////长度为0，表示我们应该禁用跟踪
			BOOLEAN enable = ProcessInformationLength != 0; 
			if (enable)
			{
				if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != (sizeof(ULONG) * 2))
				{
					return STATUS_INFO_LENGTH_MISMATCH;
				}

				// NtSetInformationProcess 将取消引用此指针
				if (ProcessInformation == NULL)
				{
					return STATUS_ACCESS_VIOLATION;
				}

				PPROCESS_HANDLE_TRACING_ENABLE_EX phtEx = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
				if (phtEx->Flags != 0)
				{
					return STATUS_INVALID_PARAMETER;
				}
			}

			IsProcessHandleTracingEnabled = enable;
			return STATUS_SUCCESS;
		}
	}

	__ret__:
	return ((Q_NtSetInformationProcess)ori_addr_NtSetInformationProcess)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS FASTCALL _NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength)
{
	typedef enum _OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectTypesInformation,
		ObjectDataInformation
	} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;


	typedef NTSTATUS(FASTCALL*Q_NtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	NTSTATUS Status = ((Q_NtQueryObject)ori_addr_NtQueryObject)(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength);

	if ((NT_SUCCESS(Status) || Status == STATUS_INFO_LENGTH_MISMATCH ) && \
		ISAttachProcess(PsGetCurrentProcess()) && MmIsAddressValid(ObjectInformation))
	{
		__try
		{
			if (ObjectInformationClass == ObjectTypeInformation)
			{
				FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);
			}
			else if (ObjectInformationClass == ObjectTypesInformation)
			{
				FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation);
			}
		}
		__except (1)
		{
			
		}
	}
	
	return Status;
}

NTSTATUS FASTCALL _NtYieldExecution()
{
	/*
		ntdll函数NtYieldExecution或其kernel32等效的SwitchToThread函数允许当前的
		线程提供放弃其余的时间片，并允许下一个预定的线程
		执行。 如果没有线程被调度执行（或者当系统以特定的方式忙碌时）
		不允许发生切换），则ntdll NtYieldExecution（）函数返回
		STATUS_NO_YIELD_PERFORMED（0x40000024）状态，这导致kernel32 SwitchToThread（）函数
		返回零。 当一个应用程序被调试时，单步执行的行为
		代码导致调试事件，并且通常导致不允许收益。 但是，这是绝望的
		用于检测调试器的不可靠方法，因为它还将检测以高优先级运行的线程的存在。
	*/

	typedef NTSTATUS(FASTCALL *Q_NtYieldExecution)();
	NTSTATUS Status = ((Q_NtYieldExecution)ori_addr_NtYieldExecution)();

	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		return STATUS_NO_YIELD_PERFORMED;
	}
	else
	{
		return Status;
	}
}

NTSTATUS FASTCALL _NtSystemDebugControl(
	IN DWORD ControlCode, 
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	IN PVOID OutputBuffer,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength)
{
#define SysDbgGetTriageDump  29
	typedef NTSTATUS (FASTCALL *Q_NtSystemDebugControl)(DWORD, PVOID, ULONG, PVOID, ULONG, PULONG);
	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		if (ControlCode == SysDbgGetTriageDump)
				return STATUS_INFO_LENGTH_MISMATCH;
			return STATUS_DEBUGGER_INACTIVE;	
	}

	return ((Q_NtSystemDebugControl)ori_addr_NtSystemDebugControl)(ControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
}

NTSTATUS FASTCALL _NtQuerySystemTime(
	IN PLARGE_INTEGER SystemTime)
{
	typedef NTSTATUS(FASTCALL *Q_NtQuerySystemTime)(PLARGE_INTEGER);
	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		if (!NativeSysTime.QuadPart)
		{
			((Q_NtQuerySystemTime)ori_addr_NtQuerySystemTime)(&NativeSysTime);
		}
		else
		{
			NativeSysTime.QuadPart++;
		}

		NTSTATUS ntStat = ((Q_NtQuerySystemTime)ori_addr_NtQuerySystemTime)(&NativeSysTime);

		if (ntStat == STATUS_SUCCESS)
		{
			if (SystemTime)
			{
				SystemTime->QuadPart = NativeSysTime.QuadPart;
			}
		}

		return ntStat;
	}
	else
	{
		return  ((Q_NtQuerySystemTime)ori_addr_NtQuerySystemTime)(&NativeSysTime);
	}	
}


NTSTATUS FASTCALL _NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency)
{

	typedef NTSTATUS(FASTCALL *Q_NtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);

	static LARGE_INTEGER OnePerformanceCounter = { 0 };
	static LARGE_INTEGER OnePerformanceFrequency = { 0 };
	if (!OnePerformanceCounter.QuadPart && ISAttachProcess(PsGetCurrentProcess()))
	{
		((Q_NtQueryPerformanceCounter)ori_addr_NtQueryPerformanceCounter)(&OnePerformanceCounter, &OnePerformanceFrequency);
	}
	else
	{
		OnePerformanceCounter.QuadPart++;
	}

	NTSTATUS ntStat = ((Q_NtQueryPerformanceCounter)ori_addr_NtQueryPerformanceCounter)(PerformanceCounter, PerformanceFrequency);

	if (ntStat == STATUS_SUCCESS && ISAttachProcess(PsGetCurrentProcess()))
	{
		if (PerformanceFrequency) //OPTIONAL
		{
			PerformanceFrequency->QuadPart = OnePerformanceFrequency.QuadPart;
		}

		if (PerformanceCounter)
		{
			PerformanceCounter->QuadPart = OnePerformanceCounter.QuadPart;
		}
	}
	return ntStat;

}


NTSTATUS FASTCALL _NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State)
{
	return STATUS_ACCESS_DENIED;
}


NTSTATUS FASTCALL _NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PVOID ApcRoutine,
	IN PVOID ApcArgument1,
	IN PVOID ApcArgument2,
	IN PVOID ApcArgument3)
{
	typedef NTSTATUS(FASTCALL *Q_NtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
	if (!ISProtectTools(PsGetCurrentProcessId()) ||
		PsGetCurrentProcess() != win32k_Process ||
		PsGetCurrentProcess() != CsrssProcess)
	{
		PETHREAD Thread = HandleToThread(ThreadHandle);
		if (Thread == NULL || ThreadHandle == NtCurrentThread())
		{
			return ((Q_NtQueueApcThread)ori_addr_NtQueueApcThread)(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
		}
		else
		{
			
			if (ISProtectTools(PsGetThreadProcessId(Thread)))
			{
				return STATUS_UNSUCCESSFUL;
			}

			return ((Q_NtQueueApcThread)ori_addr_NtQueueApcThread)(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
		}
	}
	else
	{
		return ((Q_NtQueueApcThread)ori_addr_NtQueueApcThread)(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
	}
}


NTSTATUS FASTCALL _NtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions)
{
	UNICODE_STRING uFakeObjectName = { 0 };
	static WCHAR* wszRegeditPath = L"??C:windowsregedit.exe";
	typedef NTSTATUS(FASTCALL *Q_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

	if (ObjectAttributes && ObjectAttributes->ObjectName->Length > 0 && \
		ValidateUnicodeString(ObjectAttributes->ObjectName))
	{
		if (IsPassGame(PsGetCurrentProcessId()))
		{
			if (wcsistr(ObjectAttributes->ObjectName->Buffer, L"Cheat Engine") ||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"PCHunter64") ||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"5410")||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"cheatengine"))
			{
				RtlInitUnicodeString(&uFakeObjectName, wszRegeditPath);
				ObjectAttributes->ObjectName = &uFakeObjectName;
			}
		}
	}

	return ((Q_NtOpenFile)ori_addr_NtOpenFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

}

NTSTATUS FASTCALL _NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PLARGE_INTEGER AllocationSize,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer,
	IN ULONG EaLength)
{
	UNICODE_STRING uFakeObjectName = { 0 };
	static WCHAR* wszRegeditPath = L"??C:windowsregedit.exe";
	typedef NTSTATUS(FASTCALL *Q_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

	
	if ( ObjectAttributes && ObjectAttributes->ObjectName->Length > 0 && \
		ValidateUnicodeString(ObjectAttributes->ObjectName))
	{
		if (IsPassGame(PsGetCurrentProcessId()))
		{
			if (wcsistr(ObjectAttributes->ObjectName->Buffer, L"Cheat Engine") ||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"PCHunter64") ||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"5410") ||
				wcsistr(ObjectAttributes->ObjectName->Buffer, L"cheatengine"))
			{
				RtlInitUnicodeString(&uFakeObjectName, wszRegeditPath);
				ObjectAttributes->ObjectName = &uFakeObjectName;
			}
		}
	}
	return ((Q_NtCreateFile)ori_addr_NtCreateFile)(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS FASTCALL _NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG FileInformationLength,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{
	typedef NTSTATUS(FASTCALL *Q_NtQueryDirectoryFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
	typedef struct _FILE_BOTH_DIRECTORY_INFORMATION {
		ULONG               NextEntryOffset;
		ULONG               FileIndex;
		LARGE_INTEGER       CreationTime;
		LARGE_INTEGER       LastAccessTime;
		LARGE_INTEGER       LastWriteTime;
		LARGE_INTEGER       ChangeTime;
		LARGE_INTEGER       EndOfFile;
		LARGE_INTEGER       AllocationSize;
		ULONG               FileAttributes;
		ULONG               FileNameLength;
		ULONG               EaSize;
		CHAR                ShortNameLength;
		WCHAR               ShortName[12];
		WCHAR               FileName[ANYSIZE_ARRAY];
	} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION,
		FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

	NTSTATUS Status;
	Status = ((Q_NtQueryDirectoryFile)ori_addr_NtQueryDirectoryFile)(\
		FileHandle, Event, ApcRoutine, ApcContext, \
		IoStatusBlock, FileInformation, FileInformationLength, \
		FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	if (FileIdBothDirectoryInformation == FileInformationClass)
	{
		FILE_BOTH_DIRECTORY_INFORMATION* pFileInfo = (FILE_BOTH_DIRECTORY_INFORMATION*)FileInformation;
		FILE_BOTH_DIRECTORY_INFORMATION* pLastFileInfo = NULL;
		BOOL bLastFlag = FALSE;
		do
		{
			bLastFlag = !(pFileInfo->NextEntryOffset);
			if (wcsistr(pFileInfo->FileName, L"Cheat Engine") ||
				wcsistr(pFileInfo->FileName, L"PCHunter64") ||
				wcsistr(pFileInfo->FileName, L"5410") ||
				wcsistr(pFileInfo->FileName, L"cheatengine"))
			{
				if (bLastFlag) //链表里最后一个文件
				{
					pLastFileInfo->NextEntryOffset = 0;
					break;
				}
				else
				{
					int iPos = (ULONG)pFileInfo - (ULONG)FileInformation;
					int iLeft = (ULONG)FileInformationLength - iPos - pFileInfo->NextEntryOffset;

					RtlCopyMemory((PVOID)pFileInfo, (PVOID)((char *)pFileInfo + pFileInfo->NextEntryOffset), iLeft);
					continue;
				}
			}

			pLastFileInfo = pFileInfo;
			pFileInfo = (PFILE_BOTH_DIRECTORY_INFORMATION)((CHAR*)pFileInfo + pFileInfo->NextEntryOffset);

		} while (!bLastFlag);
	}
	return Status;
}

NTSTATUS FASTCALL _NtContinue(
	IN PCONTEXT ThreadContext,
	IN BOOLEAN RaiseAlert)
{
	int ThreadDebugContextFindExistingSlotIndex();
	void ThreadDebugContextRemoveEntry(const int index);
	typedef NTSTATUS(FASTCALL *Q_NtContinue)(PCONTEXT, BOOLEAN);

	int index = ThreadDebugContextFindExistingSlotIndex();

	if (ThreadContext)
	{
		if (index != -1)
		{
			ThreadContext->Dr0 = ArrayDebugRegister[index].Dr0;
			ThreadContext->Dr1 = ArrayDebugRegister[index].Dr1;
			ThreadContext->Dr2 = ArrayDebugRegister[index].Dr2;
			ThreadContext->Dr3 = ArrayDebugRegister[index].Dr3;
			ThreadContext->Dr6 = ArrayDebugRegister[index].Dr6;
			ThreadContext->Dr7 = ArrayDebugRegister[index].Dr7;
			ThreadDebugContextRemoveEntry(index);
		}

	}

	return ((Q_NtContinue)ori_addr_NtContinue)(ThreadContext, RaiseAlert);
}


BOOLEAN FASTCALL _DbgkForwardException(
IN PEXCEPTION_RECORD64 ExceptionRecord,
IN BOOLEAN DebugException,
IN BOOLEAN SecondChance)
{
	extern ULONG_PTR _read_r12();
	typedef BOOLEAN(FASTCALL *Q_DbgkForwardException)(PEXCEPTION_RECORD64, BOOLEAN, BOOLEAN);
	void FASTCALL _KiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame);
	
	PCONTEXT r12 = (PCONTEXT)_read_r12();

	if (ISAttachProcess(PsGetCurrentProcess()))
	{
		//DbgBreakPoint();
		//return FALSE;
 		BOOLEAN bret = FALSE;
		if (ExceptionRecord->ExceptionCode != STATUS_WX86_BREAKPOINT &&
			ExceptionRecord->ExceptionCode != STATUS_WX86_SINGLE_STEP && 
			ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION &&
			ExceptionRecord->ExceptionCode != STATUS_BREAKPOINT &&
			ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		{
 			_KiUserExceptionDispatcher(ExceptionRecord, r12);
			return FALSE;
		}
		bret = ((Q_DbgkForwardException)ori_addr_DbgkForwardException)(ExceptionRecord, DebugException, SecondChance);
		if (!bret)	_KiUserExceptionDispatcher(ExceptionRecord, r12);
		return bret;
	}

	return ((Q_DbgkForwardException)ori_addr_DbgkForwardException)(ExceptionRecord, DebugException, SecondChance);
}

VOID change_anitanit_debug(
	IN BOOLEAN open)
{
	if (open == TRUE)
	{
 		ori_head_ObCheckObjectAccess = sale_hook(ObCheckObjectAccess, _ObCheckObjectAccess,
 			&ori_addr_ObCheckObjectAccess, &changge_size_ObCheckObjectAccess);
		ori_head_DbgkForwardException = sale_hook(SymbolsInfo.DbgkForwardException, _DbgkForwardException,
			&ori_addr_DbgkForwardException, &changge_size_DbgkForwardException);
		ori_head_ObpCallPreOperationCallbacks = sale_hook(SymbolsInfo.ObpCallPreOperationCallbacks, _ObpCallPreOperationCallbacks,
			&ori_addr_ObpCallPreOperationCallbacks, &changge_size_ObpCallPreOperationCallbacks);		
	}
	else
	{
		sale_unhook(ObCheckObjectAccess, ori_head_ObCheckObjectAccess, changge_size_ObCheckObjectAccess);
		sale_unhook(SymbolsInfo.DbgkForwardException, ori_head_DbgkForwardException, changge_size_DbgkForwardException);
		sale_unhook(SymbolsInfo.ObpCallPreOperationCallbacks, ori_head_ObpCallPreOperationCallbacks, changge_size_ObpCallPreOperationCallbacks);		
	}
}

VOID change_shadow_service(
	IN BOOLEAN open)
{
	typedef struct _KSERVICE_TABLE_DESCRIPTOR
	{
		PVOID  		ServiceTableBase;
		PVOID  		ServiceCounterTableBase;
		ULONGLONG  	NumberOfServices;
		PVOID  		ParamTableBase;
	} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
	ULONG_PTR	ServiceAddress;
	PULONG	W32pServiceTable;
	PKSERVICE_TABLE_DESCRIPTOR SSDTShadow = SymbolsInfo.KeServiceDescriptorTableShadow;

	KeAttachProcess((PRKPROCESS)win32k_Process);

	if (open == TRUE)
	{
		W32pServiceTable = SSDTShadow[1].ServiceTableBase;
		NtUserGetDC = (ULONG_PTR)(((QWORD)(W32pServiceTable[10] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserGetDCEx = (ULONG_PTR)(((QWORD)(W32pServiceTable[146] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserGetWindowDC = (ULONG_PTR)(((QWORD)(W32pServiceTable[100] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtGdiBitBlt = (ULONG_PTR)(((QWORD)(W32pServiceTable[8] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtGdiStretchBlt = (ULONG_PTR)(((QWORD)(W32pServiceTable[49] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserBlockInput = (ULONG_PTR)(((QWORD)(W32pServiceTable[643] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserQueryWindow = (ULONG_PTR)(((QWORD)(W32pServiceTable[16] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserFindWindowEx = (ULONG_PTR)(((QWORD)(W32pServiceTable[110] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserBuildHwndList = (ULONG_PTR)(((QWORD)(W32pServiceTable[28] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserGetClassName = (ULONG_PTR)(((QWORD)(W32pServiceTable[123] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtGdiGetPixel = (ULONG_PTR)(((QWORD)(W32pServiceTable[191] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserCallOneParam = (ULONG_PTR)(((QWORD)(W32pServiceTable[2] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserWindowFromPoint = (ULONG_PTR)(((QWORD)(W32pServiceTable[20] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserGetForegroundWindow = (ULONG_PTR)(((QWORD)(W32pServiceTable[60] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);
		NtUserWindowFromPhysicalPoint = (ULONG_PTR)(((QWORD)(W32pServiceTable[823] >> 4)
			+ (QWORD)W32pServiceTable) & 0xfffffff000ffffff);


		
		ori_head_NtUserGetDC = sale_hook(NtUserGetDC, (PVOID)_NtUserGetDC,
			&ori_addr_NtUserGetDC, &changge_size_NtUserGetDC);
		ori_head_NtUserGetDCEx = sale_hook(NtUserGetDCEx, (PVOID)_NtUserGetDCEx,
 			&ori_addr_NtUserGetDCEx, &changge_size_NtUserGetDCEx);

// 		ori_head_NtUserGetWindowDC = sale_hook(NtUserGetWindowDC, (PVOID)_NtUserGetWindowDC,
// 			&ori_addr_NtUserGetWindowDC, &changge_size_NtUserGetWindowDC);

 		ori_head_NtGdiGetPixel = sale_hook(NtGdiGetPixel, (PVOID)_NtGdiGetPixel,
 			&ori_addr_NtGdiGetPixel, &changge_size_NtGdiGetPixel);
		ori_head_NtUserBlockInput = sale_hook(NtUserBlockInput, (PVOID)_NtUserBlockInput,
 			&ori_addr_NtUserBlockInput, &changge_size_NtUserBlockInput);
 		ori_head_NtUserFindWindowEx = sale_hook(NtUserFindWindowEx, (PVOID)_NtUserFindWindowEx,
 			&ori_addr_NtUserFindWindowEx, &changge_size_NtUserFindWindowEx);
		ori_head_NtUserBuildHwndList = sale_hook(NtUserBuildHwndList, (PVOID)_NtUserBuildHwndList,
			&ori_addr_NtUserBuildHwndList, &changge_size_NtUserBuildHwndList);
		ori_head_NtUserWindowFromPoint = sale_hook(NtUserWindowFromPoint, (PVOID)_NtUserWindowFromPoint,
 			&ori_addr_NtUserWindowFromPoint, &changge_size_NtUserWindowFromPoint);
 		ori_head_NtUserGetForegroundWindow = sale_hook(NtUserGetForegroundWindow, (PVOID)_NtUserGetForegroundWindow,
 			&ori_addr_NtUserGetForegroundWindow, &changge_size_NtUserGetForegroundWindow);
 		ori_head_NtUserWindowFromPhysicalPoint = sale_hook(NtUserWindowFromPhysicalPoint, (PVOID)_NtUserWindowFromPhysicalPoint,
 			&ori_addr_NtUserWindowFromPhysicalPoint, &changge_size_NtUserWindowFromPhysicalPoint);

		ULONG_PTR addr = (ULONG_PTR)NtUserQueryWindow + 0x1f;
		addr = *(PDWORD)(addr + 1) + 5 + addr;
		ori_head_ValidateHwnd = sale_hook(addr, (PVOID)_ValidateHwnd,
			&ori_addr_ValidateHwnd, &changge_size_ValidateHwnd);
	}
	else
	{

		sale_unhook(NtUserGetDC, ori_head_NtUserGetDC, changge_size_NtUserGetDC);
		sale_unhook(NtUserGetDCEx, ori_head_NtUserGetDCEx, changge_size_NtUserGetDCEx);

//		sale_unhook(NtUserGetWindowDC, ori_head_NtUserGetWindowDC, changge_size_NtUserGetWindowDC);

 		sale_unhook(NtGdiGetPixel, ori_head_NtGdiGetPixel, changge_size_NtGdiGetPixel);
 		sale_unhook(NtUserBlockInput, ori_head_NtUserBlockInput, changge_size_NtUserBlockInput);
 		sale_unhook(NtUserFindWindowEx, ori_head_NtUserFindWindowEx, changge_size_NtUserFindWindowEx);
		sale_unhook(NtUserBuildHwndList, ori_head_NtUserBuildHwndList, changge_size_NtUserBuildHwndList);
 		sale_unhook(NtUserWindowFromPoint, ori_head_NtUserWindowFromPoint, changge_size_NtUserWindowFromPoint);
		sale_unhook(NtUserGetForegroundWindow, ori_head_NtUserGetForegroundWindow, changge_size_NtUserGetForegroundWindow);
 		sale_unhook(NtUserWindowFromPhysicalPoint, ori_head_NtUserWindowFromPhysicalPoint, changge_size_NtUserWindowFromPhysicalPoint);


		ULONG_PTR addr = (ULONG_PTR)NtUserQueryWindow + 0x1f;
		addr = *(PDWORD)(addr + 1) + 5 + addr;
		sale_unhook(addr, ori_head_ValidateHwnd, changge_size_ValidateHwnd);
	}
	KeDetachProcess();
}

VOID change_ssdt_hook(
	IN BOOLEAN open)
{
	if (open)
	{
		ori_head_NtClose = sale_hook(QNtClose, (PVOID)_NtClose,
			&ori_addr_NtClose, &changge_size_NtClose);
 		ori_head_NtContinue = sale_hook(NtContinue, (PVOID)_NtContinue,
 			&ori_addr_NtContinue, &changge_size_NtContinue);
		ori_head_NtOpenProcess = sale_hook(NtOpenProcess, (PVOID)_NtOpenProcess,
			&ori_addr_NtOpenProcess, &changge_size_NtOpenProcess);
		ori_head_NtQueryObject = sale_hook(QNtQueryObject, (PVOID)_NtQueryObject,
			&ori_addr_NtQueryObject, &changge_size_NtQueryObject);
		ori_head_NtOpenFile = sale_hook(NtOpenFile, (PVOID)_NtOpenFile,
			&ori_addr_NtOpenFile, &changge_size_NtOpenFile);
		ori_head_NtCreateFile = sale_hook(NtCreateFile, (PVOID)_NtCreateFile,
			&ori_addr_NtCreateFile, &changge_size_NtCreateFile);
		ori_head_NtQuerySystemTime = sale_hook(NtQuerySystemTime, (PVOID)_NtQuerySystemTime,
			&ori_addr_NtQuerySystemTime, &changge_size_NtQuerySystemTime);
		ori_head_NtQueryDirectoryFile = sale_hook(NtQueryDirectoryFile, (PVOID)_NtQueryDirectoryFile,
			&ori_addr_NtQueryDirectoryFile, &changge_size_NtQueryDirectoryFile);
		ori_head_NtYieldExecution = sale_hook(NtYieldExecution, (PVOID)_NtYieldExecution,
			&ori_addr_NtYieldExecution, &changge_size_NtYieldExecution);
		ori_head_NtQueueApcThread = sale_hook(NtQueueApcThread, (PVOID)_NtQueueApcThread,
			&ori_addr_NtQueueApcThread, &changge_size_NtQueueApcThread);
		ori_head_NtCreateThreadEx = sale_hook(NtCreateThreadEx, (PVOID)_NtCreateThreadEx,
			&ori_addr_NtCreateThreadEx, &changge_size_NtCreateThreadEx);
		ori_head_NtSystemDebugControl = sale_hook(SymbolsInfo.NtSystemDebugControl, (PVOID)_NtSystemDebugControl,
			&ori_addr_NtSystemDebugControl, &changge_size_NtSystemDebugControl);
		ori_head_NtSetDebugFilterState = sale_hook(NtSetDebugFilterState, (PVOID)_NtSetDebugFilterState,
			&ori_addr_NtSetDebugFilterState, &changge_size_NtSetDebugFilterState);
		ori_head_NtQuerySystemInformation = sale_hook(NtQuerySystemInformation, (PVOID)_NtQuerySystemInformation,
			&ori_addr_NtQuerySystemInformation, &changge_size_NtQuerySystemInformation);
 		ori_head_NtQueryInformationThread = sale_hook(SymbolsInfo.NtQueryInformationThread, (PVOID)_NtQueryInformationThread,
 			&ori_addr_NtQueryInformationThread, &changge_size_NtQueryInformationThread);
		ori_head_NtQueryInformationProcess = sale_hook(NtQueryInformationProcess, (PVOID)_NtQueryInformationProcess,
			&ori_addr_NtQueryInformationProcess, &changge_size_NtQueryInformationProcess);
		ori_head_NtSetInformationProcess = sale_hook(NtSetInformationProcess, (PVOID)_NtSetInformationProcess,
			&ori_addr_NtSetInformationProcess, &changge_size_NtSetInformationProcess);
//		ori_head_NtQueryPerformanceCounter = sale_hook(NtQueryPerformanceCounter, (PVOID)_NtQueryPerformanceCounter,
// 			&ori_addr_NtQueryPerformanceCounter, &changge_size_NtQueryPerformanceCounter);
	
	}
	else
	{	
		sale_unhook(QNtClose, ori_head_NtClose, changge_size_NtClose);
		sale_unhook(NtContinue, ori_head_NtContinue, changge_size_NtContinue);
		sale_unhook(NtOpenProcess, ori_head_NtOpenProcess, changge_size_NtOpenProcess);
		sale_unhook(QNtQueryObject, ori_head_NtQueryObject, changge_size_NtQueryObject);
		sale_unhook(NtOpenFile, ori_head_NtOpenFile, changge_size_NtOpenFile);
		sale_unhook(NtCreateFile, ori_head_NtCreateFile, changge_size_NtCreateFile);
		sale_unhook(NtQueryDirectoryFile, ori_head_NtQueryDirectoryFile, changge_size_NtQueryDirectoryFile);
		sale_unhook(NtYieldExecution, ori_head_NtYieldExecution, changge_size_NtYieldExecution);
 		sale_unhook(NtQuerySystemTime, ori_head_NtQuerySystemTime, changge_size_NtQuerySystemTime);
 		sale_unhook(NtQueueApcThread, ori_head_NtQueueApcThread, changge_size_NtQueueApcThread);
 		sale_unhook(NtCreateThreadEx, ori_head_NtCreateThreadEx, changge_size_NtCreateThreadEx);
		sale_unhook(SymbolsInfo.NtSystemDebugControl, ori_head_NtSystemDebugControl, changge_size_NtSystemDebugControl);
		sale_unhook(NtSetDebugFilterState, ori_head_NtSetDebugFilterState, changge_size_NtSetDebugFilterState);
		sale_unhook(NtQuerySystemInformation, ori_head_NtQuerySystemInformation, changge_size_NtQuerySystemInformation);
		sale_unhook(SymbolsInfo.NtQueryInformationThread, ori_head_NtQueryInformationThread, changge_size_NtQueryInformationThread);
		sale_unhook(NtQueryInformationProcess, ori_head_NtQueryInformationProcess, changge_size_NtQueryInformationProcess);
		sale_unhook(NtSetInformationProcess, ori_head_NtSetInformationProcess, changge_size_NtSetInformationProcess);
//		sale_unhook(NtQueryPerformanceCounter, ori_head_NtQueryPerformanceCounter, changge_size_NtQueryPerformanceCounter);
	}
}





