
#ifndef __INIT__
#define __INIT__

#include "struct.h"



#define CTL_CODET(x) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800 + x,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_SymbolsInfo									CTL_CODET(0)
#define IOCTL_Windbg										CTL_CODET(1)
#define IOCTL_CallBack										CTL_CODET(2)



extern SYMBOLS_INFO SymbolsInfo;
extern ULONG_PTR  ObCheckObjectAccess;
extern ULONG_PTR  HvlNotifyLongSpinWait;
extern ULONG_PTR  KiInSwapSingleProcess;
extern ULONG_PTR  MiProtectVirtualMemory;
extern ULONG_PTR  ZwReadVirtualMemory;
extern ULONG_PTR  ZwWriteVirtualMemory;
extern ULONG_PTR  ZwProtectVirtualMemory;
extern ULONG_PTR  ZwQueryInformationProcess;
extern ULONG_PTR  HvlSwitchVirtualAddressSpace;


extern ULONG_PTR  QNtClose;
extern ULONG_PTR  QNtQueryObject;
extern ULONG_PTR  NtContinue;
extern ULONG_PTR  QNtCreateFile;
extern ULONG_PTR  NtQueryValueKey;
extern ULONG_PTR  NtQueueApcThread;
extern ULONG_PTR  NtCreateThreadEx;
extern ULONG_PTR  NtYieldExecution;
extern ULONG_PTR  NtSuspendProcess;
extern ULONG_PTR  NtQuerySystemTime;
extern ULONG_PTR  NtSetDebugFilterState;
extern ULONG_PTR  NtQueryPerformanceCounter;

#define PROCESS_COUNT 13
char AccessProcess[PROCESS_COUNT][20] = {
	"System","winlogon.exe", "csrss.exe", "services.exe", "lsass.exe", 
	"svchost.exe","wininit.exe", "smss.exe", "rundll32.exe", "explorer.exe" ,
	"taskhost.exe","taskmgr.exe","WmiPrvSE.exe"};
#endif