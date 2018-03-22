#ifndef __DBGK__
#define __DBGK__

#include "struct.h"


//
// 调试对象访问权限
//
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

//调试相关标记
#define DEBUG_OBJECT_DELETE_PENDING			(0x1) // 调试对象是删除挂起。
#define DEBUG_OBJECT_KILL_ON_CLOSE			(0x2) // 杀死所有调试的进程关闭

#define DEBUG_KILL_ON_CLOSE					(0x01)

#define DEBUG_EVENT_READ					(0x01)  // 事件一直被 win32 应用程序
#define DEBUG_EVENT_NOWAIT					(0x02)  // 不等待. Just free the pool
#define DEBUG_EVENT_INACTIVE				(0x04)  // 消息处于非活动状态。 它可能会被激活或删除
#define DEBUG_EVENT_RELEASE					(0x08)  // 成功获取线程保护
#define DEBUG_EVENT_PROTECT_FAILED			(0x10)  // 无法获取线程保护
#define DEBUG_EVENT_SUSPEND					(0x20)  // 暂停线程

//
// 定义调试对象访问类型。 此对象上不存在安全性。
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
	DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define ProbeForWriteGenericType(Ptr, Type)                                    \
	do {                                                                       \
	if ((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||          \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) { \
	ExRaiseAccessViolation();                                          \
						}                                                                      \
						*(volatile Type *)(Ptr) = *(volatile Type *)(Ptr);                     \
	} while (0)

#define ProbeForWriteHandle(Ptr) ProbeForWriteGenericType(Ptr, HANDLE)
#define PspSetProcessFlag(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn (Flags, Flag)


#define EX_PUSH_LOCK_SHARE_INC       ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS        ((ULONG_PTR)0xf)
#define EX_PUSH_LOCK_LOCK            ((ULONG_PTR)0x1)
#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
	((hdrs)->OptionalHeader.##field)

#define DBGKM_MSG_OVERHEAD \
    (FIELD_OFFSET(DBGKM_MSG, Exception) - sizeof(PORT_MESSAGE))

#define DBGKM_API_MSG_LENGTH(TypeSize) \
    ((sizeof(DBGKM_MSG) << 16) | (DBGKM_MSG_OVERHEAD + (TypeSize)))
#define DBGKM_FORMAT_API_MSG(m,Number,TypeSize)             \
    (m).h.u1.Length = DBGKM_API_MSG_LENGTH((TypeSize));     \
    (m).h.u2.ZeroInit = LPC_DEBUG_EVENT;                    \
    (m).ApiNumber = (Number)

typedef struct _DEBUG_OBJECT
{
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY64 EventList;
	union
	{
		ULONG Flags;
		struct
		{
			UCHAR DebuggerInactive : 1;
			UCHAR KillProcessOnExit : 1;
		};
	};
} DEBUG_OBJECT, *PDEBUG_OBJECT;


typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG32 MessageId;
	union
	{
		ULONGLONG ClientViewSize;
		ULONG32 CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _LPC_CLIENT_DIED_MSG
{
	PORT_MESSAGE PortMsg;
	LARGE_INTEGER CreateTime;
} LPC_CLIENT_DIED_MSG, *PLPC_CLIENT_DIED_MSG;

typedef enum _DBGKM_APINUMBER
{
	DbgKmExceptionApi = 0,
	DbgKmCreateThreadApi = 1,
	DbgKmCreateProcessApi = 2,
	DbgKmExitThreadApi = 3,
	DbgKmExitProcessApi = 4,
	DbgKmLoadDllApi = 5,
	DbgKmUnloadDllApi = 6,
	DbgKmErrorReportApi = 7,
	DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

//
// Debug Message Structures
//
typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef struct _DBGKM_MSG
{
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcess;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	};
	UCHAR unknow[0x40];
} DBGKM_MSG, *PDBGKM_MSG;

typedef struct _DEBUG_EVENT
{
	LIST_ENTRY EventList;
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS Status;
	ULONG32 Flags;
	PETHREAD BackoutThread;
	DBGKM_MSG ApiMsg;

} DEBUG_EVENT, *PDEBUG_EVENT;

typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		struct
		{
			HANDLE HandleToThread;
			DBGKM_CREATE_THREAD NewThread;
		} CreateThread;
		struct
		{
			HANDLE HandleToProcess;
			HANDLE HandleToThread;
			DBGKM_CREATE_PROCESS NewProcess;
		} CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_EXCEPTION Exception;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;


#endif