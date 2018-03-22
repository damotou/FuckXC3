
#include "struct.h"


NTSTATUS FASTCALL _NtQueryInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL);
#define MAX_DBG_SIZE 100

//Global
DWORD		PTESize;
UINT_PTR	MAX_PDE_POS;
UINT_PTR	MAX_PTE_POS;
UINT_PTR	PAGE_SIZE_LARGE;
UINT_PTR	ZwReadVirtualMemory;
UINT_PTR	ZwWriteVirtualMemory;
UINT_PTR	ZwProtectVirtualMemory;
UINT_PTR    ZwQueryInformationProcess;
SAVE_DEBUG_REGISTERS ArrayDebugRegister[200] = { 0 }; //Max 200 threads


size_t _strlen(const char* sc)
{
	size_t count = 0;
	while (sc[count] != '\0')
		count++;
	return count;
}

size_t _wcslen(const wchar_t* sc)
{
	size_t count = 0;
	while (sc[count] != L'\0')
		count++;
	return count;
}

BOOLEAN wcsistr(const wchar_t *s, const wchar_t *t)
{
	size_t l1 = _wcslen(s);
	size_t l2 = _wcslen(t);

	if (l1 < l2)
		return FALSE;

	if (l1 == l2)
	{
		if (!_wcsicmp(s, t))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	for (int off = 0; off < (int)(l1 - l2); ++off)
	{
		if (!_wcsnicmp(s + off, t, l2))
			return TRUE;
	}

	return FALSE;
}

//功能:模块名称,地址
ULONG64 GetDirverBase(char* drivername)
{
	NTSTATUS status;
	ULONG size;
	char* pDrvName;
	PSYSTEM_MODULE_INFORMATION moduleinfo;
	PSYSTEM_MODULE_INFORMATION_ENTRY moduleinfoentry;
	status = NtQuerySystemInformation(11, &size, NULL, &size);
	if (status != 0xc0000004)
	{
		return;
	}

	moduleinfo = ExAllocatePool(NonPagedPool, size);
	if (moduleinfo == NULL)
	{
		return;
	}

	do
	{

		status = NtQuerySystemInformation(11, moduleinfo, size, &size);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		moduleinfoentry = moduleinfo->Module;
		for (ULONG i = 0; i < moduleinfo->Count; i++)
		{
			pDrvName = moduleinfoentry->ImageName + moduleinfoentry->ModuleNameOffset;
			if (!_stricmp(drivername, pDrvName))
			{
				ExFreePool(moduleinfo);
				return (ULONG64)moduleinfoentry->Base;
			}
			moduleinfoentry++;
		}

	} while (FALSE);


	ExFreePool(moduleinfo);

	return 0;
}

//功能:导出名称,地址
ULONG64 GetProcAddress(PSTR FunName)
{
	UNICODE_STRING FunNameUnicode;
	RtlInitUnicodeString(&FunNameUnicode, FunName);
	return (ULONG64)MmGetSystemRoutineAddress(&FunNameUnicode);
}

//功能:过注册回调判断
void BypassCheckSign(PDRIVER_OBJECT pDriverObj)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
}

//功能:模块基址,模块大小
VOID GetKernelModuleBase(PULONG64 KrnlBase, PULONG64 KrnlSize)
{
	NTSTATUS status;
	ULONG size;
	char* pDrvName;
	PSYSTEM_MODULE_INFORMATION moduleinfo;
	PSYSTEM_MODULE_INFORMATION_ENTRY moduleinfoentry;

	status = NtQuerySystemInformation(11, &size, NULL, &size);
	if (status != 0xc0000004)
	{
		return;
	}

	moduleinfo = ExAllocatePool(NonPagedPool, size);
	if (moduleinfo == NULL)
	{
		return;
	}

	do
	{

		status = NtQuerySystemInformation(11, moduleinfo, size, &size);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		moduleinfoentry = moduleinfo->Module;
		*KrnlBase = moduleinfoentry->Base;
		*KrnlSize = moduleinfoentry->Size;

	} while (FALSE);


	ExFreePool(moduleinfo);
}

//功能:隐藏驱动名
VOID HideDriver(char* drivername, PDRIVER_OBJECT driverobj)
{
	KIRQL irql;
	ULONG64 base;
	PLDR_DATA_TABLE_ENTRY firstentry;
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)driverobj->DriverSection;

	firstentry = entry;
	base = GetDirverBase(drivername);
	
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if (entry->DllBase == base)
		{
			irql = KeRaiseIrqlToDpcLevel();

			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;

			entry->InLoadOrderLinks.Flink = 0;
			entry->InLoadOrderLinks.Blink = 0;

			KeLowerIrql(irql);
			break;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

}

//功能:SSDT ID,地址
ULONG_PTR read_ssdt_funaddr(DWORD id)
{

	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)((PSYSTEM_SERVICE_TABLE)SymbolsInfo.\
		KeServiceDescriptorTable)->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

//功能:安全修改内核
VOID sale_change(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, IN ULONG Size)
{
	KIRQL irql;
	PVOID Msct;
	PMDL MdlForFunc;
	MdlForFunc = MmCreateMdl(NULL, ApiAddress, Size);

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
			return NULL;
		}
		Msct = MmMapLockedPagesSpecifyCache(MdlForFunc, KernelMode, MmWriteCombined, NULL, FALSE, 0);
		irql = KeRaiseIrqlToDpcLevel();

		RtlCopyMemory(Msct, Proxy_ApiAddress, Size);

		KeLowerIrql(irql);
		MmUnmapLockedPages(Msct, MdlForFunc);
		MmUnlockPages(MdlForFunc);
		IoFreeMdl(MdlForFunc);
	}
}

//功能:进程ID,进程名称
PCHAR GetProcessNameByProcessId(HANDLE ProcessId)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	PEPROCESS ProcessObj = NULL;
	PCHAR string = NULL;
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	if (NT_SUCCESS(st))
	{
		string = PsGetProcessImageFileName(ProcessObj);
		ObfDereferenceObject(ProcessObj);
	}
	return string;
}


//功能:
VOID InitMemSafe()
{
#ifndef AMD64  
	ULONG cr4reg;
	//determine if PAE is used  
	cr4reg = (ULONG)__readcr4();
	if ((cr4reg & 0x20) == 0x20)
	{
		PTESize = 8; //pae  
		PAGE_SIZE_LARGE = 0x200000;
		MAX_PDE_POS = 0xC0604000;
		MAX_PTE_POS = 0xC07FFFF8;
	}
	else
	{
		PTESize = 4;
		PAGE_SIZE_LARGE = 0x400000;
		MAX_PDE_POS = 0xC0301000;
		MAX_PTE_POS = 0xC03FFFFC;
	}
#else  
	PTESize = 8; //pae  
	PAGE_SIZE_LARGE = 0x200000;
	MAX_PTE_POS = 0xFFFFF6FFFFFFFFF8ULL;
	MAX_PDE_POS = 0xFFFFF6FB7FFFFFF8ULL;
#endif  
}

//功能:比MmIsAddressValid更安全判断
BOOLEAN IsAddressSafe(IN UINT_PTR StartAddress)
{

	struct PTEStruct
	{
		unsigned P : 1; // present (1 = present)  
		unsigned RW : 1; // read/write  
		unsigned US : 1; // user/supervisor  
		unsigned PWT : 1; // page-level write-through  
		unsigned PCD : 1; // page-level cache disabled  
		unsigned A : 1; // accessed  
		unsigned Reserved : 1; // dirty  
		unsigned PS : 1; // page size (0 = 4-KB page)  
		unsigned G : 1; // global page  
		unsigned A1 : 1; // available 1 aka copy-on-write  
		unsigned A2 : 1; // available 2/ is 1 when paged to disk  
		unsigned A3 : 1; // available 3  
		unsigned PFN : 20; // page-frame number  
	};
#ifdef AMD64  
	//规范检查。 位48到63必须匹配位47
	UINT_PTR toppart = (StartAddress >> 47);
	if (toppart & 1)
	{
		//toppart必须是 0x1ffff  
		if (toppart != 0x1ffff)
			return FALSE;
	}
	else
	{
		//toppart 不是 0  
		if (toppart != 0)
			return FALSE;

	}
#endif  
	//PDT+PTE judge  
	{
#ifdef AMD64  
		UINT_PTR kernelbase = 0x7fffffffffffffffULL;
		if (StartAddress < kernelbase)
		{
			return TRUE;
		}
		else
		{
			PHYSICAL_ADDRESS physical;
			physical.QuadPart = 0;
			physical = MmGetPhysicalAddress((PVOID)StartAddress);
			return (physical.QuadPart != 0);
		}
		return TRUE; //现在直到我ave找出了win 4分页方案  
#else  
		ULONG kernelbase = 0x7ffe0000;
		UINT_PTR PTE, PDE;
		struct PTEStruct *x;
		if (StartAddress < kernelbase)
		{
			return TRUE;
		}
		PTE = (UINT_PTR)StartAddress;
		PTE = PTE / 0x1000 * PTESize + 0xc0000000;
		//now check if the address in PTE is valid by checking the page table directory at 0xc0300000 (same location as CR3 btw)  
		PDE = PTE / 0x1000 * PTESize + 0xc0000000; //same formula  
		x = (struct PTEStruct *)PDE;
		if ((x->P == 0) && (x->A2 == 0))
		{
			//Not present or paged, and since paging in this area isn't such a smart thing to do just skip it  
			//perhaps this is only for the 4 mb pages, but those should never be paged out, so it should be 1  
			//bah, I've got no idea what this is used for  
			return FALSE;
		}
		if (x->PS == 1)
		{
			//This is a 4 MB page (no pte list)  
			//so, (startaddress/0x400000*0x400000) till ((startaddress/0x400000*0x400000)+(0x400000-1) ) ) is specified by this page  
		}
		else //if it's not a 4 MB page then check the PTE  
		{
			//still here so the page table directory agreed that it is a usable page table entry  
			x = (PVOID)PTE;
			if ((x->P == 0) && (x->A2 == 0))
				return FALSE; //see for explenation the part of the PDE  
		}
		return TRUE;
#endif  
	}
}



//功能:进程名,进程结构
VOID PsLookupProcessByProcessName(IN char* ProcessName, OUT PEPROCESS* Process)
{
	PLIST_ENTRY list = NULL;
	PLIST_ENTRY entry = NULL;
	PEPROCESS_S SystemProcess;
	PsLookupProcessByProcessId((HANDLE)4, (PEPROCESS*)&SystemProcess);
	list = entry = &SystemProcess->ActiveProcessLinks;

	do
	{
		list = list->Flink;

		*Process = (PEPROCESS_S)((PBYTE)list - 0x188);
		if (_stricmp(PsGetProcessImageFileName(*Process), ProcessName) == 0)
		{
			break;
		}
	} while (entry != list);

}

HANDLE MyOpenProcess(IN HANDLE ProcessId)
{
	PEPROCESS Process;
	HANDLE ProcessHandle;

	ProcessHandle = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		if (!NT_SUCCESS(ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, NULL, 0, &ProcessHandle)))
		{
			ProcessHandle = NULL;
		}

		ObfDereferenceObject(Process);
	}

	return ProcessHandle;
}
BOOLEAN MyZwReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG NumberOfBytesToRead)
{
	DWORD NumberOfBytesReaded;
	typedef NTSTATUS(NTAPI *Q_ZwReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	return ((Q_ZwReadVirtualMemory)ZwReadVirtualMemory)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, &NumberOfBytesReaded);
}
BOOLEAN MyZwWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite)
{
	DWORD NumberOfBytesWriteed;
	typedef NTSTATUS(NTAPI *Q_ZwWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	return ((Q_ZwWriteVirtualMemory)ZwWriteVirtualMemory)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, &NumberOfBytesWriteed);
}
BOOLEAN MyZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN	PVOID BaseAddress, IN SIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT	PULONG OldAccessProtecton)
{
	typedef NTSTATUS(NTAPI *Q_ZwProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
	return ((Q_ZwProtectVirtualMemory)ZwProtectVirtualMemory)(ProcessHandle, &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, OldAccessProtecton);
}


ULONG GetFunctionIndex(PVOID FunctionAddress)
{
#ifdef _M_X64
	if (FunctionAddress && *(ULONG*)FunctionAddress == 0xB8D18B4C)// 特征匹配 mov r10, rcx ; mov eax, 17Eh
	{
		return *((ULONG*)FunctionAddress + 1);
	}
#else
	if (FunctionAddress)
	{
		return *(ULONG*)((BYTE*)FunctionAddress + 1);
	}
#endif

	else
	{
		return (ULONG)(-1);
	}
}

PVOID GetDllFunAddress(PVOID ImageBase, CHAR *FunctionName, BOOLEAN IsValidImageBase)
{
	PIMAGE_DOS_HEADER DosHdr;
#ifdef _M_X64
	PIMAGE_NT_HEADERS64 NtHdr64;
#else
	PIMAGE_NT_HEADERS32 NtHdr32;
#endif

	PIMAGE_EXPORT_DIRECTORY ExportDir;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
	DWORD	VirtualAddress;
	DWORD	*pAddressOfFunctions;
	DWORD	*pAddressOfNames;
	WORD	*pAddressofNameOrdinals;
	int i;

	DosHdr = (PIMAGE_DOS_HEADER)ImageBase;
	if (NULL != ImageBase)
	{
		if (DosHdr->e_magic == IMAGE_DOS_SIGNATURE)
		{
#ifdef _M_X64
			NtHdr64 = (PIMAGE_NT_HEADERS64)((CHAR*)ImageBase + DosHdr->e_lfanew);
			if (NtHdr64->Signature == IMAGE_NT_SIGNATURE)
			{
				if (IsValidImageBase)
				{
					VirtualAddress = NtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
				}
#else
			NtHdr32 = (PIMAGE_NT_HEADERS32)((CHAR*)ImageBase + DosHdr->e_lfanew);
			if (NtHdr32->Signature == IMAGE_NT_SIGNATURE)
			{
				if (IsValidImageBase)
				{
					VirtualAddress = NtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
				}
#endif
				ExportDir = (PIMAGE_EXPORT_DIRECTORY)((CHAR*)ImageBase + VirtualAddress);
				if (IsValidImageBase)
				{
					AddressOfFunctions = ExportDir->AddressOfFunctions;
				}

				pAddressOfFunctions = (DWORD*)((CHAR*)ImageBase + AddressOfFunctions);

				if (IsValidImageBase)
				{
					AddressOfNameOrdinals = ExportDir->AddressOfNameOrdinals;
				}

				pAddressofNameOrdinals = (WORD*)((CHAR*)ImageBase + AddressOfNameOrdinals);

				if (IsValidImageBase)
				{
					AddressOfNames = ExportDir->AddressOfNames;
				}

				pAddressOfNames = (DWORD*)((CHAR*)ImageBase + AddressOfNames);

				for (i = 0; i < ExportDir->NumberOfNames; i++)
				{
					if (!strcmp(FunctionName, (CHAR*)ImageBase + pAddressOfNames[i]))
					{
						return (CHAR*)ImageBase + pAddressOfFunctions[pAddressofNameOrdinals[i]];
					}
				}
			}
			}
		}

	return NULL;
	}

PVOID GetNtKrnlFuncAddressByIndex(PVOID ImageBase, BOOLEAN IsValidImageBase, ULONG FindFunctionIndex)
{
	PVOID FunZwAllocMemory;
	ULONG IndexZwAllocMemory;
	int i, j;

	if (FindFunctionIndex != (ULONG)-1)
	{
		FunZwAllocMemory = GetDllFunAddress(ImageBase, "ZwAllocateVirtualMemory", IsValidImageBase);
		IndexZwAllocMemory = GetFunctionIndex(FunZwAllocMemory);

		if (IndexZwAllocMemory != (ULONG)-1)
		{
			for (i = 0; i < 100; ++i)
			{
				if (*((BYTE*)&ZwAllocateVirtualMemory + i) == 0xB8 // MOV EAX, XXXX
					&& *(DWORD*)((BYTE*)&ZwAllocateVirtualMemory + i + 1) == IndexZwAllocMemory) // 判断索引号是否一致
				{
					for (j = i; j < i + 100; ++j)
					{
						if (*((BYTE*)&ZwAllocateVirtualMemory + j) == 0xB8
							&& *(ULONG*)((BYTE*)&ZwAllocateVirtualMemory + j + 1) == IndexZwAllocMemory + 1) // 判断下一个函数索引号是否一致
						{
							if (*((BYTE*)ZwAllocateVirtualMemory + (j - i) * (FindFunctionIndex - IndexZwAllocMemory) + i) == 0xB8
								&& *(DWORD*)((BYTE*)ZwAllocateVirtualMemory + (j - i) * (FindFunctionIndex - IndexZwAllocMemory) + i + 1) == FindFunctionIndex)
							{
								return (BYTE*)ZwAllocateVirtualMemory + (j - i) * (FindFunctionIndex - IndexZwAllocMemory);
							}
							return NULL;
						}
					}
					return NULL;
				}
			}
		}
	}

	return NULL;
}

PVOID GetNtKrnlFuncAddress(PVOID ImageBase, BOOLEAN IsValidImageBase, CHAR *FunctionName)
{
	PVOID FunctionAddress;
	ULONG FunctionIndex;

	FunctionAddress = GetDllFunAddress(ImageBase, FunctionName, IsValidImageBase);
	FunctionIndex = GetFunctionIndex(FunctionAddress);

#ifdef _M_X64
	DbgPrint("[hdlphook] GetNtKrnlFuncAddress Imagebases:0x%I64X funcaddrss:0x%I64X index:%d\n", ImageBase, FunctionAddress, FunctionIndex);
#else 
	DbgPrint("[hdlphook] GetNtKrnlFuncAddress Imagebases:%08x funcaddrss:%08x index:%d\n", ImageBase, FunctionAddress, FunctionIndex);
#endif

	return GetNtKrnlFuncAddressByIndex(ImageBase, IsValidImageBase, FunctionIndex);
}

DWORD HandleToTid(IN HANDLE hThread)
{
	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PVOID TebBaseAddress;
		CLIENT_ID ClientId;
		ULONG_PTR AffinityMask;
		KPRIORITY Priority;
		LONG BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(_NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return (DWORD)tbi.ClientId.UniqueProcess;
	}
	return 0;
}
DWORD HandleToPid(IN HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;
	if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0)))
	{
		return (DWORD)pbi.UniqueProcessId;
	}
	return 0;
}
PETHREAD HandleToThread(IN HANDLE hThread)
{
	NTSTATUS status;
	PETHREAD Thread = NULL;

	status = ObReferenceObjectByHandle(
		hThread,
		NULL,
		(PVOID)* PsThreadType,
		KernelMode,
		&Thread,
		NULL);

	if (NT_SUCCESS(status))
	{
		ObDereferenceObject(Thread);
		return Thread;
	}
	else
	{
		return NULL;
	}
}
PEPROCESS HandleToProcess(IN HANDLE hProcess)
{
	NTSTATUS status;
	PEPROCESS Process = NULL;

	status = ObReferenceObjectByHandle(
		hProcess,
		NULL,
		*PsProcessType,
		KernelMode,
		&Process,
		NULL);

	if (NT_SUCCESS(status))
	{
		return Process;
	}
	else
	{
		return NULL;
	}
}
BOOLEAN IsThread(IN PVOID obejcet)
{

	if (obejcet == NULL)
	{
		return FALSE;
	}
	if (!MmIsAddressValid(obejcet))
	{
		return FALSE;
	}

	POBJECT_TYPE obejcetType = ObGetObjectType(obejcet);

	if (!MmIsAddressValid(obejcetType) ||
		obejcetType == NULL)
	{
		return FALSE;
	}

	if (obejcetType != *PsThreadType)
	{
		return FALSE;
	}
	return TRUE;

}
BOOLEAN IsProcess(IN PVOID obejcet)
{

	if (obejcet == NULL)
	{
		return FALSE;
	}
	if (!MmIsAddressValid(obejcet))
	{
		return FALSE;
	}


	POBJECT_TYPE obejcetType = ObGetObjectType(obejcet);

	if (!MmIsAddressValid(obejcetType) ||
		obejcetType == NULL)
	{
		return FALSE;
	}

	if (obejcetType != *PsProcessType)
	{
		return FALSE;
	}
	return TRUE;

}

DWORD ReadInheritedProcessPid(PEPROCESS Process)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	HANDLE hProcess;
	ULONG pid = NULL;
	BOOL bInit = FALSE;
	typedef NTSTATUS(NTAPI *Q_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	//无效的进程对象，或者已经退出的进程，都直接返回
	if (!MmIsAddressValid(Process))
	{
		return NULL;
	}
	status = ObOpenObjectByPointer(
		Process,          // Object    
		OBJ_KERNEL_HANDLE,  // HandleAttributes    
		NULL,               // PassedAccessState OPTIONAL    
		PROCESS_ALL_ACCESS,       // DesiredAccess    
		*PsProcessType,     // ObjectType    
		KernelMode,         // AccessMode    
		&hProcess);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	status = ((Q_ZwQueryInformationProcess)ZwQueryInformationProcess)(
		hProcess,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return NULL;
	}

	pid = pbi.InheritedFromUniqueProcessId;
	ZwClose(hProcess);
	return pid;
}

BOOLEAN ValidateUnicodeString(IN PUNICODE_STRING usStr)
{
	ULONG i;

	__try
	{
		if (!MmIsAddressValid(usStr))
		{
			return FALSE;
		}
		if (usStr->Buffer == NULL || usStr->Length == 0)
		{
			return FALSE;
		}
		for (i = 0; i < usStr->Length; i++)
		{
			if (!MmIsAddressValid((PUCHAR)usStr->Buffer + i))
			{
				return FALSE;
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER){

	}
	return TRUE;
}

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
#define REGISTRY_POOL_TAG 'pRE'
	BOOLEAN foundCompleteName = FALSE;
	BOOLEAN partial = FALSE;
	if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
		return FALSE;

	if (!foundCompleteName)
	{
		/* Query the object manager in the kernel for the complete name */
		NTSTATUS status;
		ULONG returnedLength;
		PUNICODE_STRING pObjectName = NULL;
		status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG);
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlCopyUnicodeString(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreePoolWithTag(pObjectName, REGISTRY_POOL_TAG);
		}
	}
	return foundCompleteName;
}

void ThreadDebugContextRemoveEntry(const int index)
{
	ArrayDebugRegister[index].dwThreadId = 0;
}

int ThreadDebugContextFindFreeSlotIndex()
{
	for (int i = 0; i < _countof(ArrayDebugRegister); i++)
	{
		if (ArrayDebugRegister[i].dwThreadId == 0)
		{
			return i;
		}
	}

	return -1;
}

int ThreadDebugContextFindExistingSlotIndex()
{
	for (int i = 0; i < _countof(ArrayDebugRegister); i++)
	{
		if (ArrayDebugRegister[i].dwThreadId != 0)
		{
			if (ArrayDebugRegister[i].dwThreadId == PsGetCurrentThreadId())
			{
				return i;
			}
		}
	}

	return -1;
}

void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext)
{
	ArrayDebugRegister[index].dwThreadId = PsGetCurrentThreadId();
	ArrayDebugRegister[index].Dr0 = ThreadContext->Dr0;
	ArrayDebugRegister[index].Dr1 = ThreadContext->Dr1;
	ArrayDebugRegister[index].Dr2 = ThreadContext->Dr2;
	ArrayDebugRegister[index].Dr3 = ThreadContext->Dr3;
	ArrayDebugRegister[index].Dr6 = ThreadContext->Dr6;
	ArrayDebugRegister[index].Dr7 = ThreadContext->Dr7;
}

void FASTCALL _KiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame)
{
	if (ContextFrame && (ContextFrame->ContextFlags & CONTEXT_DEBUG_REGISTERS))
	{
		int slotIndex = ThreadDebugContextFindFreeSlotIndex();
		if (slotIndex != -1)
		{
			ThreadDebugContextSaveContext(slotIndex, ContextFrame);
		}

		ContextFrame->Dr0 = 0;
		ContextFrame->Dr1 = 0;
		ContextFrame->Dr2 = 0;
		ContextFrame->Dr3 = 0;
		ContextFrame->Dr6 = 0;
		ContextFrame->Dr7 = 0;
	}
}

