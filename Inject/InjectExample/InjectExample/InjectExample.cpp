// InjectExample.cpp : 定义控制台应用程序的入口点。


#include "stdafx.h"

int EnableDebugPriv(const wchar_t *name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	//打开进程令牌环
	if(NULL == OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
		return 1;

	//获得进程本地唯一ID
	if(!LookupPrivilegeValue(NULL,name,&luid))
		return 1;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	
	//调整权限
	if(!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
		return 1;
	return 0;
}

BOOL InjectDll(const wchar_t* DllFullPath,const DWORD dwRemoteProcessId)
{
	HANDLE hRemoteProcess;
	EnableDebugPriv(SE_DEBUG_NAME);
	//打开远程线程 
	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessId);
	if(!hRemoteProcess)
	{
		printf("OpenProcess Fail,GetLastError: %d",GetLastError());
		return FALSE;
	}

	void *pszLibFileRemote;
	//使用VirtualAllocEx 函数在远程进程的内存地址空间分配DLL文件名空间
	pszLibFileRemote = VirtualAllocEx(hRemoteProcess,NULL,(wcslen(DllFullPath)+1)*sizeof(wchar_t),MEM_COMMIT,PAGE_READWRITE);
	if(!pszLibFileRemote)
	{
		printf("VirtualAllocEx Fail,GetLastError: %d",GetLastError());
		return FALSE;
	}

	//使用WriteProcessMemory 函数将DLL的路径写入到远程进程的内存空间
	DWORD dwReceiveSize;
	if(0 == WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void*)DllFullPath,wcslen(DllFullPath)*sizeof(wchar_t),NULL))
	{
		printf("WriteProcessMemory Fail,GetLastError: %d",GetLastError());
		return FALSE;
	}
	printf("WriteProcessMem Success!\r\n");

	//计算LoadLibrary 的入口地址
	PTHREAD_START_ROUTINE pfnStartAddr = NULL;

//#ifdef _UNICODE
	pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(::GetModuleHandle(TEXT("Kernel32")),"LoadLibraryW");
//#else
	//pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(::GetModuleHandle(TEXT("Kernel32")),"LoadLibraryA");
//#endif


	if(NULL == pfnStartAddr)
	{
		printf("GetProcAddress Fail,GetLastError: %d",GetLastError());
		return FALSE;
	}

	//启动远程线程 LoadLibraryA,通过远程线程调用创建新的线程
	DWORD dwThreadId=0;
	HANDLE hRemoteThread = CreateRemoteThread(hRemoteProcess,NULL,0,pfnStartAddr,pszLibFileRemote,0,NULL);
	if(hRemoteThread == NULL)
	{
		printf("注入线程失败,ErrorCode: %d\r\n",GetLastError());
		return FALSE;
	}
	printf("Inject Success ,ProcessId : %d\r\n",dwRemoteProcessId);
	
	WaitForSingleObject(hRemoteThread,INFINITE);
	GetExitCodeThread(hRemoteThread,&dwThreadId);
	//卸载 注入dll
	pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")),"FreeLibrary");
	hRemoteThread = CreateRemoteThread(hRemoteProcess,NULL,0,pfnStartAddr,(LPVOID)dwThreadId,0,NULL);
	CloseHandle(hRemoteThread);
	//释放远程进程控件
	VirtualFreeEx(hRemoteProcess,pszLibFileRemote,wcslen(DllFullPath)*sizeof(wchar_t)+1,MEM_DECOMMIT);
	//释放句柄
	CloseHandle(hRemoteProcess);
	return TRUE;
}

DWORD GetProcessId()
{
	DWORD Pid = -1;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); // 创建系统快照

	//创建系统快照
	PROCESSENTRY32 lPrs; //保存进程信息的结构
	ZeroMemory(&lPrs,sizeof(PROCESSENTRY32));

	lPrs.dwSize = sizeof(lPrs);
	wchar_t *targetFile = L"calc.exe";
	Process32First(hSnap,&lPrs); //取得系统快照中第一个进程信息
	if(wcsstr(targetFile,lPrs.szExeFile)) // 判断进程信息是否为explore.exe
	{
		Pid = lPrs.th32ProcessID;
		return Pid;
	}
	while(1)
	{
		ZeroMemory(&lPrs,sizeof(lPrs));
		lPrs.dwSize = sizeof(lPrs);
		if(!Process32Next(hSnap,&lPrs))
		{
			Pid=-1;
			break;
		}
		if(wcsstr(targetFile,lPrs.szExeFile))
		{
			Pid = lPrs.th32ProcessID;
			break;
		}
	}
	CloseHandle(hSnap);
	return Pid;

}

int _tmain(int argc, _TCHAR* argv[])
{
	wchar_t myFILE[MAX_PATH];
	GetCurrentDirectory(MAX_PATH,myFILE); //获取当前路径
	wcscat_s(myFILE,L"\\InjectDllExample.dll");
	InjectDll(myFILE,GetProcessId());

	return 0;
}

