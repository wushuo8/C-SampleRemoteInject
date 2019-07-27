// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <malloc.h>
#include <stdlib.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	wchar_t *szProcessId = (wchar_t*)malloc(10*sizeof(wchar_t));
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL,L"远程注入提示",L"RemoteDLL",MB_OK);
		break;
	default:
		return TRUE;
	//case DLL_THREAD_ATTACH:
	//case DLL_THREAD_DETACH:
	//case DLL_PROCESS_DETACH:
		//break;
	}
	return TRUE;
}