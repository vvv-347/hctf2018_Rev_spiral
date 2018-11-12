#include "stdafx.h"
#include "load_drv.h"

// 申明ntdll中使用的函数
typedef DWORD(CALLBACK * RTLANSISTRINGTOUNICODESTRING)(PVOID, PVOID, DWORD);
RTLANSISTRINGTOUNICODESTRING RtlAnsiStringToUnicodeString;
typedef DWORD(CALLBACK * RTLFREEUNICODESTRING)(PVOID);
RTLFREEUNICODESTRING RtlFreeUnicodeString;
typedef DWORD(CALLBACK * ZWLOADDRIVER)(PVOID);
ZWLOADDRIVER ZwLoadDriver;

void show_error() {
	printf("Error Occurred\n");
}

void Get_Procs() {
	HMODULE hNtdll = NULL;
	hNtdll = LoadLibraryA("ntdll.dll");

	//从ntdll.dll里获取函数
	if (!hNtdll)
	{
		show_error();
		exit(-1);
	}

	RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)
		GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
	RtlFreeUnicodeString = (RTLFREEUNICODESTRING)
		GetProcAddress(hNtdll, "RtlFreeUnicodeString");
	ZwLoadDriver = (ZWLOADDRIVER)
		GetProcAddress(hNtdll, "ZwLoadDriver");
}

int LoadDriver(char * szDrvName, char * szDrvPath)
{

	char szSubKey[200], szDrvFullPath[256];
	LSA_UNICODE_STRING buf1;
	LSA_UNICODE_STRING buf2;
	int iBuffLen;
	HKEY hkResult;
	char Data[4] = { 1,0,0,0 };
	DWORD dwOK;
	iBuffLen = sprintf(szSubKey, "SYSTEM\\CurrentControlSet\\services\\%s", szDrvName);
	szSubKey[iBuffLen] = 0;
	dwOK = RegCreateKeyA(HKEY_LOCAL_MACHINE, szSubKey, &hkResult);
	if (dwOK != ERROR_SUCCESS) {
		show_error();
		return false;
	}
	// 写入注册表
	dwOK = RegSetValueExA(hkResult, "Type", 0, 4, (const unsigned char *)Data, 4);
	dwOK = RegSetValueExA(hkResult, "ErrorControl", 0, 4, (const unsigned char *)Data, 4);
	dwOK = RegSetValueExA(hkResult, "Start", 0, 4, (const unsigned char *)Data, 4);
	GetFullPathNameA(szDrvPath, 256, szDrvFullPath, NULL);
	iBuffLen = sprintf(szSubKey, "\\??\\%s", szDrvFullPath);
	szSubKey[iBuffLen] = 0;
	dwOK = RegSetValueExA(hkResult, "ImagePath", 0, 1, (const unsigned char *)szSubKey, iBuffLen);
	RegCloseKey(hkResult);
	iBuffLen = sprintf(szSubKey, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", szDrvName);
	szSubKey[iBuffLen] = 0;
	buf2.Buffer = (PVOID)szSubKey;
	buf2.Length = iBuffLen;
	RtlAnsiStringToUnicodeString(&buf1, &buf2, 1);
	// 加载驱动程序
	dwOK = ZwLoadDriver(&buf1);
	RtlFreeUnicodeString(&buf1);
	iBuffLen = sprintf(szSubKey, "%s%s\\Enum", "System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	//删除注册表项
	RegDeleteKeyA(HKEY_LOCAL_MACHINE, szSubKey);
	iBuffLen = sprintf(szSubKey, "%s%s\\Security", "System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	RegDeleteKeyA(HKEY_LOCAL_MACHINE, szSubKey);
	iBuffLen = sprintf(szSubKey, "%s%s", "System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	RegDeleteKeyA(HKEY_LOCAL_MACHINE, szSubKey);
	iBuffLen = sprintf(szSubKey, "\\\\.\\%s", szDrvName);
	szSubKey[iBuffLen] = 0;
	return true;
}

void Deal_flag_p2(char *param1) {
	char * Drv_path = param1;
	char Drv_name[32];
	strcpy(Drv_name, strrchr(Drv_path, '\\') + 1);
	Drv_name[strchr(Drv_name, '.') - Drv_name] = 0;

	Get_Procs();

	if (LoadDriver(Drv_name, Drv_path) == false) {
		show_error();
	}

	//printf("DONE\n");
}