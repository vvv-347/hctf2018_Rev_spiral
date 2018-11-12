#pragma once
#include "stdafx.h"

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PVOID Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef LSA_UNICODE_STRING UNICODE_STRING, *PUNICODE_STRING;

void show_error();

void Get_Procs();

int LoadDriver(char * szDrvName, char * szDrvPath);

void Deal_flag_p2(char *param1);

