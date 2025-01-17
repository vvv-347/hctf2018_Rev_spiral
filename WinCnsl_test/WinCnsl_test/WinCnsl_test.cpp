#include "stdafx.h"
#include "load_drv.h"
#include "set_driver.h"
#include "vm_r3.h"
const char * drv_name = "\\Spiral_core.sys";
char flag_internal[128];
BYTE flag_p1[46] = { 0, };
BYTE flag_p2[27] = { 0, };

void say_bye(int error_code) {
	printf("Good bye Kamina: 0x%X\n", error_code);
}

bool get_os_version() {
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;

	dwVersion = GetVersion();

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	if (dwMajorVersion == 5 && dwMinorVersion == 1) {
		return true;
	}
	return false;
}

void set_flag_parts(char * full_flag) {
	for (int i = 0; i < 46; i++) {
		flag_p1[i] = full_flag[i];
	}
	for (int j = 0; j < 27; j++) {
		flag_p2[j] = full_flag[46 + j];
	}
	//printf("flag_p1: [%s]\n", flag_p1);
	//printf("flag_p2: [%s]\n", flag_p2);
}

int modify_input(char * input_s) {
	strcpy(flag_internal, strstr(input_s , "hctf{") + 5);
	flag_internal[strrchr(flag_internal, '}')-flag_internal] = 0;
	//printf("%s\n", flag_internal);
	//printf("%d\n", strlen(flag_internal));
	return strlen(flag_internal);

}

int main(int argc, char *argv[])
{
	printf("[------------Requiem aeternam, Dona eis, Domine------------]\n");
	if (get_os_version() == false) {
		say_bye(0x7f);
		return 1;
	}
	if (argc != 2 || modify_input(argv[1]) != 73) {
		say_bye(0x7e);
		return 1;
	}
	set_flag_parts(flag_internal);

	if (Deal_flag_p1((char*)flag_p1) != false) {
		printf("[---------Second verse dedicates to the real peeps---------]\n");
		Deal_set_driver((char *)flag_p2);
		Deal_flag_p2((char *)drv_name);
	}
	else {
		say_bye(0x7d);
	}
	
	return 0;
}
