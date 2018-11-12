#include "stdafx.h"
#include "vm_r3.h"
BYTE *vm_opcode;
BYTE *vm_data;
BYTE * vm_enc;
BYTE vm_enc_flag[] = {0x07, 0xe7, 0x07, 0xe4, 0x01, 0x19, 0x03, 0x50, 0x07, 0xe4, 0x01, 0x20, 0x06, 0xb7, 0x07, 0xe4, 0x01, 0x22, 0x00, 0x28, 0x00, 0x2a, 0x02, 0x54, 0x07, 0xe4, 0x01, 0x1f, 0x02, 0x50, 0x05, 0xf2, 0x04, 0xcc, 0x07, 0xe4, 0x00, 0x28, 0x06, 0xb3, 0x05, 0xf8, 0x07, 0xe4, 0x00, 0x28, 0x06, 0xb2, 0x07, 0xe4, 0x04, 0xc0, 0x00, 0x2f, 0x05, 0xf8, 0x07, 0xe4, 0x04, 0xc0, 0x00, 0x28, 0x05, 0xf0, 0x07, 0xe3, 0x00, 0x2b, 0x04, 0xc4, 0x05, 0xf6, 0x03, 0x4c, 0x04, 0xc0, 0x07, 0xe4, 0x05, 0xf6, 0x06, 0xb3, 0x01, 0x19, 0x07, 0xe3, 0x05, 0xf7, 0x01, 0x1f, 0x07, 0xe4};

void deal_input(char *input) {
	vm_opcode = (BYTE *)malloc(strlen(input) / sizeof(char));
	vm_data = (BYTE *)malloc(strlen(input) / sizeof(char));
	for (unsigned int i = 0; i < strlen(input); i++) {
		vm_opcode[i] = input[i] & 0b111;
		//printf("%d, vm_opcode: %x\n", i, vm_opcode[i]);
		vm_data[i] = (input[i] & 0b1111000) >> 3;
		//printf("%d, vm_data: %x\n", i, vm_data[i]);
	}
}

void vm_interpreter(int order) {
	BYTE this_vm_opcode = vm_opcode[order];
	switch (this_vm_opcode)
	{
	case 0b000:
		vm_data[order] -= 0xde;
		break;
	case 0b001:
		vm_data[order] -= 0xed;
		break;
	case 0b010:
		vm_data[order] -= 0xba;
		break;
	case 0b011:
		vm_data[order] -= 0xbe;
		break;
	case 0b100:
		vm_data[order] ^= 0xca;
		break;
	case 0b101:
		vm_data[order] ^= 0xfe;
		break;
	case 0b110:
		vm_data[order] ^= 0xbe;
		break;
	case 0b111:
		vm_data[order] ^= 0xef;
		break;
	default:
		break;
	}
}

void vm_proc(char * input) {
	vm_enc = (BYTE *)malloc((strlen(input) / sizeof(char)) * 2);
	for (unsigned int i = 0; i < strlen(input); i++) {
		vm_interpreter(i);
		vm_enc[2 * i] = vm_opcode[i];
		vm_enc[2 * i + 1] = vm_data[i];
	}

}

BOOL vm_check_flag(char * input) {

	for (unsigned int i = 0; i < strlen(input)*2; i++) {
		if (vm_enc[i] != vm_enc_flag[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL Deal_flag_p1(char *param1) {
	BOOL check;

	printf("[Gurren]  %s\n\n", param1);
	deal_input(param1);
	vm_proc(param1);
	check = vm_check_flag(param1);
	return check;
}