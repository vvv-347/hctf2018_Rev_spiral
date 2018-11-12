#pragma once

GUEST_REGS g_GuestRegs;

ULONG Board_Init = FALSE;
ULONG dst_board[] = { 7, 206, 89, 35, 9, 5, 3, 1, 6, 2, 6, 5, 125, 86, 240, 40, 4, 89, 77, 77, 75, 83, 9, 1, 15, 87, 8, 211, 56, 111, 665, 225, 54, 2, 118, 855, 106, 170, 884, 420, 93, 86, 87, 7, 127, 8, 168, 176, 9, 50, 2, 6, 1123, 1129, 5, 198, 2, 37, 104, 51, 50, 103, 1, 113, 1, 1287, 99, 8, 6, 163, 1525, 6, 49, 952, 101, 512, 40, 87, 1, 165, 9 };
PULONG dst_addr = dst_board;

ULONG input_d[64] = { 95, 82, 64, 119, 33, 95, 114, 48, 87, 33, 95, 70, 49, 103, 55, 84, 95, 89, 72, 53, 95, 80, 48, 87, 53, 82, 33, };
ULONG input_d_rev[64] = { 33, 82, 53, 87, 48, 80, 95, 53, 72, 89, 95, 84, 55, 103, 49, 70, 95, 33, 87, 48, 114, 95, 33, 119, 64, 82, 95, };
PULONG src_addr;

ULONG r_vm_opcode[10] = {0xa3, 0xf9, 0x77, 0xa6, 0xc1, 0xc7, 0x4e, 0xd1, 0x51, 0xff};
ULONG fake_xor_opcode_once[10] = { 0x93, 0xc8, 0x45, 0x95, 0xf5, 0xf2, 0x78, 0xe6, 0x69, 0xc6 };
ULONG xor_opcode_once[10] = { 0x90, 0xcd, 0x40, 0x96, 0xf0, 0xfe, 0x78, 0xe3, 0x64, 0xc7 };

ULONG region_1[] = { 0x00, 0x01, 0x02, 0x03, 0x12, 0x13, 0x14, 0x23, 0x24 };
ULONG region_2[] = { 0x04, 0x05, 0x06, 0x07, 0x08, 0x15, 0x17, 0x27, 0x37 };
ULONG region_3[] = { 0x10, 0x20, 0x30, 0x31, 0x40, 0x50, 0x51, 0x52, 0x60 };
ULONG region_4[] = { 0x11, 0x21, 0x22, 0x32, 0x33, 0x34, 0x35, 0x41, 0x42 };
ULONG region_5[] = { 0x16, 0x25, 0x26, 0x36, 0x43, 0x44, 0x45, 0x46, 0x54 };
ULONG region_6[] = { 0x18, 0x28, 0x38, 0x48, 0x58, 0x67, 0x68, 0x78, 0x88 };
ULONG region_7[] = { 0x47, 0x55, 0x56, 0x57, 0x65, 0x66, 0x76, 0x77, 0x87 };
ULONG region_8[] = { 0x53, 0x62, 0x63, 0x64, 0x72, 0x74, 0x75, 0x85, 0x86 };
ULONG region_9[] = { 0x61, 0x70, 0x71, 0x73, 0x80, 0x81, 0x82, 0x83, 0x84 };
PULONG all_region[] = {region_1, region_2, region_3, region_4, region_5, region_6, region_7, region_8, region_9};

void show_r_vm_opcode(){
	//Log("Show r_vm_opcode now",0);
	UCHAR i=0;
	for(i=0;i<10;i++){
		//Log("opcode: ", r_vm_opcode[i]);
	}
}

void show_byte_value_and_pos(ULONG value, ULONG pos){
	//Log("Enc pos",pos);
	//Log("Enc value", value);

}

ULONG check_in_num(ULONG cmp_v)
{
	ULONG flag = 1;
	ULONG stand[] = { 1, 2, 3, 4, 5, 6,7, 8, 9 };
	for (ULONG i = 0; i < 9; i++) {
		if (cmp_v != stand[i])
			continue;
		else {
			return flag;
		}
	}
	return 0;
}

ULONG check_enc_core(ULONG region_order)
{
	ULONG cmp_tmp[9];
	ULONG flag = 1;
	for (ULONG i = 0;  i < 9; i++) {
		ULONG dst_pos = ((all_region[region_order][i] >> 4) & 0x0f) * 9 + (all_region[region_order][i] & 0x0f);
		cmp_tmp[i] = dst_board[dst_pos];
		if (check_in_num(cmp_tmp[i]) == 0) {
			return 0;
		}
	}
	for (ULONG i_1 = 0; i_1 < 8; i_1++) {
		for (ULONG j_1 = i_1+1; j_1 < 9; j_1++) {
			if (cmp_tmp[i_1] == cmp_tmp[j_1]) {
				flag = 0;
				break;
			}
		}
	}
	return flag;
}

void check_enc()
{
	ULONG flag = 1;
	for (ULONG i = 0; i < 9; i++) {
		flag &= check_enc_core(1);
	}
	if (flag == 1) {
		//Log("---> DONE", 0);
	}
}

void HandleCPUID()
{
	//Log("VMM_handler_CPUID",g_GuestRegs.eax);
	if (g_GuestRegs.eax == 0xDEADBEEF)
	{
		//Log("here am i",0);
		UCHAR i;
		for(i=0; i<10; i++){
			r_vm_opcode[i] ^= xor_opcode_once[i]; 
		}
		
	}
	else if(g_GuestRegs.eax == 0xCAFEBABE)
	{
		//Log("here am i ERRoR",0);
		UCHAR j;
		for(j=0; j<10; j++){
			r_vm_opcode[j] ^= fake_xor_opcode_once[j]; 
		}
	}
	else Asm_CPUID(g_GuestRegs.eax,&g_GuestRegs.eax,&g_GuestRegs.ebx,&g_GuestRegs.ecx,&g_GuestRegs.edx);
}


void HandleInvd()
{
	//Log("VMM_handler_Invd",g_GuestRegs.eax);
	if(g_GuestRegs.eax == 0x4433){
		ULONG tmp_0;
		UCHAR i;
		for(i=0; i<5; i++){
			tmp_0 = r_vm_opcode[2*i];
			r_vm_opcode[2*i] = r_vm_opcode[2*i+1];
			r_vm_opcode[2*i+1] = tmp_0;
		}
		//show_r_vm_opcode();
	}
	else if(g_GuestRegs.eax == 0x4434){
		ULONG tmp_1;
		UCHAR j;
		tmp_1 = r_vm_opcode[0];
		for(j=0; j<9; j++){
			r_vm_opcode[j] = r_vm_opcode[j+1];
		}
		r_vm_opcode[9] = tmp_1;
		//show_r_vm_opcode();
	}
	else if(g_GuestRegs.eax == 0x4437){
		ULONG tmp_2;
		UCHAR k;
		UCHAR init_pos = 7;
		UCHAR init_pos_2 = 3;
		tmp_2 = r_vm_opcode[7];
		for(k=0; k<3;k++){
			r_vm_opcode[init_pos+k] = r_vm_opcode[init_pos-k-1];
			if(k!=2){
				r_vm_opcode[init_pos-k-1] = r_vm_opcode[init_pos+k+1];
			}
			else{
				r_vm_opcode[init_pos-k-1] = r_vm_opcode[3];
			}
		}
		for(k=0;k<1;k++){
			r_vm_opcode[init_pos_2] = r_vm_opcode[init_pos_2-k-2];
			r_vm_opcode[init_pos_2-k-2] = r_vm_opcode[init_pos_2-k-1];
		}
		r_vm_opcode[init_pos_2-k-1] = tmp_2;
		//show_r_vm_opcode();
	}
	else
		Asm_Invd();
}

void HandleVmCall() {
	ULONG vm_code = ((g_GuestRegs.eax) >> 24) & 0xff;
	ULONG dst_pos_orig = ((g_GuestRegs.eax) >> 16) & 0xff;
	ULONG src_spec = ((g_GuestRegs.eax) >> 8) & 0xff;
	ULONG src_pos = (g_GuestRegs.eax) & 0xff;
	ULONG JmpEIP;

	ULONG dst_pos = ((dst_pos_orig >> 4) & 0x0f) * 9 + (dst_pos_orig & 0x0f);
	if (src_spec == 0xcc) {
		src_addr = input_d;
	}
	else {
		src_addr = input_d_rev;
	}
	if (vm_code == r_vm_opcode[0]) {
		//Log("MOV: value of eax", vm_code);
		dst_addr[dst_pos] = src_addr[src_pos];
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[1]) {
		//Log("ADD: value of eax", vm_code);
		dst_addr[dst_pos] += src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[2]) {
		//Log("SUB: value of eax", vm_code);
		dst_addr[dst_pos] -= src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[3]) {

		//Log("DIV: value of eax", vm_code);
		dst_addr[dst_pos] /= src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[4]) {
		//Log("MUL: value of eax", vm_code);
		dst_addr[dst_pos] *= src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[5]) {
		//Log("XOR: value of eax", vm_code);
		dst_addr[dst_pos] ^= src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[6]) {
		//Log("MIX: value of eax", vm_code);
		ULONG num = src_addr[src_pos];
		num += src_addr[src_pos - 1];
		num -= src_addr[src_pos + 1];
		dst_addr[dst_pos] ^= num;
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);

	}
	else if (vm_code == r_vm_opcode[7]) {
		//Log("SHIFT: value of eax", vm_code);
		ULONG num3 = src_addr[src_pos] << 4;
		dst_addr[dst_pos] ^= num3;
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[8]) {
		//Log("OR: value of eax", vm_code);
		dst_addr[dst_pos] |= src_addr[src_pos];
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == r_vm_opcode[9]) {
		//Log("MIX2: value of eax", vm_code);
		ULONG num2 = src_addr[src_pos];
		num2 += src_addr[src_pos - 2];
		num2 -= src_addr[src_pos + 2];
		num2 ^= src_addr[src_pos - 1];
		num2 ^= src_addr[src_pos + 1];
		dst_addr[dst_pos] ^= num2;
		dst_addr[dst_pos] &= 0xff;
		show_byte_value_and_pos(dst_addr[dst_pos], dst_pos);
	}
	else if (vm_code == 0xdd) {
		//Log("Stop_VT: value of eax", vm_code);
		JmpEIP = g_GuestRegs.eip + Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);
		Vmx_VmxOff();
		Asm_AfterVMXOff(g_GuestRegs.esp, JmpEIP);
	}
	else if (vm_code == 0xff) {
		check_enc();
	}
	else {
		Log("DEFAULT: value of eax", vm_code);
	}
}

void HandleMsrRead()
{
	//Log("VMM_handler_ReadMsr", g_GuestRegs.eax);
	if (g_GuestRegs.eax == 0x174) 
	{
		ULONG tmp_1 = dst_board[8 * 9 + 8];
		ULONG tmp_2 = dst_board[0 * 9 + 8];
		ULONG i, j;

		for ( i = 8; i >0 ; i--) {
			dst_board[i * 9 + i] = dst_board[(i - 1) * 9 + (i-1)];
		}
		dst_board[i * 9 + i] = tmp_1;

		for (j = 1; j < 9; j++) {
			dst_board[8 * j] = dst_board[8 * (j + 1)];
		}
		dst_board[8 * j] = tmp_2;
	}
	else if (g_GuestRegs.eax == 0x176)
	{
		ULONG tmp_3 = dst_board[8 * 9 + 4];
		ULONG tmp_4 = dst_board[4 * 9 + 0];

		for (ULONG i_1 = 8; i_1 > 0; i_1--) {
			dst_board[i_1 * 9 + 4] = dst_board[(i_1-1) * 9 + 4];
		}
		dst_board[4] = tmp_3;

		for (ULONG i_2 = 0; i_2 < 8; i_2++) {
			dst_board[4 * 9 + i_2] = dst_board[4 * 9 + i_2 + 1];
		}
		dst_board[4 * 9 + 8] = tmp_4;
	}
	else
	{
		switch (g_GuestRegs.ecx)
		{
		case MSR_IA32_SYSENTER_CS:
			{
				g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_CS);
				break;
			}
		case MSR_IA32_SYSENTER_ESP:
			{
				g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_ESP);
				break;
			}
		case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
			{
				g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_EIP);
				break;
			}
		default:
			g_GuestRegs.eax = Asm_ReadMsr(g_GuestRegs.ecx);
		}
	}
}

void HandleMsrWrite()
{
	switch(g_GuestRegs.ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		{
			Vmx_VmWrite(GUEST_SYSENTER_CS,g_GuestRegs.eax);
			break;
		}
	case MSR_IA32_SYSENTER_ESP:
		{
			Vmx_VmWrite(GUEST_SYSENTER_ESP,g_GuestRegs.eax);
			break;
		}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
		{
			Vmx_VmWrite(GUEST_SYSENTER_EIP,g_GuestRegs.eax);
			break;
		}
	default:
		Asm_WriteMsr(g_GuestRegs.ecx,g_GuestRegs.eax,g_GuestRegs.edx);
	}
}

void HandleCrAccess()
{
	ULONG		movcrControlRegister;
	ULONG		movcrAccessType;
	ULONG		movcrOperandType;
	ULONG		movcrGeneralPurposeRegister;
	ULONG		movcrLMSWSourceData;
	ULONG		ExitQualification;

	ExitQualification = Vmx_VmRead(EXIT_QUALIFICATION) ;
	movcrControlRegister = ( ExitQualification & 0x0000000F );
	movcrAccessType = ( ( ExitQualification & 0x00000030 ) >> 4 );
	movcrOperandType = ( ( ExitQualification & 0x00000040 ) >> 6 );
	movcrGeneralPurposeRegister = ( ( ExitQualification & 0x00000F00 ) >> 8 );

	//	Control Register Access (CR3 <-- reg32)
	//
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.eax );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ecx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.edx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ebx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.esp );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ebp );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.esi );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.edi );
	}
	//	Control Register Access (reg32 <-- CR3)
	//
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
	{
		g_GuestRegs.eax = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
	{
		g_GuestRegs.ecx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
	{
		g_GuestRegs.edx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
	{
		g_GuestRegs.ebx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
	{
		g_GuestRegs.esp = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
	{
		g_GuestRegs.ebp = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
	{
		g_GuestRegs.esi = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
	{
		g_GuestRegs.edi = g_GuestRegs.cr3;
	}  
}

void HandleBoardInit()
{
	ULONG k;
	ULONG tmp_3 = dst_board[4 * 9 + 4];
	for (k = 0; k < 4; k++) {
		dst_board[(k + 5) * 8] = dst_board[(k + 5) * 8 - 1];
		for (ULONG k_1 = 0; k_1 < 2 * k + 1; k_1++) {
			dst_board[(k + 4 - (k_1)) * 9 + (3 - k)] = dst_board[(k + 4 - (k_1 + 1)) * 9 + (3 - k)];
		}
		for (ULONG k_2 = 0; k_2 < 2 * k + 2; k_2++) {
			dst_board[(3 - k) * 9 + (3 - k) + k_2] = dst_board[(3 - k) * 9 + (3 - k) + (k_2 + 1)];
		}
		for (ULONG k_3 = 0; k_3 < 2 * k + 2; k_3++) {
			dst_board[(3 - k + k_3) * 9 + (5 + k)] = dst_board[(3 - k + (k_3 + 1)) * 9 + (5 + k)];
		}
		for (ULONG k_4 = 0; k_4 < 2 * k + 2; k_4++) {
			dst_board[(5 + k) * 9 + (5 + k) - (k_4)] = dst_board[(5 + k) * 9 + (5 + k) - (k_4 + 1)];
		}
	}
	dst_board[8 * 9] = tmp_3;
}

extern "C" ULONG GetGuestRegsAddress()
{
	return (ULONG)&g_GuestRegs;
}

extern "C" void VMMEntryPoint()
{
	ULONG ExitReason;
	ULONG ExitInstructionLength;
	ULONG GuestResumeEIP;

	ExitReason = Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength = Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);

	g_GuestRegs.esp = Vmx_VmRead(GUEST_RSP);
	g_GuestRegs.eip = Vmx_VmRead(GUEST_RIP);
	g_GuestRegs.cr3 = Vmx_VmRead(GUEST_CR3);
	if(Board_Init == FALSE)
	{
		//Log("VMM_handler_board_init",0);
		HandleBoardInit();
		Board_Init = TRUE;
	}

	switch(ExitReason)
	{
	case EXIT_REASON_CPUID:
		{
			HandleCPUID();
			break;
		}
	case EXIT_REASON_INVD:
		{
			HandleInvd();
			break;
		}
	case EXIT_REASON_VMCALL:
		{
			HandleVmCall();
			break;
		}
	case EXIT_REASON_MSR_READ:
		{
			HandleMsrRead();
			break;
		}
	case EXIT_REASON_MSR_WRITE:
		{
			HandleMsrWrite();
			break;
		}
	case EXIT_REASON_CR_ACCESS:
		{
			HandleCrAccess();
			break;
		}
	default:
		break;
	}

Resume:
	GuestResumeEIP = g_GuestRegs.eip+ExitInstructionLength;
	Vmx_VmWrite(GUEST_RIP,GuestResumeEIP);
	Vmx_VmWrite(GUEST_RSP,g_GuestRegs.esp);
}