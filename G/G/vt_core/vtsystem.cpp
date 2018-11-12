#include "stdafx.h"
#include "vtsystem.h"
#include "vtasm.h"
#include "exithandler.h"
#include "common.h"

VMX_CPU g_VMXCPU;


NTSTATUS AllocateVMXRegion()
{
	PVOID pVMXONRegion;
	PVOID pVMCSRegion;
	PVOID pHostEsp;

	pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool,0x1000,'vmon'); //4KB
	if (!pVMXONRegion)
	{
		//Log("ERROR:����VMXON�ڴ�����ʧ��!",0);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMXONRegion,0x1000);

	pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool,0x1000,'vmcs');
	if (!pVMCSRegion)
	{
		//Log("ERROR:����VMCS�ڴ�����ʧ��!",0);
		ExFreePoolWithTag(pVMXONRegion,0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMCSRegion,0x1000);

	pHostEsp = ExAllocatePoolWithTag(NonPagedPool,0x2000,'mini');
	if (!pHostEsp)
	{
		//Log("ERROR:������������������ʧ��!",0);
		ExFreePoolWithTag(pVMXONRegion,0x1000);
		ExFreePoolWithTag(pVMCSRegion,0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pHostEsp,0x2000);

	//Log("TIP:VMXON�ڴ������ַ",pVMXONRegion);
	//Log("TIP:VMCS�ڴ������ַ",pVMCSRegion);
	//Log("TIP:���������������ַ",pHostEsp);

	g_VMXCPU.pVMXONRegion = pVMXONRegion;
	g_VMXCPU.pVMXONRegion_PA = MmGetPhysicalAddress(pVMXONRegion);
	g_VMXCPU.pVMCSRegion = pVMCSRegion;
	g_VMXCPU.pVMCSRegion_PA = MmGetPhysicalAddress(pVMCSRegion);
	g_VMXCPU.pHostEsp = pHostEsp;
	return STATUS_SUCCESS;
}

void SetupVMXRegion()
{
	VMX_BASIC_MSR Msr;
	ULONG uRevId;
	_CR4 uCr4;
	_EFLAGS uEflags;

	RtlZeroMemory(&Msr,sizeof(Msr));

	*((PULONG)&Msr) = Asm_ReadMsr(MSR_IA32_VMX_BASIC);
	uRevId = Msr.RevId;

	*((PULONG)g_VMXCPU.pVMXONRegion) = uRevId;
	*((PULONG)g_VMXCPU.pVMCSRegion) = uRevId;

	//Log("TIP:VMX�汾����Ϣ",uRevId);

	*((PULONG)&uCr4) = Asm_GetCr4();
	uCr4.VMXE = 1;
	Asm_SetCr4(*((PULONG)&uCr4));

	Vmx_VmxOn(g_VMXCPU.pVMXONRegion_PA.LowPart,g_VMXCPU.pVMXONRegion_PA.HighPart);
	*((PULONG)&uEflags) = Asm_GetEflags();
	if (uEflags.CF != 0)
	{
		//Log("ERROR:VMXONָ�����ʧ��!",0);
		return;
	}
	//Log("SUCCESS:VMXONָ����óɹ�!",0);
}

extern "C" void SetupVMCS()
{
	_EFLAGS uEflags;
	ULONG GdtBase,IdtBase;
	SEGMENT_SELECTOR SegmentSelector;
	ULONG uCPUBase,uExceptionBitmap;

	Vmx_VmClear(g_VMXCPU.pVMCSRegion_PA.LowPart,g_VMXCPU.pVMCSRegion_PA.HighPart);
	*((PULONG)&uEflags) = Asm_GetEflags();
	if (uEflags.CF != 0 || uEflags.ZF != 0)
	{
		//Log("ERROR:VMCLEARָ�����ʧ��!",0);
		return;
	}
	//Log("SUCCESS:VMCLEARָ����óɹ�!",0);
	Vmx_VmPtrld(g_VMXCPU.pVMCSRegion_PA.LowPart,g_VMXCPU.pVMCSRegion_PA.HighPart);

	GdtBase = Asm_GetGdtBase();
	IdtBase = Asm_GetIdtBase();

	//
	// 1.Guest State Area
	//
	Log("Do the impossible",0);
	Vmx_VmWrite(GUEST_CR0,Asm_GetCr0());
	Vmx_VmWrite(GUEST_CR3,Asm_GetCr3());
	Vmx_VmWrite(GUEST_CR4,Asm_GetCr4());

	Vmx_VmWrite(GUEST_DR7,0x400);
	Vmx_VmWrite(GUEST_RFLAGS,Asm_GetEflags());

	FillGuestSelectorData(GdtBase,ES,Asm_GetEs());
	FillGuestSelectorData(GdtBase,FS,Asm_GetFs());
	FillGuestSelectorData(GdtBase,DS,Asm_GetDs());
	FillGuestSelectorData(GdtBase,CS,Asm_GetCs());
	FillGuestSelectorData(GdtBase,SS,Asm_GetSs());
	FillGuestSelectorData(GdtBase,GS,Asm_GetGs());
	FillGuestSelectorData(GdtBase,TR,Asm_GetTr());
	FillGuestSelectorData(GdtBase,LDTR,Asm_GetLdtr());

	Vmx_VmWrite(GUEST_GDTR_BASE,GdtBase);
	Vmx_VmWrite(GUEST_GDTR_LIMIT,Asm_GetGdtLimit());
	Vmx_VmWrite(GUEST_IDTR_BASE,IdtBase);
	Vmx_VmWrite(GUEST_IDTR_LIMIT,Asm_GetIdtLimit());

	Vmx_VmWrite(GUEST_IA32_DEBUGCTL,Asm_ReadMsr(MSR_IA32_DEBUGCTL)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH,Asm_ReadMsr(MSR_IA32_DEBUGCTL)>>32);

	Vmx_VmWrite(GUEST_SYSENTER_CS,Asm_ReadMsr(MSR_IA32_SYSENTER_CS)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_ESP,Asm_ReadMsr(MSR_IA32_SYSENTER_ESP)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_EIP,Asm_ReadMsr(MSR_IA32_SYSENTER_EIP)&0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(GUEST_RSP,Asm_GetGuestESP());
	Vmx_VmWrite(GUEST_RIP,Asm_GetGuestReturn());// ָ��vmlaunch�ͻ�������ڵ� ���������ÿͻ�������ִ�м��������Ĵ���

	Vmx_VmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	Vmx_VmWrite(GUEST_ACTIVITY_STATE, 0);
	Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);
	Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//
	// 2.Host State Area
	//
	Log("See the invisible",0);
	Vmx_VmWrite(HOST_CR0,Asm_GetCr0());
	Vmx_VmWrite(HOST_CR3,Asm_GetCr3());
	Vmx_VmWrite(HOST_CR4,Asm_GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR,Asm_GetEs() & 0xFFF8);
	Vmx_VmWrite(HOST_CS_SELECTOR,Asm_GetCs() & 0xFFF8);
	Vmx_VmWrite(HOST_DS_SELECTOR,Asm_GetDs() & 0xFFF8);
	Vmx_VmWrite(HOST_FS_SELECTOR,Asm_GetFs() & 0xFFF8);
	Vmx_VmWrite(HOST_GS_SELECTOR,Asm_GetGs() & 0xFFF8);
	Vmx_VmWrite(HOST_SS_SELECTOR,Asm_GetSs() & 0xFFF8);
	Vmx_VmWrite(HOST_TR_SELECTOR,Asm_GetTr() & 0xFFF8);

	InitializeSegmentSelector(&SegmentSelector,Asm_GetFs(),GdtBase);
	Vmx_VmWrite(HOST_FS_BASE,SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector,Asm_GetGs(),GdtBase);
	Vmx_VmWrite(HOST_GS_BASE,SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector,Asm_GetTr(),GdtBase);
	Vmx_VmWrite(HOST_TR_BASE,SegmentSelector.base);

	Vmx_VmWrite(HOST_GDTR_BASE,GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE,IdtBase);

	Vmx_VmWrite(HOST_IA32_SYSENTER_CS,Asm_ReadMsr(MSR_IA32_SYSENTER_CS)&0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP,Asm_ReadMsr(MSR_IA32_SYSENTER_ESP)&0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP,Asm_ReadMsr(MSR_IA32_SYSENTER_EIP)&0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP,((ULONG)g_VMXCPU.pHostEsp) + 0x1FFF);//8KB 0x2000
	Vmx_VmWrite(HOST_RIP,(ULONG)&Asm_VMMEntryPoint);//���ﶨ�����ǵ�VMM����������

	//
	// 3.��������п�����
	//
	Log("Touch the untouchable",0);
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL,VmxAdjustControls(0,MSR_IA32_VMX_PINBASED_CTLS));

	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MASK,0);
	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MATCH,0);
	Vmx_VmWrite(TSC_OFFSET,0);
	Vmx_VmWrite(TSC_OFFSET_HIGH,0);

	uCPUBase = VmxAdjustControls(0,MSR_IA32_VMX_PROCBASED_CTLS);

	//uCPUBase |= CPU_BASED_MOV_DR_EXITING; // ���ص��ԼĴ�������
	//uCPUBase |= CPU_BASED_USE_IO_BITMAPS; // ���ؼ��������Ϣ
	//uCPUBase |= CPU_BASED_ACTIVATE_MSR_BITMAP; // ����MSR����

	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL,uCPUBase);

	/*
	Vmx_VmWrite(IO_BITMAP_A,0);
	Vmx_VmWrite(IO_BITMAP_A_HIGH,0);
	Vmx_VmWrite(IO_BITMAP_B,0);
	Vmx_VmWrite(IO_BITMAP_B_HIGH,0);
	*/

	Vmx_VmWrite(CR3_TARGET_COUNT,0);
	Vmx_VmWrite(CR3_TARGET_VALUE0,0);
	Vmx_VmWrite(CR3_TARGET_VALUE1,0);
	Vmx_VmWrite(CR3_TARGET_VALUE2,0);
	Vmx_VmWrite(CR3_TARGET_VALUE3,0);

	//
	// 4.VMEntry���п�����
	//
	Log("Break the unbreakable",0);
	Vmx_VmWrite(VM_ENTRY_CONTROLS,VmxAdjustControls(0,MSR_IA32_VMX_ENTRY_CTLS));
	Vmx_VmWrite(VM_ENTRY_MSR_LOAD_COUNT,0);
	Vmx_VmWrite(VM_ENTRY_INTR_INFO_FIELD,0);


	//
	// 5.VMExit���п�����
	//
	Vmx_VmWrite(VM_EXIT_CONTROLS,VmxAdjustControls(VM_EXIT_ACK_INTR_ON_EXIT,MSR_IA32_VMX_EXIT_CTLS));
	Vmx_VmWrite(VM_EXIT_MSR_LOAD_COUNT,0);
	Vmx_VmWrite(VM_EXIT_MSR_STORE_COUNT,0);

	Vmx_VmLaunch();

	g_VMXCPU.bVTStartSuccess = FALSE;

	//Log("ERROR:VmLaunchָ�����ʧ��!",Vmx_VmRead(VM_INSTRUCTION_ERROR));
}

VOID RegVM_in_VMX(){
	//Log("����RegVm_in_VMX",0);
	Vmx_ReadMsr(0x176);
	Vmx_Invd(0x4433);
	Vmx_VmCall(0x30133403);
	Vmx_VmCall(0x3401cc01);
	Vmx_VmCall(0x36327a09);
	Vmx_VmCall(0x3300cc00);
	Vmx_VmCall(0x3015cc04);
	Vmx_VmCall(0x35289d07);
	Vmx_VmCall(0x3027cc06);
	Vmx_VmCall(0x3412cc03);
	Vmx_VmCall(0x3026cd06);
	Vmx_VmCall(0x34081f01);
	Vmx_VmCall(0x3311c302);
	Vmx_VmCall(0x3625cc05);
	Vmx_VmCall(0x3930cc07);
	Vmx_VmCall(0x37249405);
	Vmx_VmCall(0x34027200);
	Vmx_VmCall(0x39236b04);	
	Vmx_VmCall(0x34317308);
	Vmx_VmCall(0x3704cc02);
	Vmx_Invd(0x4434);
	Vmx_VmCall(0x38531f11);
	Vmx_VmCall(0x3435cc09);
	Vmx_VmCall(0x3842cc0a);
	Vmx_VmCall(0x3538cb0b);
	Vmx_VmCall(0x3750cc0d);
	Vmx_VmCall(0x3641710d);
	Vmx_VmCall(0x3855cc0f);
	Vmx_VmCall(0x3757cc10);
	Vmx_VmCall(0x3740000c);
	Vmx_VmCall(0x3147010f);
	Vmx_VmCall(0x3146cc0b);
	Vmx_VmCall(0x3743020e);
	Vmx_VmCall(0x36360f0a);
	Vmx_VmCall(0x3152cc0e);
	Vmx_VmCall(0x34549c12);
	Vmx_VmCall(0x34511110);
	Vmx_VmCall(0x3448cc0c);
	Vmx_VmCall(0x3633cc08);
	Vmx_Invd(0x4437);
	Vmx_VmCall(0x3080cc17);
	Vmx_VmCall(0x37742c16);
	Vmx_VmCall(0x3271cc14);
	Vmx_VmCall(0x3983cc19);
	Vmx_VmCall(0x3482bb17);
	Vmx_VmCall(0x3567bc15);
	Vmx_VmCall(0x3188041a);
	Vmx_VmCall(0x3965cc12);
	Vmx_VmCall(0x32869c19);
	Vmx_VmCall(0x3785cc1a);
	Vmx_VmCall(0x3281cc18);
	Vmx_VmCall(0x3262dc14);
	Vmx_VmCall(0x3573cc15);
	Vmx_VmCall(0x37566613);
	Vmx_VmCall(0x3161cc11);
	Vmx_VmCall(0x3266cc13);
	Vmx_VmCall(0x39844818);
	Vmx_VmCall(0x3777cc16);
	Vmx_VmCall(0xffeedead);
}

NTSTATUS StartVirtualTechnology()
{
	NTSTATUS status = STATUS_SUCCESS;
	if (!IsVTEnabled())
		return STATUS_NOT_SUPPORTED;

	status = AllocateVMXRegion();
	if (!NT_SUCCESS(status))
	{
		//Log("ERROR:VMX�ڴ���������ʧ��",0);
		return STATUS_UNSUCCESSFUL;
	}
	//Log("SUCCESS:VMX�ڴ���������ɹ�!",0);

	SetupVMXRegion();
	g_VMXCPU.bVTStartSuccess = TRUE;

	Asm_SetupVMCS();
	RegVM_in_VMX();

	if (g_VMXCPU.bVTStartSuccess)
	{
		Log("-> DONE",0);
		//Log("SUCCESS:�������CPU������VMXģʽ.",0);
		return STATUS_SUCCESS;
	}
	else Log("-> Error",0);
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS StopVirtualTechnology()
{
	_CR4 uCr4;
	if(g_VMXCPU.bVTStartSuccess)
	{
		Vmx_VmCall(0xddea7a94); //
		
		*((PULONG)&uCr4) = Asm_GetCr4();
		uCr4.VMXE = 0;
		Asm_SetCr4(*((PULONG)&uCr4));

		ExFreePoolWithTag(g_VMXCPU.pVMXONRegion,'vmon');
		ExFreePoolWithTag(g_VMXCPU.pVMCSRegion,'vmcs');
		ExFreePoolWithTag(g_VMXCPU.pHostEsp,'mini');

		Log("<- DONE",0);
		//Log("SUCCESS:�������CPU�˳���VMXģʽ.",0);
	}

	return STATUS_SUCCESS;
}

BOOLEAN IsVTEnabled()
{
	ULONG uRet_EAX,uRet_ECX,uRet_EDX,uRet_EBX;
	_CPUID_ECX uCPUID;
	_CR0 uCr0;
	_CR4 uCr4;
	IA32_FEATURE_CONTROL_MSR msr;
	//1. CPUID
	Asm_CPUID(1,&uRet_EAX,&uRet_EBX,&uRet_ECX,&uRet_EDX);
	*((PULONG)&uCPUID) = uRet_ECX;

	if (uCPUID.VMX != 1)
	{
		//Log("ERROR:���CPU��֧��VT!",0);
		return FALSE;
	}

	// 2. CR0 CR4
	*((PULONG)&uCr0) = Asm_GetCr0();
	*((PULONG)&uCr4) = Asm_GetCr4();

	if (uCr0.PE != 1||uCr0.PG!=1||uCr0.NE!=1)
	{
		//Log("ERROR:���CPUû�п���VT!",0);
		return FALSE;
	}

	if (uCr4.VMXE == 1)
	{
		//Log("ERROR:���CPU�Ѿ�������VT!",0);
		//Log("�����Ǳ�������Ѿ�ռ����VT�������ر�������ܿ�����",0);
		return FALSE;
	}

	// 3. MSR
	*((PULONG)&msr) = Asm_ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock!=1)
	{
		//Log("ERROR:VTָ��δ������!",0);
		return FALSE;
	}
	//Log("SUCCESS:���CPU֧��VT!",0);
	return TRUE;
}