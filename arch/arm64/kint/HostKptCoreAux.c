#include "kint.h"
u32 __hyp_text stxr_write_handler_asm(u32 wdata, u64 fault_ipa) // not working, stxr returns 1
{
	u32 flag;
	asm volatile("stxr_again%=:"
		     "ldxr %0, [%1]\n\t"
		     "stxr %w0, %2, [%1] \n\t"
		     "cbnz %w0, stxr_again%="
		     : "=&r"(flag)
		     : "r"(fault_ipa), "r"(wdata)
		     : "memory");
	return flag;
}

u64 __hyp_text fetch_instruction(void){
	u64 pc_counter, pc_va, inst, kimg_offset; 

	pc_counter = read_sysreg(elr_el2); 
	kimg_offset = get_kim_voff();
	inst = (u64)readl_relaxed((void *)__el2_va(pc_counter - kimg_offset));//hum maybe get a case for readq ? instruction might be longer somtimes. 

	return inst; 
}

u64 __hyp_text fetch_wdata(u64 hsr, u64 inst)
{	
	u64 wdata, pc_counter, pc_va; 
	u32 inst_stxr_op,inst_stp_op, Rt, ISV;

	ISV = (hsr & ESR_EL2_ISV_MASK) >> ESR_EL2_ISV_SHIFT;

	inst_stxr_op = inst & STXR_OPCODE_MASK;
	inst_stp_op = inst & STP_OPCODE_MASK;

	if (inst_stxr_op == STXR_OPCODE1 || inst_stxr_op == STXR_OPCODE2)
	{	
		Rt = (inst & STXR_Rt_MASK) >> STXR_Rt_SHIFT;  //Write content
		wdata = get_host_regs(Rt);
	}
	else if (inst_stp_op == STP_OPCODE)
	{
		wdata = 0x0;
	}
	else 
	{
		if (ISV == 1)
		{
			wdata = host_get_mmio_data(hsr);
		}
		else
		{
			print_string("\rUnable to fetch wdata with HSR ISV = 0\n");
			v_panic();
		}
	}
	return wdata; 
}

u64 __hyp_text fetch_rdata(u64 addr) //function doublon avec host handle read un bail comme ca 
{	
	u64 rdata, far_el2, fault_ipa; 

	far_el2 = read_sysreg_el2(far) & offset_mask;
	fault_ipa = addr | far_el2;
	rdata = (u64)readq_relaxed((void *)__el2_va(fault_ipa));

	return rdata; 
}

u64 __hyp_text translate_to_phys(u64 v_addr)
{
	u64 par,tmp, hpfar; 
	u32 fault, FST, PTW; 

	par = read_sysreg(par_el1);
	
	asm volatile("at s1e1r, %0" : : "r" (v_addr));
	
	isb();
	
	tmp = read_sysreg(par_el1);
	write_sysreg(par, par_el1);

	fault = tmp & 1UL; 
	if(fault)
	{	
		FST = (tmp & 0x7E) >> 1;  //Select bit [6-1] 
		PTW = (tmp & (1UL << 8)); 
		return INVALID64; 
	}
	else
	{
		hpfar = ((tmp >> 12) & ((1UL << 36) - 1)) << 12;
		return hpfar;
	}
}
