#include "kint.h"

void __hyp_text stxr_write_handler(u64 wdata, u64 inst, u64 va)
{
	u64 inst_op, len;
	u32 Rs, flag;

	inst_op = inst & STXR_OPCODE_MASK;

	if (inst_op == STXR_OPCODE1) {
		len = 4;
	} else if (inst_op == STXR_OPCODE2) {
		len = 8;
	} else {
		print_string("\rUnknown stxr opcode\n");
		printhex_ul(inst_op);
		v_panic();
	}

	Rs = (inst & STXR_Rs_MASK) >> STXR_Rs_SHIFT; //flag

	flag = stxr_write_handler_asm(wdata, va);
	set_host_regs(Rs, flag);
}

void __hyp_text stp_write_handler(u64 inst, u64 va)
{
	u64 inst_op, inst_op2, wdata1, wdata2;
	u32 Rt, Rt2;

	inst_op = inst & STP_XZR_MASK;
	inst_op2 = inst & STP_OPCODE_MASK;

	if (inst_op == STP_XZR_INST) {
		handle_host_update_write(0x0, va, 8U);
		handle_host_update_write(0x0, va + 8U, 8U);
	} else if (inst_op2 == STP_OPCODE) {
		Rt = (inst & STP_Rt_MASK) >> STP_Rt_SHIFT;
		Rt2 = (inst & STP_Rt2_MASK) >> STP_Rt2_SHIFT;

		wdata1 = get_host_regs(Rt);
		wdata2 = get_host_regs(Rt2);

		/*
		 * FIXME: Required to check the written data, bypass the checking from now
		 * Possible data in register:
		 * 1. address of host kpt pool
		 * 2. address of &pool->free_area[]
		 */
		if (1) {
			handle_host_update_write(wdata1, va, 8U);
			handle_host_update_write(wdata2, va + 8U, 8U);
		} else {
			print_string("\rUnable to handle write data not in kpt pool\n");
			printhex_ul(inst_op);
			v_panic();
		}
	} else {
		print_string("\rUnknown stp opcode\n");
		printhex_ul(inst_op);
		v_panic();
	}

}

u64 __hyp_text handle_host_update_read(u64 fault_ipa, u32 len)
{
	void __iomem *base = (void *)fault_ipa;
	u64 rdata;
	if (len == 8U) {
		rdata = (u64)readq_relaxed(fault_ipa);
	} else if (len == 4U) {
		rdata = (u64)readl_relaxed(fault_ipa);
	} else if (len == 2U) {
		rdata = (u64)readw_relaxed(fault_ipa);
	} else if (len == 1U) {
		rdata = (u64)readb_relaxed(fault_ipa);
	} else {
		print_string("\rhandle read panic\n");
		printhex_ul(len);
		v_panic();
	}
	return rdata;
}

void __hyp_text handle_host_update_write(u64 write_content, u64 va, u32 len)
{
	void __iomem *base = (void *)va;

	if (len == 8U) {
#if 0
		pt_store(COREVISOR, fault_ipa, (u64)write_content);
#else
		writeq_relaxed((u64)write_content, base);
#endif

	} else if (len == 4U) {
		writel_relaxed((u32)write_content, base);
	} else if (len == 2U) {
		writew_relaxed((u16)write_content, base);
	} else if (len == 1U) {
		writeb_relaxed((u8)write_content, base);
	} else {
		print_string("\rHandle write size panic\n");
		printhex_ul(len);
		printhex_ul(write_content);
		v_panic();
	}
}

u32 __hyp_text get_kpt_shift(u32 subid)
{
	switch (subid) {
	case EL1_PGD:
		return PGD_SHIFT;
	case EL1_PUD:
		return PUD_SHIFT;
	case EL1_PMD:
		return PMD_SHIFT;
	case EL1_PTE:
		return PTE_SHIFT;
	}
}

u64 __hyp_text el1_va_to_el2(u64 el1_va)
{
	u64 ret, pa, offset, pfn;
	u64 target;
	void *ptr;

	offset = el1_va & offset_mask;
	pfn = translate_to_phys(el1_va);
	
	if(pfn != INVALID64)
	{
		pa = pfn | offset;
		pfn = pfn << PAGE_SHIFT;

		return __el2_va(pa);
	}
	else
		v_panic(); // This should not happen
}

u32 __hyp_text check_clear_pfn_host(u64 pfn)
{
	u64 pte, addr;
	u32 ret, subowner;

	acquire_lock_pt(HOSTVISOR);

	ret = 0U;
	pte = walk_npt(HOSTVISOR, pfn * PAGE_SIZE);
	if (pte != 0UL)
	{
		if (pte & PUD_MARK)
		{
			ret = 1U;
		}
		else if (pte & PMD_MARK)
		{
			addr = (pfn * PAGE_SIZE) & PMD_MASK;
			if (check_if_clear_range_host(addr, PMD_SIZE))
			{
				set_npt(HOSTVISOR, pfn * PAGE_SIZE, 2U, 0);
				kvm_tlb_flush_vmid_ipa_host(kint_pfn_pmd(pfn));
				ret = 2U;
			}
		}
		else
		{
			set_npt(HOSTVISOR, pfn * PAGE_SIZE, 3U, 0);
			kvm_tlb_flush_vmid_ipa_host(pfn * PAGE_SIZE);
			ret = 3U;
		}
    }

	release_lock_pt(HOSTVISOR);

	return ret;
}

u32 __hyp_text check_if_clear_range_host(u64 start, u64 size)
{
	 u64 addr, i;
	 u32 subowner;

	 for (i = 0; i < (size >> PAGE_SHIFT); i++)
	 {
		addr = start + i * PAGE_SIZE;
		subowner = get_pfn_subowner(addr >> PAGE_SHIFT);

		if (subowner != 0U)
		{
			return 0;
		}

	 }

	 return 1;
}
