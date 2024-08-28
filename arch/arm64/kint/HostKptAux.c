#include "kint.h"

u32 __hyp_text handle_host_update(u64 wdata, u32 inst,  u64 fault_ipfn, u32 hsr)
{	
	u32 inst_stxr_op, inst_stp_op;
	u64 va, subowner;
	u64 ISV, far_el2;
	u32 len;
	u64 rdata, pc_counter, fault_ipa;

	len = host_dabt_get_as(hsr);

	far_el2 = read_sysreg_el2(far) & offset_mask; //tranform into function 
	fault_ipa = fault_ipfn | far_el2;
	subowner = get_pfn_subowner(fault_ipfn >> PAGE_SHIFT);
	va = __el2_va(fault_ipa);

	inst_stxr_op = inst & STXR_OPCODE_MASK; //transform into function
	inst_stp_op = inst & STP_OPCODE_MASK;
	ISV = (hsr & ESR_EL2_ISV_MASK) >> ESR_EL2_ISV_SHIFT; // tranform insto function 

	acquire_lock_host_kpt();
	
	if(inst_stxr_op == STXR_OPCODE1 || inst_stxr_op == STXR_OPCODE2)
	{	
		stxr_write_handler(wdata, inst, va);
		host_skip_instr();
		release_lock_host_kpt();
        return 0;
	}
	else if (inst_stp_op == STP_OPCODE && check_host_s1pgtable(fault_ipfn)
					&& subowner == NONE)
	{
		stp_write_handler(inst, va);
		host_skip_instr();
		release_lock_host_kpt();
		return 0;
	}
	else 
	{
		if (ISV == 1)
		{	
			handle_host_update_write(wdata, va, len);
			host_skip_instr();
			release_lock_host_kpt();
			return 0;
		}
		else
		{
			print_string("\rError write emulation HSR ISV = 0\n");
			pc_counter = read_sysreg(elr_el2);
			printhex_ul(pc_counter);
			release_lock_host_kpt();
			v_panic();
			return 1;
		}
	}
	
}

void __hyp_text handle_host_remove_page(u64 pfn, u32 vmid)
{
	u64 perm, new_pte;
	u32 ret, subowner;

	if (vmid == HOSTVISOR) // Check if this check is really necessary 
	{	
		subowner = get_pfn_subowner(pfn);

		set_pfn_subowner(pfn, 0); 
		clear_phys_page(pfn);
		__flush_dcache_area(__el2_va(pfn << PAGE_SHIFT), PAGE_SIZE);


		/* Not refund pages if it is protected module */
		if (!is_mod(subowner))
		{
			ret = check_clear_pfn_host(pfn);
			if (ret == 2U)
			{
				perm = pgprot_val(SECT_S2_KERNEL);
				new_pte = kint_mk_pmd(pfn, perm);
				mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 2U, new_pte);
			}
			else if (ret == 3U)
			{
				perm = pgprot_val(PAGE_S2_KERNEL);
				new_pte = (pfn * PAGE_SIZE) | perm;
				mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 3U, new_pte);
			}
		}
	}
}

u32 __hyp_text handle_host_new_page(u64 pfn, u32 subid, u32 vmid)
{
	u64 perm, new_pte;
	u32 owner; 

	if (vmid == HOSTVISOR)
	{	
		/// note : remap or map at stage2 page table is the same. maybe flush tlb only when we remap
		u32 ret = check_clear_pfn_host(pfn);

		if(ret)
		{
			if(ret == 1U)
			{
				v_panic();
			}
			else
			{
				if (check_host_s1pgtable(pfn * PAGE_SIZE))
				{
					perm = pgprot_val(SECT_S2);
					new_pte = kint_mk_pmd(pfn, perm);
					mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 2U, new_pte);
				}
				else
				{
					perm = pgprot_val(PAGE_S2);
					new_pte = pfn * PAGE_SIZE | perm;
					mmap_s2pt(HOSTVISOR, pfn * PAGE_SIZE, 3U, new_pte);
				}
			}
		}

		clear_phys_page(pfn);
		__flush_dcache_area(__el2_va(pfn << PAGE_SHIFT), PAGE_SIZE);
		set_pfn_subowner(pfn, subid);
	}
}

 void __hyp_text handle_host_leaf_update(u64 wdata, u32 w_subowner, u32 inst,  u64 fault_ipfn, u32 hsr)
 {	
	u32 ret;
	u64 w_pfn, pxn;

//Enable Dynamic EL1 pt PXN

	if(w_subowner != EL1_KCODE && w_subowner != EL1_MOD_txt && !(wdata & DCPTR_EL1_PXN_BLOCK_MASK))
	{	
		wdata = wdata | DCPTR_EL1_PXN_BLOCK_MASK; 
	}

	ret = handle_host_update(wdata, inst, fault_ipfn, hsr);
 }
