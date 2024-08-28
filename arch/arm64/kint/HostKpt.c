#include "kint.h"

void __hyp_text host_kpt_handler(u64 addr, u32 hsr)
{	
	u64 wdata, rdata, inst, pfn, pc_counter;
	u32 subid, ret;

	pfn = addr / PAGE_SIZE;
	acquire_lock_s2page();

	subid = get_pfn_subowner(pfn);
	
	if (is_kpt(subid))
	{
		inst = fetch_instruction(); 
		wdata = fetch_wdata(hsr, inst);
		rdata = fetch_rdata(addr); 

		if (wdata == 0)
		{
			unmapping_handler(rdata, wdata, inst, addr, hsr);
		} 
		else if (rdata == 0 && wdata !=0) 
		{
			mapping_handler(wdata, inst, addr, hsr);
		} 
		else if (rdata != 0 && wdata != 0) 
		{
			update_handler(rdata, wdata, inst, addr, hsr);
		}
	}
	else if (subid >= EL1_MOD_txt && subid <= EL1_MOD_ro)
	{
		wdata = fetch_wdata(hsr, inst);
		rdata = fetch_rdata(addr); 
		mod_reloc_handler(wdata, rdata, inst, addr, hsr); 
	}
	else if (subid == EL0_PGD)
	{
		inst = fetch_instruction();
		wdata = fetch_wdata(hsr, inst);
		if (wdata)
			wdata = wdata | DCPTR_EL1_PXN_TABLE_MASK;
		ret = handle_host_update(wdata, inst, addr, hsr);
	}
	else if (check_host_s1pgtable(addr))
	{
		/*
		 * Currently, we only handle the host kernel page
		 * table that is allocated from the 2MB-aligned
		 * stage 1 page pool. The allocator is implemented
		 * at arch/arm64/kvm/pt_alloc.c for now.
		 *
		 * As of now, the only situation that causes a
		 * trap (no subid) to EL2 due to a permission
		 * fault is when 'stp' instruction is accessed.
		 */

		inst = fetch_instruction();
		wdata = fetch_wdata(hsr, inst);
		ret = handle_host_update(wdata, inst, addr, hsr);
	}
	else
	{
		v_panic();
	}

	release_lock_s2page(); 

	return 0;
}
