#include "kint.h"

void __hyp_text unmapping_handler(u64 rdata, u64 wdata, u64 inst, u64 fault_ipfn, u64 hsr) 
{	
	u32 ret, subcount, pfn, owner, subowner;

	pfn = phys_page(rdata) >> PAGE_SHIFT;

	owner = get_pfn_owner(pfn);
	subowner = get_pfn_subowner(fault_ipfn/PAGE_SIZE);

	if (owner != INVALID_MEM && owner != HOSTVISOR)
			v_panic();

	if (is_kpt(subowner))
	{	
		subcount = get_pfn_subcount(pfn);

		ret = handle_host_update(wdata, inst, fault_ipfn, hsr);
		set_pfn_el1_va(pfn, 0UL); 

		if (subcount != INVALID_MEM)
		{	
			if (subcount == 1)
			{
				handle_host_remove_page(pfn, owner);
			}
			set_pfn_subcount(pfn, subcount - 1); 
		}		
	}
	
}

void __hyp_text mapping_handler(u64 wdata, u64 inst, u64 fault_ipfn, u64 hsr)
{
	u64 w_pfn, pfn, kpt_index, offset; 
	u32 type, subowner, w_subowner, w_subcount, subcount, ret, kpt_shift;
	u32 owner;  

	w_pfn = phys_page(wdata) >> PAGE_SHIFT;

	pfn = fault_ipfn >> PAGE_SHIFT; 
	type = (wdata & TYPE_BIT_MASK) >> TYPE_BIT_SHIFT;
	offset = read_sysreg_el2(far) & offset_mask;

	
	kpt_index = get_pfn_kpt_index(pfn);
	owner = get_pfn_owner(w_pfn);
	subowner = get_pfn_subowner(pfn);
	subcount = get_pfn_subcount(pfn);
	w_subowner = get_pfn_subowner(w_pfn); 
	w_subcount = get_pfn_subcount(w_pfn);

	if (points_to_table(subowner, type))
	{	
		if (w_subowner == subowner + 1)
		{	
			ret = handle_host_update(wdata, inst, fault_ipfn, hsr);
			set_pfn_subcount(w_pfn, w_subcount + 1);

			kpt_shift = get_kpt_shift(subowner);
			kpt_index |= (offset / 8) << kpt_shift;						
			set_pfn_kpt_index(w_pfn, kpt_index);
			
		}
		else if (w_subowner) 
		{
			return; 
		}
		else
		{	
			ret = handle_host_new_page(w_pfn, subowner + 1, owner);
		}		
	}
	else if (points_to_leaf(subowner, type)) 
	{	
		handle_host_leaf_update(wdata, w_subowner, inst, fault_ipfn, hsr);
		set_pfn_subcount(w_pfn, w_subcount + 1);
		kpt_shift = get_kpt_shift(subowner);
		kpt_index |= (offset / 8) << kpt_shift;					
		set_pfn_el1_va(w_pfn, kpt_index);				
	}
}


void __hyp_text update_handler(u64 rdata, u64 wdata, u64 inst, u64 fault_ipfn, u64 hsr)
{
	u64 w_pfn, r_pfn, pfn; 
	u32 type, ret;
	u32 subowner;
	u32 w_subowner, r_subowner;
	u32 owner, r_owner;

	w_pfn = phys_page(wdata) >> PAGE_SHIFT;
	r_pfn = phys_page(rdata) >> PAGE_SHIFT; 	

	if(w_pfn != r_pfn)
		return; 

	pfn = fault_ipfn >> PAGE_SHIFT; 
	type = (wdata & TYPE_BIT_MASK) >> TYPE_BIT_SHIFT;

	owner = get_pfn_owner(w_pfn);
	r_owner = get_pfn_owner(r_pfn);
	subowner = get_pfn_subowner(pfn);
	w_subowner = get_pfn_subowner(w_pfn); 
	r_subowner = get_pfn_subowner(r_pfn); 

	if (r_owner != INVALID_MEM && r_owner != HOSTVISOR)
		v_panic();

	if (points_to_table(subowner, type))
	{
		if (w_subowner == subowner + 1) 
		{	
			ret = handle_host_update(wdata, inst, fault_ipfn, hsr);
		}
		else if (w_subowner)
		{
			return; 
		}
		else
		{	
			ret = handle_host_new_page(w_pfn, subowner + 1, owner);
		}		
	}
	else if (points_to_leaf(subowner, type))
	{
		handle_host_leaf_update(wdata, w_subowner, inst, fault_ipfn, hsr);
	}
	
}
