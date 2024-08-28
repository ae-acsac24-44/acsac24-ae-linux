#include "kint.h"

u32 __hyp_text get_pfn_subowner(u64 pfn)
{
       u64 index;
       u32 ret;

       index = get_s2_page_index(pfn * PAGE_SIZE);
       if (index != INVALID64)
       {
               ret = get_s2_page_subid(index);
       }
       else
       {
               ret = INVALID_MEM;
       }
       return check(ret);
}

void __hyp_text set_pfn_subowner(u64 pfn, u32 subid)
{
       u64 index;

       index = get_s2_page_index(pfn * PAGE_SIZE);
       if (index != INVALID64)
       {
            set_s2_page_subid(index, subid);
       }
	   else
	   {
			print_string("\rcould not set subowner\n");
	   }
}

void __hyp_text set_pfn_subcount(u64 pfn, u32 subcount)
{
    u64 index;

    index = get_s2_page_index(pfn * PAGE_SIZE);

	if (index != INVALID64)
    {
        set_s2_page_subcount(index, subcount);
    }
}

u32 __hyp_text get_pfn_subcount(u64 pfn)
{
	u64 index;
    u32 ret;

    index = get_s2_page_index(pfn * PAGE_SIZE);

    if (index != INVALID64)
    {

		ret = get_s2_page_subcount(index);
    }
    else
    {
    	ret = INVALID_MEM;
    }
    return check(ret);
}

void __hyp_text set_pfn_kpt_index(u64 pfn, u64 kpt_index)
{
    u64 index;


    index = get_s2_page_index(pfn * PAGE_SIZE);

	if (index != INVALID64)
    {
        set_s2_page_kpt_index(index, kpt_index);
    }
}

u64 __hyp_text get_pfn_kpt_index(u64 pfn)
{
	u64 index;
    u64 ret;

    index = get_s2_page_index(pfn * PAGE_SIZE);

    if (index != INVALID64)
    {

		ret = get_s2_page_kpt_index(index);
    }
    else
    {
    	ret = INVALID_MEM;
    }
    return check64(ret);
}

void __hyp_text set_pfn_el1_va(u64 pfn, u64 el1_va)
{
    u64 index;

    index = get_s2_page_index(pfn * PAGE_SIZE);

	if (index != INVALID64)
    {
        set_s2_page_el1_va(index, el1_va);
    }
}

u64 __hyp_text get_pfn_el1_va(u64 pfn)
{
	u64 index;
    u64 ret;

    index = get_s2_page_index(pfn * PAGE_SIZE);

    if (index != INVALID64)
    {

		ret = get_s2_page_el1_va(index);
    }
    else
    {
        ret = INVALID_MEM;
    }
    return check64(ret);
}

u64 __hyp_text get_pfn_s2_perm(u64 pfn, u32 lvl)
{
	u64 subowner, perm;

	subowner = get_pfn_subowner(pfn);

	if (subowner >= EL1_PGD && subowner <= EL1_PTE)
	{
		perm = (lvl < 3U)?
			pgprot_val(SECT_S2) : pgprot_val(PAGE_S2);
	}
	else if (subowner == EL1_KCODE)
	{
		perm = (lvl < 3U)?
			pgprot_val(SECT_S2_KCODE) : pgprot_val(PAGE_S2_KCODE);
	}
	else if (subowner == EL1_DATA)
	{
		perm = (lvl < 3U)?
			pgprot_val(SECT_S2P) : pgprot_val(PAGE_S2P);
	}
	else if (subowner == EL1_RODATA)
	{
		perm = (lvl < 3U)?
			pgprot_val(SECT_S2) : pgprot_val(PAGE_S2);
	}
	else
	{
		perm = (lvl < 3U)?
			pgprot_val(SECT_S2_KERNEL) : pgprot_val(PAGE_S2_KERNEL);
	}

	return perm;
}
