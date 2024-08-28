#include "kint.h"

void __hyp_text inc_subcount(u64 pfn)
{
	u64 prev_count, inc_count;
	prev_count = get_pfn_subcount(pfn);
	inc_count = prev_count + 1;
	set_pfn_subcount(pfn, inc_count);
}

u64 __hyp_text init_set_pt_pfn_subowner(u64 entry, u32 subid)
{
	u64 pfn;
	u32 owner;

	pfn = phys_page(entry) >> PAGE_SHIFT;
	owner = get_pfn_owner(pfn);
	if (owner == HOSTVISOR)
	{
		set_pfn_subowner(pfn, subid);
		inc_subcount(pfn);
	}
	return pfn;
}

u64 __hyp_text init_set_section_subowner(u64 entry, u32 subid)
{
	u64 pfn;
	u32 owner, subowner;

	pfn = phys_page(entry) >> PAGE_SHIFT;
	owner = get_pfn_owner(pfn);
	subowner = get_pfn_subowner(pfn);
	if (owner == HOSTVISOR)
	{	
		if (!is_kpt(subowner))
		{
			set_pfn_subowner(pfn, subid);
		}
	}
	return pfn;
}

u32 __hyp_text is_kcode(u64 entry, u64 size)
{	
	u64 pfn, i, start, end;
	u32 subowner;

	pfn = entry; 

	start = get_text();
	end = get_etext();

	for (i = 0; i < (size >> 12); i++)
	{
		pfn = entry + i * PAGE_SIZE;
		subowner = get_pfn_subowner(pfn >> 12);
		
		if (subowner != EL1_KCODE)
		{
			return 0; 
		}
	}
	
	return 1; 
}



#if 1
void __hyp_text check_if_pte(u64 pte)
{
	int i;
	u32 subid;
	u64 ptr, page_des, pfn, count, kpt_index;

	kpt_index = get_pfn_kpt_index((pte >> PAGE_SHIFT));

	for (i = 0; i < PTRS_PER_PTE; i++) {
		ptr = pte + (i * sizeof(pte_t));
		page_des = pt_load(COREVISOR, ptr);

		if (page_des)
		{	
			pfn = phys_page(page_des) >> 12;
			subid = get_pfn_subowner(pfn);
			kpt_index |= i << PTE_SHIFT; 
			set_pfn_kpt_index(pfn, kpt_index); 
			set_pfn_el1_va(pfn, kpt_index);
			if (subid != EL1_KCODE && subid != EL1_INIT)
			{
				pt_store(COREVISOR, ptr, page_des | DCPTR_EL1_PXN_BLOCK_MASK);
			} else {
				pt_store(COREVISOR, ptr, page_des | DCPTR_EL1_XN_BLOCK_MASK);
			}
			inc_subcount(pfn);
		}
	}
}
#endif

void __hyp_text walk_and_set_el1_pmd(u64 pmd)
{
	u64 pmde, pte, pmdp, i, pfn, kpt_index;

	kpt_index = get_pfn_kpt_index((pmd >> PAGE_SHIFT));
	for (i = 0; i < PTRS_PER_PMD; i++) {

		pmdp = pmd + (i * sizeof(pmd_t));
		pmde = pt_load(COREVISOR, pmdp);

		if (pmde & PMD_TABLE_BIT) {
			pte = phys_page(pmde);
			pfn = pte >> PAGE_SHIFT;
			kpt_index |= i << PMD_SHIFT;
			set_pfn_kpt_index(pfn, kpt_index);
			init_set_pt_pfn_subowner(pte, EL1_PTE);
			check_if_pte(pte);
		}
		else if (pmde && !(pmde & PMD_TABLE_BIT))
		{	
			if (!is_kcode(phys_pmd_huge(pmde), HUGE_PMD_SIZE)
				&& !(pmde & DCPTR_EL1_PXN_BLOCK_MASK))
			{
				pt_store(COREVISOR, pmdp, pmde | DCPTR_EL1_PXN_BLOCK_MASK);
			}
		}
	}
}

void __hyp_text walk_and_set_el1_pud(u64 pud)
{
	u64 pude, pmd, pudp, pfn, kpt_index, i;

	kpt_index = get_pfn_kpt_index((pud >> PAGE_SHIFT));
	for (i = 0; i < PTRS_PER_PUD; i++) {
		pudp = pud + (i * sizeof(pud_t));
		pude = pt_load(COREVISOR, pudp);

		if (pude & PUD_TABLE_BIT) {
			pmd = phys_page(pude);
			pfn = pmd >> PAGE_SHIFT;
			kpt_index = kpt_index | (i << PUD_SHIFT);
			set_pfn_kpt_index(pfn, kpt_index);
			init_set_pt_pfn_subowner(pmd, EL1_PMD);
			walk_and_set_el1_pmd(pmd);
		}
		else if (pude && !(pude & PUD_TABLE_BIT)) 
		{
			if (!is_kcode(phys_pud_huge(pud), HUGE_PUD_SIZE)
				&& !(pude & DCPTR_EL1_PXN_BLOCK_MASK))
			{	
				print_string("\rPUD REWRITE\n");
				pt_store(COREVISOR, pudp, pude | DCPTR_EL1_PXN_BLOCK_MASK);
			}
		}
	}
}

void __hyp_text walk_and_set_el1_pt(u64 ttbr)
{
	u64 pgde, pud, pgdp, pfn;
	u64 i;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pgdp = ttbr + (i * sizeof(pgd_t));
		pgde = pt_load(COREVISOR, pgdp);
		if (pgde) {
			pud = phys_page(pgde);
			pfn = pud >> PAGE_SHIFT;
			set_pfn_kpt_index(pfn, i << PGD_SHIFT);
			init_set_pt_pfn_subowner(pud, EL1_PUD);
			walk_and_set_el1_pud(pud);
		}
	}
	return;
}

void __hyp_text init_init_sec(void)
{
	u64 start, end, diff, i;
	start = get_inittext_begin() >> 12;
	end = get_inittext_end() >> 12;

	diff = end - start; 

	for (i = 0; i < diff; i++)
	{	
		init_set_section_subowner((start + i) << 12, EL1_INIT); 
	}
}

void __hyp_text init_text(void)
{
	u64 start, end, diff, i;
	start = get_text() >> 12;
	end = get_etext() >> 12;

	diff = end - start; 

	for (i = 0; i < diff; i++)
	{	
		init_set_section_subowner((start + i) << 12, EL1_KCODE); 
	}
}

void __hyp_text init_rodata(void)
{
	u64 start, end, diff, i, zero_page;
	start = get_rodata() >> 12;
	end = get_erodata() >> 12;

	diff = end - start;

	for (i = 0; i < diff; i++)
	{
		init_set_section_subowner((start + i) << 12, EL1_RODATA);
	}

	zero_page = get_host_zero_page();
	init_set_section_subowner(zero_page, EL1_RODATA);
}

void __hyp_text init_data(void)
{
	u64 start, end, diff, i;
	start = get_data() >> 12;
	end = get_edata() >> 12;

	diff = end - start; 

	for (i = 0; i < diff; i++)
	{	
		init_set_section_subowner((start + i) << 12, EL1_DATA); 
	}
}

void __hyp_text init_el1_pts(void)
{
	u64 ttbr, tramp;
	ttbr = get_host_ttbr1();
	print_string("\rTTBR\n");
	printhex_ul(ttbr);
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	tramp = ttbr - (PAGE_SIZE + RESERVED_TTBR0_SIZE);
#endif

	acquire_lock_s2page();

	init_text();
	init_data();
	init_init_sec();
	init_rodata();
	init_set_pt_pfn_subowner(ttbr, EL1_PGD);
	walk_and_set_el1_pt(ttbr);
#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	init_set_pt_pfn_subowner(tramp, EL1_PGD);
	walk_and_set_el1_pt(tramp);
#endif
	release_lock_s2page();
}

void __hyp_text init_s2_page(void)
{	
	u64 i; 
	u64 index; 
	acquire_lock_s2page();

	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start); 
	for( i = 0; i < S2_PFN_SIZE; i++)
	{
		el2_data->s2_pages[i].subid  = 0; 
		el2_data->s2_pages[i].subcount = 0;
		el2_data->s2_pages[i].dynamic = 0;
		el2_data->s2_pages[i].kpt_index = 0;
		el2_data->s2_pages[i].el1_va = 0;
	}
	release_lock_s2page();
}
