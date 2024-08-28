#include "hypsec.h"

/*
 * NPTWalk
 */

u32 __hyp_text get_npt_level(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd;u32 ret;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);

	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}

	pmd = walk_pmd(vmid, pud, addr, 0U);

	if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
	{
		u64 pte = walk_pte(vmid, pmd, addr);
		if (phys_page(pte) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 3U;
		}
	}
	else
	{
		if (phys_page(pmd) == 0UL)
		{
			ret = 0U;
		}
		else
		{
			ret = 2U;
		}
	}

	return check(ret);
}

u64 __hyp_text walk_npt(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd, ret, pte;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);

	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 0U);
	}
	else
	{
		pud = pgd;
	}

	if (v_pud_table(pud) == PUD_TYPE_TABLE)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);

		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			pte = walk_pte(vmid, pmd, addr);
			ret = pte;
		}
		else
		{
			ret = pmd;
		}
	}
	else
	{
		ret = pud;
	}

	return check64(ret);
}

void __hyp_text set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 vttbr, pgd, pud, pmd;
	u64 pfn, perm;

	vttbr = get_pt_vttbr(vmid);	
	pfn = addr >> PAGE_SHIFT;

	if (vmid == HOSTVISOR && level == 1U)
		pgd = walk_pgd(vmid, vttbr, addr, 0U);
	else
		pgd = walk_pgd(vmid, vttbr, addr, 1U);

	if (vmid == COREVISOR)
	{
		pud = walk_pud(vmid, pgd, addr, 1U);
	}
	else
	{
		pud = pgd;
	}

	if (level == 1U)
	{
		if (v_pud_table(pud) == PUD_TYPE_TABLE)
		{
			/* fallback to PMD */
			perm = get_pfn_s2_perm(pfn, 2U);
			pte = kint_mk_pmd(pfn, perm);
			set_npt(vmid, addr, 2U, pte);
		}
		else
		{
			v_set_pud(vmid, vttbr, addr, pte);
		}
	}
	else if (level == 2U)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
		{
			/* fallback to PTE */
			perm = get_pfn_s2_perm(pfn, 3U);
			pte = (pfn * PAGE_SIZE) | perm;
			set_npt(vmid, addr, 3U, pte);
		}
		else
		{
			v_set_pmd(vmid, pud, addr, pte);
		}
	}
	else
	{
		if (v_pud_table(pud) == PUD_TYPE_TABLE)
		{
			pmd = walk_pmd(vmid, pud, addr, 1U);
			if (v_pmd_table(pmd) == PMD_TYPE_TABLE) {
				v_set_pte(vmid, pmd, addr, pte);
			}
			else
			{
				print_string("\rset existing npt: pte\n");
				v_panic();
			}
		}
		else
		{
			print_string("\rset existing npt: pte\n");
			v_panic();
		}
	}
}

void mem_load_ref(u64 gfn, u32 reg)
{
	mem_load_raw(gfn, reg);
}

void mem_store_ref(u64 gfn, u32 reg)
{
	mem_store_raw(gfn, reg);
}
