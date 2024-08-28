#include "kint.h"

u64 __hyp_text alloc_tmp_buffer(u64 pgnum)
{
	u64 buff;

	buff = get_tmp_buf();
	if (buff + pgnum * PAGE_SIZE < stage2_tmp_pgs_end)
	{
		el2_memset((void *)buff, 0UL, PAGE_SIZE * pgnum);
	}
	else
	{
		return INVALID_MEM;
	}
	return check64(buff);
}

int __hyp_text el2_cmp_name(const void *va, const void *vb)
{
	const char *a;
	const struct kernel_symbol *b;
	a = va; b = vb;
	return el2_strcmp(a, el1_va_to_el2(b->name));
}

bool __hyp_text el2_find_symbol_in_section(const struct symsearch *syms,
				   void *data)
{
	struct find_symbol_arg *fsa = data;
	struct kernel_symbol *sym;

	sym = el2_bsearch(fsa->name, syms->start, syms->stop - syms->start,
			sizeof(struct kernel_symbol), el2_cmp_name);

	if (sym != NULL) {
		fsa->sym = &syms->start[sym - syms->start];
		return true;
	}
	return false;
}

#define AARCH64_INSN_SF_BIT	BIT(31)
#define AARCH64_INSN_N_BIT	BIT(22)
#define AARCH64_INSN_LSL_12	BIT(22)

int __hyp_text el2_aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	case AARCH64_INSN_IMM_N:
		mask = 1;
		shift = 22;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

u32 __hyp_text el2_aarch64_insn_decode_register(enum aarch64_insn_register_type type,
					u32 insn)
{
	int shift;

	switch (type) {
	case AARCH64_INSN_REGTYPE_RT:
	case AARCH64_INSN_REGTYPE_RD:
		shift = 0;
		break;
	case AARCH64_INSN_REGTYPE_RN:
		shift = 5;
		break;
	case AARCH64_INSN_REGTYPE_RT2:
	case AARCH64_INSN_REGTYPE_RA:
		shift = 10;
		break;
	case AARCH64_INSN_REGTYPE_RM:
		shift = 16;
		break;
	default:
		return 0;
	}

	return (insn >> shift) & EL2_GENMASK(4, 0);	
}

u32 __hyp_text el2_aarch64_insn_gen_movewide(enum aarch64_insn_register dst,
			      int imm, int shift,
			      enum aarch64_insn_variant variant,
			      enum aarch64_insn_movewide_type type)
{
	u32 insn;

	switch (type) {
	case AARCH64_INSN_MOVEWIDE_ZERO:
		insn = aarch64_insn_get_movz_value();
		break;
	case AARCH64_INSN_MOVEWIDE_KEEP:
		insn = aarch64_insn_get_movk_value();
		break;
	case AARCH64_INSN_MOVEWIDE_INVERSE:
		insn = aarch64_insn_get_movn_value();
		break;
	default:
		print_string("unknown movewide encoding\n");
		return AARCH64_BREAK_FAULT;
	}

	if (imm & ~(SZ_64K - 1)) {
		print_string("invalid immediate encoding \n");
		return AARCH64_BREAK_FAULT;
	}

	switch (variant) {
	case AARCH64_INSN_VARIANT_32BIT:
		if (shift != 0 && shift != 16) {
			print_string("invalid shift encoding \n");
			return AARCH64_BREAK_FAULT;
		}
		break;
	case AARCH64_INSN_VARIANT_64BIT:
		insn |= AARCH64_INSN_SF_BIT;
		if (shift != 0 && shift != 16 && shift != 32 && shift != 48) {
			pr_err("%s: invalid shift encoding %d\n", __func__,
			       shift);
			return AARCH64_BREAK_FAULT;
		}
		break;
	default:
		pr_err("%s: unknown variant encoding %d\n", __func__, variant);
		return AARCH64_BREAK_FAULT;
	}

	insn |= (shift >> 4) << 21;

	insn = el2_aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

	return el2_aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
}

u32 __hyp_text el2_aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
					  enum aarch64_insn_branch_type type)
{
	u32 insn;
	long offset;

	/*
	 * B/BL support [-128M, 128M) offset
	 * ARM64 virtual address arrangement guarantees all kernel and module
	 * texts are within +/-128M.
	 */
	offset = el2_branch_imm_common(pc, addr, SZ_128M);
	if (offset >= SZ_128M)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_BRANCH_LINK:
		insn = aarch64_insn_get_bl_value();
		break;
	case AARCH64_INSN_BRANCH_NOLINK:
		insn = aarch64_insn_get_b_value();
		break;
	default:
		print_string("unknown branch encoding \n");
		return AARCH64_BREAK_FAULT;
	}

	return el2_aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn,
					     offset >> 2);
}


struct plt_entry __hyp_text el2_get_plt_entry(u64 val)
{
	/*
	 * MOVK/MOVN/MOVZ opcode:
	 * +--------+------------+--------+-----------+-------------+---------+
	 * | sf[31] | opc[30:29] | 100101 | hw[22:21] | imm16[20:5] | Rd[4:0] |
	 * +--------+------------+--------+-----------+-------------+---------+
	 *
	 * Rd     := 0x10 (x16)
	 * hw     := 0b00 (no shift), 0b01 (lsl #16), 0b10 (lsl #32)
	 * opc    := 0b11 (MOVK), 0b00 (MOVN), 0b10 (MOVZ)
	 * sf     := 1 (64-bit variant)
	 */
	return (struct plt_entry){
		cpu_to_le32(0x92800010 | (((~val      ) & 0xffff)) << 5),
		cpu_to_le32(0xf2a00010 | ((( val >> 16) & 0xffff)) << 5),
		cpu_to_le32(0xf2c00010 | ((( val >> 32) & 0xffff)) << 5),
		cpu_to_le32(0xd61f0200)
	};
}

bool __hyp_text el2_plt_entries_equal(const struct plt_entry *a,
				     const struct plt_entry *b)
{
	return a->mov0 == b->mov0 &&
	       a->mov1 == b->mov1 &&
	       a->mov2 == b->mov2;
}
