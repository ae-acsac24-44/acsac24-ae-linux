#include "kint.h"

u32 __hyp_text el2_aarch64_insn_encode_register(enum aarch64_insn_register_type type,
					u32 insn,
					enum aarch64_insn_register reg)
{
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
		print_string("\runknown register encoding\n");
		return AARCH64_BREAK_FAULT;
	}

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
	case AARCH64_INSN_REGTYPE_RS:
		shift = 16;
		break;
	default:
        print_string("\runknown register type encoding\n");
		return AARCH64_BREAK_FAULT;
	}

	insn &= ~(EL2_GENMASK(4, 0) << shift);
	insn |= reg << shift;

	return insn;
}

long __hyp_text el2_branch_imm_common(unsigned long pc, unsigned long addr,
				     long range)
{
	long offset;

	if ((pc & 0x3) || (addr & 0x3)) {
		print_string("A64 instructions must be word aligned\n");
		return range;
	}

	offset = ((long)addr - (long)pc);

	if (offset < -range || offset >= range) {
		print_string("offset out of range\n");
		return range;
	}

	return offset;
}