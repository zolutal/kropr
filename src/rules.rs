use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};

fn is_ret(instr: &Instruction, ret_thunk: Option<u64>) -> bool {
    match instr.mnemonic() {
        Mnemonic::Ret => true,
        Mnemonic::Jmp => {
            let ret_thunk = match ret_thunk {
                Some(ret_thunk) => ret_thunk,
                None => { return false; }
            };
            match instr.op0_kind() {
                OpKind::NearBranch64 |OpKind::NearBranch32 | OpKind::NearBranch16 => {
                    instr.near_branch_target() == ret_thunk
                },
                _ => false
            }
        }
        _ => false
    }
}

fn is_target_thunk(
    instr: &Instruction,
    ret_thunk: Option<u64>,
	thunks: &Vec<(String, Option<u64>)>,
) -> bool {
    match instr.mnemonic() {
        Mnemonic::Jmp => {
            match instr.op0_kind() {
                OpKind::NearBranch64 |OpKind::NearBranch32 | OpKind::NearBranch16 => {
                    let target = instr.near_branch_target();

                    // check return_thunk first
                    if ret_thunk == Some(target) {
                        return true;
                    }

                    // then check each vector of thunks
                    for (_, thunk_addr) in thunks.iter() {
                        if let Some(addr) = thunk_addr {
                            if *addr == target {
                                return true;
                            }
                        }
                    }

                    false
                },
                _ => false
            }
        },
        _ => false
    }
}

fn is_sys(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => true,
		Mnemonic::Sysret | Mnemonic::Sysretq | Mnemonic::Sysexit | Mnemonic::Sysexitq => true,
		_ => false,
	}
}

fn is_jop(instr: &Instruction, noisy: bool) -> bool {
	match instr.mnemonic() {
		Mnemonic::Jmp => {
			if noisy {
				true
			}
			else {
				match instr.op0_kind() {
					OpKind::Register => true,
					OpKind::Memory => !matches!(instr.memory_base(), Register::EIP | Register::RIP),
					_ => false,
				}
			}
		}
		Mnemonic::Call => {
			if noisy {
				true
			}
			else {
				match instr.op0_kind() {
					OpKind::Register => true,
					OpKind::Memory => !matches!(instr.memory_base(), Register::EIP | Register::RIP),
					_ => false,
				}
			}
		}
		_ => false,
	}
}

fn is_invalid(instr: &Instruction) -> bool { matches!(instr.code(), Code::INVALID) }

pub fn is_gadget_tail(
    instr: &Instruction,
    rop: bool,
    sys: bool,
    jop: bool,
    noisy: bool,
    ret_thunk: Option<u64>,
    thunks: &Vec<(String, Option<u64>)>,
) -> bool {
	if is_invalid(instr) {
		return false;
	}
	if instr.flow_control() == FlowControl::Next {
		return false;
	}
    if rop && is_target_thunk(instr, ret_thunk, thunks) {
        return true;
    }
	if rop && is_ret(instr, ret_thunk) {
		return true;
	}
	if sys && is_sys(instr) {
		return true;
	}
	if jop && is_jop(instr, noisy) {
		return true;
	}
	false
}

pub fn is_rop_gadget_head(instr: &Instruction, noisy: bool) -> bool {
	if is_invalid(instr) {
		return false;
	}
	if !noisy
		&& (instr.has_lock_prefix()
			|| instr.has_rep_prefix()
			|| instr.has_repe_prefix()
			|| instr.has_repne_prefix()
			|| instr.has_xacquire_prefix()
			|| instr.has_xrelease_prefix())
	{
		return false;
	}
	match instr.flow_control() {
		FlowControl::Next => true,
		FlowControl::ConditionalBranch => noisy,
		FlowControl::Call => instr.mnemonic() != Mnemonic::Call,
		_ => false,
	}
}

pub fn is_stack_pivot_head(instr: &Instruction) -> bool {
	let reg0 = instr.op0_register();
	let kind1 = instr.op1_kind();
	let reg1 = instr.op1_register();
	match instr.mnemonic() {
		Mnemonic::Adc
		| Mnemonic::Adcx
		| Mnemonic::Add
		| Mnemonic::Sbb
		| Mnemonic::Sub
		| Mnemonic::Bndmov
		| Mnemonic::Cmova
		| Mnemonic::Cmovae
		| Mnemonic::Cmovb
		| Mnemonic::Cmovbe
		| Mnemonic::Cmove
		| Mnemonic::Cmovg
		| Mnemonic::Cmovge
		| Mnemonic::Cmovl
		| Mnemonic::Cmovle
		| Mnemonic::Cmovne
		| Mnemonic::Cmovno
		| Mnemonic::Cmovnp
		| Mnemonic::Cmovns
		| Mnemonic::Cmovo
		| Mnemonic::Cmovp
		| Mnemonic::Cmovs
		| Mnemonic::Cmpxchg
		| Mnemonic::Cmpxchg16b
		| Mnemonic::Cmpxchg8b
		| Mnemonic::Pop
		| Mnemonic::Popa
		| Mnemonic::Popad => {
			matches!(reg0, Register::RSP | Register::ESP | Register::SP)
				&& matches!(
					kind1,
					OpKind::Immediate8
						| OpKind::Immediate8_2nd | OpKind::Immediate16
						| OpKind::Immediate32 | OpKind::Immediate64
						| OpKind::Immediate8to16 | OpKind::Immediate8to32
						| OpKind::Immediate8to64 | OpKind::Immediate32to64
						| OpKind::Register
				)
		}
		Mnemonic::Mov | Mnemonic::Movbe | Mnemonic::Movd => {
			matches!(reg0, Register::RSP | Register::ESP | Register::SP)
				&& (matches!(kind1, OpKind::Register) || instr.memory_base() != Register::None)
		}
		Mnemonic::Xadd | Mnemonic::Xchg => {
			matches!(reg0, Register::RSP | Register::ESP | Register::SP)
				|| matches!(reg1, Register::RSP | Register::ESP | Register::SP)
		}
		Mnemonic::Leave => true,
		_ => false,
	}
}

pub fn is_stack_pivot_tail(instr: &Instruction, ret_thunk: Option<u64>) -> bool { is_ret(instr, ret_thunk) }

pub fn is_base_pivot_head(instr: &Instruction) -> bool {
	let reg0 = instr.op0_register();
	let kind1 = instr.op1_kind();
	let reg1 = instr.op1_register();
	match instr.mnemonic() {
		Mnemonic::Adc
		| Mnemonic::Adcx
		| Mnemonic::Add
		| Mnemonic::Sbb
		| Mnemonic::Sub
		| Mnemonic::Bndmov
		| Mnemonic::Cmova
		| Mnemonic::Cmovae
		| Mnemonic::Cmovb
		| Mnemonic::Cmovbe
		| Mnemonic::Cmove
		| Mnemonic::Cmovg
		| Mnemonic::Cmovge
		| Mnemonic::Cmovl
		| Mnemonic::Cmovle
		| Mnemonic::Cmovne
		| Mnemonic::Cmovno
		| Mnemonic::Cmovnp
		| Mnemonic::Cmovns
		| Mnemonic::Cmovo
		| Mnemonic::Cmovp
		| Mnemonic::Cmovs
		| Mnemonic::Cmpxchg
		| Mnemonic::Cmpxchg16b
		| Mnemonic::Cmpxchg8b
		| Mnemonic::Pop
		| Mnemonic::Popa
		| Mnemonic::Popad => {
			matches!(reg0, Register::RBP | Register::EBP | Register::BP)
				&& matches!(
					kind1,
					OpKind::Immediate8
						| OpKind::Immediate8_2nd | OpKind::Immediate16
						| OpKind::Immediate32 | OpKind::Immediate64
						| OpKind::Immediate8to16 | OpKind::Immediate8to32
						| OpKind::Immediate8to64 | OpKind::Immediate32to64
						| OpKind::Register
				)
		}
		Mnemonic::Mov | Mnemonic::Movbe | Mnemonic::Movd => {
			matches!(reg0, Register::RBP | Register::EBP | Register::BP)
				&& (matches!(kind1, OpKind::Register) || instr.memory_base() != Register::None)
		}
		Mnemonic::Xadd | Mnemonic::Xchg => {
			matches!(reg0, Register::RBP | Register::EBP | Register::BP)
				|| matches!(reg1, Register::RBP | Register::EBP | Register::BP)
		}
		Mnemonic::Enter => true,
		_ => false,
	}
}
