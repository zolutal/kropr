use crate::{disassembler::Disassembler, error::{Error, Result}};
use goblin::{elf64::program_header::PF_X, pe::section_table::IMAGE_SCN_MEM_EXECUTE, Object};
use iced_x86::{Code, Formatter, FormatterOutput, Instruction};
use std::{
	fs::read,
	path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy)]
pub enum Bitness {
	Bits32,
	Bits64,
}

pub struct Binary {
	path: PathBuf,
	bytes: Vec<u8>,
}

impl Binary {
	pub fn new(path: impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref();
		let bytes = read(path)?;
		let path = path.to_path_buf();
		Ok(Self { path, bytes })
	}

	pub fn path(&self) -> &Path { &self.path }

    pub fn get_sym_addr(&self, fnname: &str) -> Option<u64> {
        let elf = match Object::parse(&self.bytes).expect("couldn't parse object???, is this a vmlinux?") {
            Object::Elf(e) => e,
            _ => {
                panic!("wtf expected an elf, gimme a vmlinux");
            }
        };
        let matched: Vec<u64> = elf.syms.iter().filter(|s| {
                elf.strtab.get_at(s.st_name).unwrap_or("") == fnname
            })
            .map(|s| s.st_value)
            .collect();

        if matched.len() > 0 {
            return Some(matched[0])
        }
        None
    }

    pub fn patch_retpolines(&mut self, thunk_array_addr: u64) -> Result<()> {
        if let Object::Elf(e) = Object::parse(&self.bytes)? {
            let return_sites: Option<Vec<usize>> = e
                .section_headers
                .iter()
                .find(|header| {
                    e.shdr_strtab
                    .get_at(header.sh_name)
                    .unwrap_or("") == ".retpoline_sites"
                })
                .map(|header| {
                    let start_offset = header.sh_offset as usize;
                    let end_offset = start_offset + header.sh_size as usize;
                    let data = &self.bytes[start_offset..end_offset].to_vec();
                    data.chunks(4)
                        .enumerate()
                        .map(|(idx, chunk)| {
                            i32::from_ne_bytes(chunk.try_into().expect(
                                "Failed to cast return site entry to i32"
                            )) as i64 as usize + (header.sh_addr as usize + (idx * 4))
                    }).collect()
                });

            let return_sites = match return_sites {
                Some(r) => r,
                None => {
                    eprintln!(".retpoline_sites section not found, skipping!");
                    return Ok(())
                }
            };

            if let Some(header) = e.section_headers.iter()
                .find(|header| {
                    e.shdr_strtab
                    .get_at(header.sh_name)
                    .unwrap_or("") == ".text"
                })
            {
                let start_addr = header.sh_addr as usize;
                let text_start_offset = header.sh_offset as usize;
                return_sites.iter()
                    .for_each(|retp_vaddr| {
                        let retp_text_offset = retp_vaddr-start_addr;
                        if retp_text_offset > (header.sh_size as usize) {
                            // probably in .init.text
                        } else {
                            let patch_addr = text_start_offset + retp_text_offset;
                            let mut dis = Disassembler::new(Bitness::Bits64, &self.bytes[patch_addr..patch_addr+15]);
                            let mut instr = Instruction::default();
                            dis.decode_at_offset(*retp_vaddr as u64, 0, &mut instr);

                            let target = instr.near_branch_target();

                            // RETPOLINE_THUNK_SIZE == 32
                            let mut reg = (target - thunk_array_addr) / 32;

                            if reg == 4 {
                                panic!("retpoline CALL/JMP to rsp? wtf?")
                            }

                            let mut modrm: u8 = match instr.code() {
                                Code::Call_rel32_64 => {
                                    0x10
                                },
                                Code::Jmp_rel32_64 => {
                                    0x20
                                },
                                // There might be another case for a conditional relative jmp
                                // but I don't know when that ever would get emitted?
                                _ => panic!("encountered retpoline site that wasnt jmp or call")
                            };

                            let patch_start = text_start_offset + retp_text_offset;
                            let mut patch_idx = 0;
                            if reg >= 8 {
                                self.bytes[patch_start+patch_idx] = 0x41; // REX.B prefix
                                patch_idx += 1;
                                reg -= 8;
                            }

                            modrm |= 0xc0;
                            modrm += reg as u8;

                            self.bytes[patch_addr+patch_idx] = 0xff;
                            patch_idx += 1;

                            self.bytes[patch_addr+patch_idx] = modrm;
                            patch_idx += 1;

                            // this isn't exactly what the kernel does, but just fill with nops
                            // it does some nop optimizations to reduce the number of instructions
                            // too lazy to implement that and it doesn't really matter anyways
                            self.bytes[patch_addr+patch_idx..patch_addr+instr.len()].fill(0x90);
                        }
                    })
            }
        };

        Ok(())
    }

	pub fn format_instruction(&self, insn: &iced_x86::Instruction, output: &mut impl FormatterOutput) {
		let mut formatter = iced_x86::IntelFormatter::new();
		let options = iced_x86::Formatter::options_mut(&mut formatter);
		options.set_hex_prefix("0x");
		options.set_hex_suffix("");
		options.set_space_after_operand_separator(true);
		options.set_branch_leading_zeroes(false);
		options.set_uppercase_hex(false);
		options.set_rip_relative_addresses(true);
		// Write instructions
        formatter.format(insn, output);
        output.write(" ", iced_x86::FormatterTextKind::Text);
	}

    pub fn apply_returnsites(&mut self) -> Result<()> {
        if let Object::Elf(e) = Object::parse(&self.bytes)? {
            let return_sites: Option<Vec<usize>> = e
                .section_headers
                .iter()
                .find(|header| {
                    e.shdr_strtab
                    .get_at(header.sh_name)
                    .unwrap_or("") == ".return_sites"
                })
                .map(|header| {
                    let start_offset = header.sh_offset as usize;
                    let end_offset = start_offset + header.sh_size as usize;
                    let data = &self.bytes[start_offset..end_offset].to_vec();
                    data.chunks(4)
                        .enumerate()
                        .map(|(idx, chunk)| {
                            i32::from_ne_bytes(chunk.try_into().expect(
                                "Failed to cast return site entry to i32"
                            )) as i64 as usize + (header.sh_addr as usize + (idx * 4))
                    }).collect()
                });

            let return_sites = match return_sites {
                Some(r) => r,
                None => {
                    eprintln!(".return_sites section not found, skipping!");
                    return Ok(())
                }
            };

            if let Some(header) = e.section_headers.iter()
                .find(|header| {
                    e.shdr_strtab
                    .get_at(header.sh_name)
                    .unwrap_or("") == ".text"
                })
            {
                let start_addr = header.sh_addr as usize;
                let text_start_offset = header.sh_offset as usize;
                return_sites.iter()
                    .for_each(|ret_vaddr| {
                        let ret_text_offset = ret_vaddr-start_addr;
                        if ret_text_offset > (header.sh_size as usize) {
                            // probably in .init.text
                        } else {
                            let patch_addr = text_start_offset + ret_text_offset;
                            self.bytes[patch_addr..patch_addr+5]
                                .copy_from_slice(&[0xc3, 0xcc, 0xcc, 0xcc, 0xcc]);
                        }
                    })
            }
        };

        Ok(())
    }

	pub fn sections(&self, raw: Option<bool>) -> Result<Vec<Section>> {
		match raw {
			Some(true) => Ok(vec![Section {
				file_offset: 0,
				section_vaddr: 0,
				program_base: 0,
				bytes: &self.bytes,
				bitness: Bitness::Bits64,
			}]),
			Some(false) => match Object::parse(&self.bytes)? {
				Object::Elf(e) => {
					let bitness = if e.is_64 {
						Bitness::Bits64
					}
					else {
						Bitness::Bits32
					};
					let sections = e
						.program_headers
						.iter()
						.filter(|header| header.p_flags & PF_X != 0)
						.map(|header| {
							let start_offset = header.p_offset as usize;
							let end_offset = start_offset + header.p_filesz as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: header.p_vaddr as usize,
								program_base: 0,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::PE(p) => {
					let bitness = if p.is_64 {
						Bitness::Bits64
					}
					else {
						Bitness::Bits32
					};
					let sections = p
						.sections
						.iter()
						.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
						.map(|section| {
							let start_offset = section.pointer_to_raw_data as usize;
							let end_offset = start_offset + section.size_of_raw_data as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: section.virtual_address as usize,
								program_base: p.image_base,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::Unknown(_) => Err(Error::ParseErr),
				_ => Err(Error::Unsupported),
			},
			// Default behaviour - fall back to raw if able
			None => match Object::parse(&self.bytes)? {
				Object::Elf(e) => {
					let bitness = if e.is_64 {
						Bitness::Bits64
					}
					else {
						Bitness::Bits32
					};
					let sections = e
						.section_headers
						.iter()
						.filter(|header| {
							e.shdr_strtab
							.get_at(header.sh_name)
							.unwrap_or("") == ".text"
						})
						.map(|header| {
							let start_offset = header.sh_offset as usize;
							let end_offset = start_offset + header.sh_size as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: header.sh_addr as usize,
								program_base: 0,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				Object::PE(p) => {
					let bitness = if p.is_64 {
						Bitness::Bits64
					}
					else {
						Bitness::Bits32
					};
					let sections = p
						.sections
						.iter()
						.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
						.map(|section| {
							let start_offset = section.pointer_to_raw_data as usize;
							let end_offset = start_offset + section.size_of_raw_data as usize;
							Section {
								file_offset: start_offset,
								section_vaddr: section.virtual_address as usize,
								program_base: p.image_base,
								bytes: &self.bytes[start_offset..end_offset],
								bitness,
							}
						})
						.collect::<Vec<_>>();
					Ok(sections)
				}
				_ => Ok(vec![Section {
					file_offset: 0,
					section_vaddr: 0,
					program_base: 0,
					bytes: &self.bytes,
					bitness: Bitness::Bits32,
				}]),
			},
		}
	}
}

pub struct Section<'b> {
	file_offset: usize,
	section_vaddr: usize,
	program_base: usize,
	bitness: Bitness,
	bytes: &'b [u8],
}

impl Section<'_> {
	pub fn file_offset(&self) -> usize { self.file_offset }

	pub fn section_vaddr(&self) -> usize { self.section_vaddr }

	pub fn program_base(&self) -> usize { self.program_base }

	pub fn bitness(&self) -> Bitness { self.bitness }

	pub fn bytes(&self) -> &[u8] { self.bytes }
}
