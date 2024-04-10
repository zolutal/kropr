use clap::Parser;
use colored::control::set_override;
use core::panic;
use iced_x86::{FormatterOutput, FormatterTextKind};
use rayon::prelude::*;
use regex::Regex;
use ropr::{
	binary::Binary, disassembler::Disassembly, formatter::ColourFormatter, gadgets::Gadget,
};
use rustc_hash::FxHashMap;
use std::{
	error::Error,
	io::{stdout, BufWriter, Write},
	path::PathBuf,
	time::Instant,
};

#[derive(Parser)]
#[clap(version)]
struct Opt {
	/// Includes potentially low-quality gadgets such as prefixes, conditional branches, and near branches (will find significantly more gadgets)
	#[clap(short = 'n', long)]
	noisy: bool,

	/// Forces output to be in colour or plain text (`true` or `false`)
	#[clap(short = 'c', long)]
	colour: Option<bool>,

	/// Removes normal "ROP Gadgets"
	#[clap(short = 'r', long)]
	norop: bool,

	/// Removes sysret/iret/sysexit gadgets
	#[clap(short = 's', long)]
	nosys: bool,

	/// Removes "JOP Gadgets" - these may have a controllable branch, call, etc. instead of a simple `ret` at the end
	#[clap(short = 'j', long)]
	nojop: bool,

	/// Filters for gadgets which alter the stack pointer
	#[clap(short = 'p', long)]
	stack_pivot: bool,

	/// Filters for gadgets which alter the base pointer
	#[clap(short = 'b', long)]
	base_pivot: bool,

	/// Maximum number of instructions in a gadget
	#[clap(short, long, default_value = "6")]
	max_instr: u8,

	/// Perform a regex search on the returned gadgets for easy filtering
	#[clap(short = 'R', long)]
	regex: Vec<String>,

	/// Perform an inverse regex search on the returned gadgets for easy filtering
	#[clap(short = 'N')]
	not_regex: Vec<String>,

	/// Treats the input file as a blob of code (`true` or `false`)
	#[clap(long)]
	raw: Option<bool>,

	/// Search between address ranges (in hexadecial) eg. `0x1234-0x4567`
	#[clap(long)]
	range: Vec<String>,

	/// Show duplicated gadgets
	#[clap(short = 'u', long)]
	nouniq: bool,

	/// Alphabetically sort gadget output
	#[clap(long)]
	sort: bool,

	/// The path of the file to inspect
	binary: PathBuf,
}

fn write_gadgets(
    mut w: impl Write,
    gadgets: &[(Gadget, usize)],
    ret_thunk: Option<u64>,
    thunks: &Vec<(String, Option<u64>)>,
    jump_thunks: &Vec<(String, Option<u64>)>,
    call_thunks: &Vec<(String, Option<u64>)>,
    sort: bool
) {
	let mut output = ColourFormatter::new();
    let mut formatted_gadgets: Vec<(usize, String)> = vec![];
	for (gadget, address) in gadgets {
		output.clear();

        let mut formatted = String::new();
		gadget.format_instruction(&mut formatted);

        if let Some(ret_thunk) = ret_thunk {
            formatted = formatted.replace(
                &format!("{ret_thunk:#x};"),
                &format!("{ret_thunk:#x} <__x86_return_thunk>;")
            );
        }

        // replace address of thunks/jump_thunks/call_thunks with the String in the vec
        let replace_thunk_addresses = |thunks: &Vec<(String, Option<u64>)>, formatted: &mut String| {
            for (name, address) in thunks {
                if let Some(addr) = address {
                    *formatted = formatted.replace(
                        &format!("{addr:#x}"),
                        &format!("{addr:#x} <{name}>")
                    );
                }
            }
        };

        // Replace addresses of thunks, jump_thunks, and call_thunks with their names
        replace_thunk_addresses(thunks, &mut formatted);
        replace_thunk_addresses(jump_thunks, &mut formatted);
        replace_thunk_addresses(call_thunks, &mut formatted);

        if !sort {
            output.write(&format!("{:#010x}: ", address), FormatterTextKind::Function);
            output.write(&formatted, FormatterTextKind::Text);
            match writeln!(w, "{}", output) {
                Ok(_) => (),
                Err(_) => return, // Pipe closed - finished writing gadgets
            }
        } else {
            formatted_gadgets.push((address.clone(), formatted));
        }
	}

    if sort {
        formatted_gadgets.sort_by(|(_, gadget1), (_, gadget2)| gadget1.cmp(gadget2));
        for (address, formatted) in formatted_gadgets {
            output.clear();
            output.write(&format!("{:#010x}: ", address), FormatterTextKind::Function);
            output.write(&formatted, FormatterTextKind::Text);
            match writeln!(w, "{}", output) {
                Ok(_) => (),
                Err(_) => return, // Pipe closed - finished writing gadgets
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
	let start = Instant::now();

	let opts = Opt::parse();

	let b = opts.binary;
	let b = Binary::new(b)?;
	let sections = b.sections(opts.raw)?;

	let noisy = opts.noisy;
	let colour = opts.colour;
	let rop = !opts.norop;
	let sys = !opts.nosys;
	let jop = !opts.nojop;
	let uniq = !opts.nouniq;
	let sort = opts.sort;
	let stack_pivot = opts.stack_pivot;
	let base_pivot = opts.base_pivot;
	let max_instructions_per_gadget = opts.max_instr as usize;

	if max_instructions_per_gadget == 0 {
		panic!("Max instructions must be >0");
	}

	let ranges = opts
		.range
		.iter()
		.filter_map(|s| s.split_once('-'))
		.filter_map(|(mut from, mut to)| {
			if from.starts_with("0x") {
				from = &from[2..];
			}
			if to.starts_with("0x") {
				to = &to[2..];
			}
			let from = usize::from_str_radix(from, 16).ok()?;
			let to = usize::from_str_radix(to, 16).ok()?;
			Some((from, to))
		})
		.collect::<Vec<_>>();

	let regices = opts
		.regex
		.into_iter()
		.map(|r| Regex::new(&r))
		.collect::<Result<Vec<_>, _>>()?;

	let regices_inverse = opts
		.not_regex
		.into_iter()
		.map(|r| Regex::new(&r))
		.collect::<Result<Vec<_>, _>>()?;

    // arch/x86/include/asm/GEN-for-each-reg.h
    let regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

    // these are indirect jumps but they don't use the return thunk
    let thunks: Vec<(String, Option<u64>)> = regs.into_iter()
        .map(|r| (format!("__x86_indirect_thunk_{r}"), b.lookup_fn_addr(&format!("__x86_indirect_thunk_{r}"))))
        .collect();

    let jump_thunks: Vec<(String, Option<u64>)> = regs.into_iter()
        .map(|r| (format!("__x86_indirect_jump_thunk_{r}"), b.lookup_fn_addr(&format!("__x86_indirect_jump_thunk_{r}"))))
        .collect();

    let call_thunks: Vec<(String, Option<u64>)> = regs.into_iter()
        .map(|r| (format!("__x86_indirect_call_thunk_{r}"), b.lookup_fn_addr(&format!("__x86_indirect_call_thunk_{r}"))))
        .collect();


    let ret_thunk = b.lookup_fn_addr("__x86_return_thunk");
    //panic!("{}", ret_thunk.unwrap());

	let gadget_to_addr = sections
		.iter()
		.filter_map(Disassembly::new)
		.flat_map(|dis| {
			(0..dis.bytes().len())
				.into_par_iter()
				.filter(|offset| dis.is_tail_at(*offset, rop, sys, jop, noisy, ret_thunk, &thunks, &jump_thunks, &call_thunks))
				.flat_map_iter(|tail| {
					dis.gadgets_from_tail(tail, max_instructions_per_gadget, noisy, uniq)
				})
				.collect::<Vec<_>>()
		})
		.filter(|&(_, address)| {
			if ranges.is_empty() {
				return true;
			}
			ranges
				.iter()
				.any(|(from, to)| -> bool { *from <= address && address <= *to })
		})
		.collect::<FxHashMap<_, _>>();

	let mut gadgets = gadget_to_addr
		.into_iter()
		.filter(|(g, _)| {
			let mut formatted = String::new();
			g.format_instruction(&mut formatted);
			regices.iter().all(|r| r.is_match(&formatted))
				&& !regices_inverse.iter().any(|r| r.is_match(&formatted))
		})
		.filter(|(g, _)| !stack_pivot | g.is_stack_pivot(ret_thunk))
		.filter(|(g, _)| !base_pivot | g.is_base_pivot())
		.collect::<Vec<_>>();
	gadgets.sort_unstable_by(|(_, addr1), (_, addr2)| addr1.cmp(addr2));

	let gadget_count = gadgets.len();

	// Don't account for time it takes to print gadgets since this depends on terminal implementation
	let elapsed = Instant::now() - start;

	// Stdout uses a LineWriter internally, therefore we improve performance by wrapping stdout in a BufWriter
	let mut stdout = BufWriter::new(stdout());

	if let Some(colour) = colour {
		set_override(colour);
	}

	write_gadgets(&mut stdout, &gadgets, ret_thunk, &thunks, &jump_thunks, &call_thunks, sort);

	drop(stdout);

	eprintln!(
		"\n==> Found {} gadgets in {:.3} seconds",
		gadget_count,
		elapsed.as_secs_f32()
	);

	Ok(())
}
