## Install

Use install.sh to install as 'kropr' without breaking unmodified ropr installation

## Goals

Reduce false positives and false negatives that are a result of linux kernel self-patching, filter out gadgets that are unusable in the kernel context, and add convenience methods.

## Changes Made:

### Only scan .text
Prevent scanning executable sections besides .text (e.g. .init.text for gadgets), they won't be executable at runtime.

### Remove gadgets with undesirable instructions
Change 'sys' gadgets to not include `syscall` or `int 0x80` since those are never useful in the kernel, the remaining 'sys' gadgets -- sysret/iret/sysexit -- can be filtered out with '--nosys' as before

Do not include results with interrupt instructions (e.g. int3)

### Handle thunked calls/jmps/rets from spectre mitigations
Find gadgets that end in `jmp __x86_return_thunk`, `jmp __x86_indirect_thunk_r*`, `jmp __x86_indirect_jump_thunk_r*`, `jmp __x86_indirect_call_thunk_r*`

Conditionally apply patches according to the `.return_sites` section (patches `jmp __x86_return_thunk` to `ret; int3; int3; int3; int3;` to match the kernel's behavior) via `--patch-rets` (default: true)

Conditionally apply retpoline patches according to the `.retpoline_sites` section (patches `jmp/call __x86_indirect_thunk_array+xxx` to `jmp/call reg`) via `--patch-retpolines` (default: true)

Made the --noisy flag treat anything ending in a branch/call as a potential gadget, excluding near jumps can mean that thunked gadgets are not found when symbols are not available 

### Convenience

Output can be sorted alphabetically via the --sort option

The --magic flag can be used to get some commonly used offsets
