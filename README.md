## Install

Use install.sh to install as 'kropr' without breaking unmodified ropr installation

## Changes Made:

Prevent scanning executable sections besides .text (e.g. .init.text for gadgets), they won't be executable at runtime. Cuts down on false positives.

Change 'sys' gadgets to not include `syscall` or `int 0x80` since those are never useful in the kernel, the remaining 'sys' gadgets -- sysret/iret/sysexit -- can be filtered out with '--nosys' as before.

Do not include results with interrupt instructions (e.g. int3).

Find gadgets that end in `jmp __x86_return_thunk`, `jmp __x86_indirect_thunk_r*`, `jmp __x86_indirect_jump_thunk_r*`, `jmp __x86_indirect_call_thunk_r*`

Made it so that --noisy treats anything ending in a branch/call as a potential gadget, excluding near jumps can mean that when symbols are not available thunked gadgets are not found

Output can be sorted alphabetically via the --sort option

The --magic flag can be used to get some commonly used offsets

Conditionally apply self-patching according to the .return_sites section (patches `jmp __x86_return_thunk` to `ret; int3; int3; int3` to match the kernel's behavior) via --patch_rets
