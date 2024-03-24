## Install

Use install.sh to install as 'kropr' without breaking unmodified ropr installation

## Changes Made:

Prevent scanning executable sections besides .text (e.g. .init.text for gadgets), they won't be executable at runtime. Cuts down on false positives.

Change 'sys' gadgets to not include `syscall` or `int 0x80` since those are never useful in the kernel, the remaining 'sys' gadgets -- sysret/iret/sysexit -- can be filtered out with '--nosys' as before.

Do not include results with interrupt instructions (e.g. int3).

Find gadgets that end in `jmp __x86_return_thunk`, `jmp __x86_indirect_thunk_r*`, `jmp __x86_indirect_jump_thunk_r*`, `jmp __x86_indirect_call_thunk_r*`
