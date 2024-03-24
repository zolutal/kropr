Changes Made:

Prevent scanning executable sections besides .text (e.g. .init.text for gadgets), they won't be executable at runtime. Cuts down on false positives.

Use install.sh to install as 'kropr' without breaking unmodified ropr installation
