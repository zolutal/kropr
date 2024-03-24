#!/bin/bash

cargo install --path . --root /tmp
mv /tmp/bin/ropr ~/.cargo/bin/kropr
rm -r /tmp/bin
