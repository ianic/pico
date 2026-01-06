#!/bin/bash -e
set -e

zig build -Doptimize=ReleaseSafe

# send uart reboot command
printf '\xAB' | sudo tio -b 115200 /dev/ttyACM0
sleep 0.5

app=${1:-blinky}
picotool load -x -f zig-out/firmware/"$app".uf2
