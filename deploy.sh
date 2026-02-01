#!/bin/bash -e
set -e

# zig build -Doptimize=ReleaseSafe

# # send uart reboot command
# printf '\xAB' | sudo tio -b 115200 /dev/ttyACM0
# sleep 1

# app=${1:-blinky}
# picotool load -x -f zig-out/firmware/"$app".uf2

function pico_load() {
    offset=$1
    file=$2
    size=$(wc -c <$file)
    echo load at offset $offset $size bytes of file $file

    printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
        $((size & 0xff)) $(((size >> 8) & 0xff)) $(((size >> 16) & 0xff)) $((size >> 24)))" \
        >header.bin

    output=output.bin
    cat header.bin "$file" >"$output"
    rm header.bin

    picotool load --offset $offset --verify $output
    rm $output
}

opt_load=false
opt_verbose=false
opt_deploy=false
opt_build=false

# if there is not arguments
if [ $# -eq 0 ]; then
    opt_deploy=true
fi

# Parse short options
while getopts "ldb:v" opt; do
    case $opt in
    l) opt_load=true ;;
    d) opt_deploy=true ;;
    b) opt_build=true ;;
    v) opt_verbose=true ;;
    \?)
        echo "Invalid option -$OPTARG"
        #usage
        exit 1
        ;;
    esac
done

if $opt_load; then
    #picotool load --offset 0x10350000 --verify
    # starting at 40_0000 = 4M end of flash
    # 5_0000 = 64*5 = 320k block for file starting from 40_0000 - 5_0000 = 3b_0000
    pico_load 0x103b0000 ~/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_61.bin
    # next block of 320k starting at 3b_0000 - 5_0000 = 36_0000
    pico_load 0x10360000 ~/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_7_95_88.bin
    # next block of 1k staring at 36_0000 - 1_000 = 35_f000
    pico_load 0x1035f000 ~/Code/microzig/drivers/wireless/cyw43/firmware/43439A0_clm.bin
fi

shift $((OPTIND - 1))

app=pong
if [[ -n "$1" ]]; then
    app="$1"
    opt_deploy=true
fi

if [ $opt_build ] || [ $opt_deploy ]; then
    zig build -Doptimize=ReleaseSmall
fi

if $opt_deploy; then
    # send uart reboot command
    printf '\xAB' | sudo tio -b 115200 /dev/ttyACM0

    # create raw binary from elf
    elf=$app.elf
    bin=$app.bin
    cd zig-out/firmware/
    arm-none-eabi-objcopy -O binary $elf $bin

    ls -al $app.*

    until picotool load --offset 0x10000000 -x -f $bin; do
        sleep 1
    done
fi
