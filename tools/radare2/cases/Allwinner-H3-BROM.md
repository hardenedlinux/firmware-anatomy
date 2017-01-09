# Radare2 case: Allwinner H3 BROM

## Extracting

Just use `sunxi-fel` to extract the BROM. It's at 0xffff0000 and with a size of 0x8000.

## Loading into R2

As it's a raw binary file, it needs some parameters to be feed into R2.

`r2 -a arm -b 32 -m 0xffff0000 h3.bin` is the current command.
