## coreboot for HiFive Unleashed

HiFive Unleashed is the 1st RISC-V based hardware can run GNU/Linux. Jonathan Neuschäfer as a coreboot for RISC-V maintainer [started to porting](https://review.coreboot.org/cgit/coreboot.git/commit/?id=1c09cfa37b167d64da2a182058b04780789f6201) coreboot to HiFive Unleashed. The [original boot process](https://mail.coreboot.org/pipermail/coreboot/2018-June/086954.html) is about:

```

+------+    +------+    +------+    +-----+
| MSEL |--->| ZSBL |--->| FSBL |--->| BBL |
+------+    +------+    +------+    +-----+

```

Our target should be looks like this:

```

+------+    +------+    +----------+
| MSEL |--->| ZSBL |--->| coreboot |
+------+    +------+    +----------+

```

coreboot is supposed to replace FSBL/BBL but [FSBL](https://mail.coreboot.org/pipermail/coreboot/2018-June/086967.html) is not open source. Due to some reasons( NDA?), SiFive wouldn't provide either source code or DRAM controller config register value. Fortunately, [SiFive seems](https://forums.sifive.com/t/ddr-controller-configuration-register-values-for-hifive-unleashed/1334/3) ok about people getting it by reverse engineering. We dump the FSBL binary blob and it's about ~9k LoC( asm). Well, it should be easier than reversing Intel FSP( even in case of which IDA Pro decompiler doesn't work here).

## Update: Jul 2 2018

SiFive decided to [release the full source code of HiFive Unleashed](https://forums.sifive.com/t/ddr-controller-configuration-register-values-for-hifive-unleashed/1334/8) shortly and that's an awesome news. IMOHO, we still need RE tools if other vendor/board doesn't open source in the future.


## RE issues

  * We tried reversing the fsbl binary blob a bit via r2 and figured that the disasm code is not good as expected. This issue led to [r2 is not using](https://github.com/radare/radare2/tree/master/libr/asm/arch/riscv) [capstone](http://www.capstone-engine.org/) which is based on llvm. Capstone will [support partial implementation of RISCV32IMAFD and RISCV64IMAFD](https://github.com/aquynh/capstone/pull/1131) soon since [riscv-llvm seems need more time](http://www.lowrisc.org/llvm/status/) to landing the upstream.


## Prerequisites

* Reversing tools: [radare2](https://github.com/radare/radare2) or [GNU toolchains( included objdump)](https://github.com/sifive/freedom-u-sdk).
* [HiFive Unleashed Firmware](https://static.dev.sifive.com/dev-kits/hifive-unleashed/hifive-unleashed-firmware-1.0.zip)


## Dump the binary blob

Assume that you've already decompress the gpt image from the zip file:
```
# losetup -f hifive-unleashed-a00-1.0-2018-03-20.gpt
# losetup -l
```

Dump the fsbl blob and fsbl.bin is bascially our "evil" blob:
```
# partx -a /dev/loop0
# partx -s /dev/loop0
NR START   END SECTORS  SIZE NAME               UUID
 1    34    85      52   26K fsbl               0ab3452d-e798-50f9-b9ae-db3ebca936bf
 2    86 32701   32616 15.9M bare-metal program 7c3f492f-88ef-5a49-a1c6-85745a1bfa31

# dd if=/dev/loop0p1 of=dump.bin
# riscv64-unknown-linux-gnu-as inc.s -o inc.o
# riscv64-unknown-linux-gnu-ld -T linker.ld inc.o -o fsbl.elf
```

## Dissecting our "evil" blob( sure it's not Bob)

File info: 

```
# rabin2 -I fsbl.elf 
Warning: Cannot initialize program headers
Warning: Cannot initialize dynamic strings
Warning: Cannot initialize dynamic section
Warning: index out of strtab range
Warning: index out of strtab range
Warning: index out of strtab range
Warning: index out of strtab range
arch     riscv
binsz    134244557
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
lang     c
linenum  true
lsyms    true
machine  RISC V
maxopsz  16
minopsz  1
nx       false
os       linux
pcalign  0
pic      false
relocs   true
rpath    NONE
static   true
stripped false
subsys   linux
va       true
``
