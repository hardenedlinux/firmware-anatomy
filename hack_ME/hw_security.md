## Info about hardware security

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu 

If the peripheral device and firmware( e.g: Intel ME) is called "Ring -3", so let's call "Ring -4" refered as hardware level( naming is one of the hardest issue in CS, isn't it;-)). Those knowledge from offensive side will help us to know better where we are and how we react. Transparency is more crucial in hardware security than software's due to the emerging cost/complexity of open audit is inevitable. A couple of issues must be taken into account before we have the chance to bring back the hardware freedom to the individuals:

* Libre/open FPGA toolchain
* Libre/open EDA toolchain
* Reproducible semiconductor fabrication process
* Open audit process/method for multiple levels, e.g: RTL, schematic, PCB layout, etc
* FLOSS based hardware supply chain risk assessment and management


## Fault injection

* [Bypassing Secure Boot using Fault Injection - 201708](https://app.media.ccc.de/v/SHA2017-143-bypassing_secure_boot_using_fault_injection), a few low-cost hardwares( [ChipWhisperer-Lite](https://wiki.newae.com/CW1173_ChipWhisperer-Lite), [RF - Passive](https://www.langer-emv.de/en/category/rf-passive-30-mhz-3-ghz/35), etc) can be utilized by the attacker.

* [Escalating Privileges in Linux using Voltage Fault Injection - 201710](https://www.riscure.com/publication/escalating-privileges-linux-using-fault-injection/), [paper](https://www.riscure.com/uploads/2017/10/Riscure_Whitepaper_Escalating_Privileges_in_Linux_using_Fault_Injection.pdf) and [slide](https://www.riscure.com/uploads/2017/10/escalating-privileges-in-linux-using-fi-presentation-fdtc-2017.pdf).

### Mitigation/Countermeasure

* The IP register can be modified by software at runtime in arhcitectures like armv7 which can be exploited by some FI methods. The critical mission should avoid to use such hardwares.

* Software mitigation: [Hardening the COREs](https://github.com/hardenedlinux/hardenedlinux_profiles/raw/master/slide/hardening_the_core.pdf).

* Don't make compiler( _volatile_) become your enemy.


## Article/paper

* [Semi-invasive attacks - A new approach to hardware security analysis - 200504](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-630.pdf)
* [A Touch of Evil: High-Assurance Cryptographic Hardware from Untrusted Components - 201709](https://arxiv.org/abs/1709.03817), find more info on the [website](https://backdoortolerance.org/) and the [write-up](https://www.benthamsgaze.org/2018/02/06/a-witch-hunt-for-trojans-in-our-chips/).
* [DARPA Rolls Out Electronics Resurgence Initiative - 2017](https://www.darpa.mil/news-events/2017-09-13)
* [System Security Integration Through Hardware and Firmware](SSITH)(https://www.darpa.mil/program/system-security-integration-through-hardware-and-firmware)
* [ISA Semantics for ARMv8-A, RISC-V, and CHERI-MIPS](https://alastairreid.github.io/papers/POPL_19/)
* [Surprisingly Turing-Complete](https://www.gwern.net/Turing-complete)
* [When a Patch is Not Enough - HardFails: Software-Exploitable Hardware Bugs](https://arxiv.org/pdf/1812.00197.pdf)


### Secure processor, PUF/POK/FET

* [AEGIS: A single-chip secure processor](https://people.csail.mit.edu/devadas/pubs/aegis-istr-august6-2005.pdf)
* [Trapdoor Computational Fuzzy Extractors and Stateless Cryptographically-Secure Physical Unclonable Functions - 2014](https://eprint.iacr.org/2014/938.pdf)
* [PHYSICAL-LAYER SECURITY FOR THE INTERNET OF THINGS - 2017](https://www.emsec.ruhr-uni-bochum.de/media/attachments/files/2017/03/dissertation-zenger.pdf), another short [write-up](https://pdfs.semanticscholar.org/9c7f/d8cad243654cbcc29b62d721d5c8929ecdb8.pdf).


## Hardware trojan

* [Silencing Hardware Backdoors - 2011](http://www.cs.columbia.edu/~simha/preprint_oakland11.pdf)
* [Stealthy Dopant-Level Hardware Trojans - 2013](https://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
* [DeTrust: Defeating Hardware Trust Verification with Stealthy Implicitly-Triggered Hardware Trojans - 2014](http://www.cse.cuhk.edu.hk/~qxu/zhang-ccs14.pdf)
* [Interdiction in Practice – Hardware Trojan Against a High-Security USB Flash Drive - 2016](https://eprint.iacr.org/2015/768)
* [A2: Analog Malicious Hardware - 2016](https://ieeexplore.ieee.org/document/7546493)
* [Advancing the State-of-the-Art in Hardware Trojans Detection - 2016](https://eprint.iacr.org/2014/943.pdf)
* [TrojanZero: Switching Activity-Aware Design of Undetectable Hardware Trojans with Zero Power and Area Footprint - 201811](https://arxiv.org/abs/1812.02770)


## Free/libre open source project

* [Trust-Hub](http://www.trust-hub.org/home)
* [Pentesting hardware](https://github.com/unprovable/PentestHardware)
* [The Sail ISA specification language](https://github.com/rems-project/sail)


## FPGA

* [Experience Using a Low-Cost FPGA Design to Crack DES Keys](https://www.cl.cam.ac.uk/~rnc1/descrack/DEScracker.html)
* [Active Fences against Voltage-based Side Channels inMulti-Tenant FPGAs](https://eprint.iacr.org/2019/1152.pdf)
* [DDR4 SDRAM - Initialization, Training and Calibration](https://www.systemverilog.io/ddr4-initialization-and-calibration)
* [FPGAs for Software Engineers 0: The Basics](https://rhye.org/post/fpgas-for-software-engineers-0-basics/)


## Open FPGA materials

* [Yosys+nextpnr: an Open Source Framework from Verilog to Bitstream for Commercial FPGAs - 2019](https://arxiv.org/abs/1903.10407)
* [open-fpga-verilog-tutorial](https://github.com/Obijuan/open-fpga-verilog-tutorial/wiki/Chapter-0%3A-you-are-leaving-the-private-sector)
* [FPGADesignElements](https://github.com/laforest/FPGADesignElements)


## Libre/open toolchains

* [yosys](https://github.com/YosysHQ/yosys), systhesis tool can transform Verilog to RTL.
* [nextpnr](https://github.com/YosysHQ/nextpnr), place & route tool transform RTL to bitstream.
* [nextpnr-xilinx](https://github.com/daveshah1/nextpnr-xilinx/), experimental project integrate nextpnr with open bitstream for high end Xilinx FPGA( xc7, [Alveo U250](https://www.xilinx.com/products/boards-and-kits/alveo/u250.html#specifications))
* [symbiflow](https://symbiflow.github.io/)
* [OpenROAD](https://theopenroadproject.org/), [multiple projects](https://github.com/The-OpenROAD-Project) aims to develop open source generation flow( RTL-to-GDS).
* [Project Oak Hardware](https://github.com/project-oak/oak-hardware), enclave demo can work with Xilinx ZCU104.


### SystemVerilogy & VHDL

* [UHDM( Universal Hardware Data Model)](https://github.com/alainmarcel/UHDM), under UHDM's context, the design and implementation process should be like:

```
+---------------------+      +-------------------------+      +------------------------+      +-------------------------------+
|SystemVerilog Design | ---> | Parser: Verible/Surelog | ---> | Tools: Yosys/Verilator | ---> | Simulation/Gate level netlist |
+---------------------+      +-------------------------+      +------------------------+      +-------------------------------+
```
* [Surelog](https://github.com/alainmarcel/Surelog), System Verilog 2017 Pre-processor, Parser, UHDM Compiler. Provides IEEE Design/TB VPI and Python AST API.
* [SystemVerilog Report](https://symbiflow.github.io/sv-tests/), [test suite](https://github.com/SymbiFlow/sv-tests) designed to check compliance with the SystemVerilog standard.


### [OpenTitan](https://opentitan.org/)

* [Ibex RISC-V Core](https://github.com/lowRISC/ibex)
* [Project X-Ray](https://symbiflow.readthedocs.io/projects/prjxray/en/latest/), [Arty A7-100T](https://store.digilentinc.com/arty-a7-artix-7-fpga-development-board-for-makers-and-hobbyists/) and [Nexys Video Artix-7](https://store.digilentinc.com/nexys-video-artix-7-fpga-trainer-board-for-multimedia-applications/)


## Hardware Reverse Engineering

* [HAL — The Missing Piece of the Puzzle for Hardware Reverse Engineering, Trojan Detection and Insertion - 2018](https://eprint.iacr.org/2017/783), [HAL](https://github.com/emsec/HAL) is a FLOSS project can be used to aid the hardware audit.


## Open ASIC design and manufacture

* [Libre Silicon Alliance](https://github.com/libresilicon)
* [ASICone](https://www.youtube.com/watch?v=17Pqy6nH4HA)
