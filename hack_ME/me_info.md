## Info about ME

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu 

We should know our enemeies from RING 3/0/-1/-2 and espeically the "devil" from RING -3 world.


## Slide

* [Introducing Ring -3 Rootkit - 2009-08](https://www.blackhat.com/presentations/bh-usa-09/TERESHKIN/BHUSA09-Tereshkin-Ring3Rootkit-SLIDES.pdf)
* [A Quest To The Core - 2009-09](http://invisiblethingslab.com/resources/misc09/Quest%20To%20The%20Core%20(public).pdf)
* [Security Evaluation of Intel's Active Management Technology - 2010](https://people.kth.se/~maguire/DEGREE-PROJECT-REPORTS/100402-Vassilios_Ververis-with-cover.pdf)
* [Intel AMT/ME Meet Intel's hardware backdoor - 2012-09](www.uberwall.org/bin/download/download/102/lacon12_intel_amt.pdf)
* [Rootkit in your laptop - 2012-10](http://me.bios.io/images/c/ca/Rootkit_in_your_laptop.pdf)
* [Persistent, Stealthy, Remote-controlled Dedicated Hardware Malware - 201312](http://stewin.org/slides/30c3-dedicated_hw_malware-stewin_bystrov_final.pdf), [presentation video](http://www.youtube.com/watch?v=Ti-N7WDqNjk) at 30C3.
* [Intel ME Secrets - 2014-06](https://recon.cx/2014/slides/Recon%202014%20Skochinsky.pdf), [video1](https://www.youtube.com/watch?v=4kCICUPc9_8), [video2](https://www.youtube.com/watch?v=Y2_-VXz9E-w)
* [Intel ME: Two Years Later - 2014-10](https://github.com/skochinsky/papers/raw/master/2014-10%20%5BBreakpoint%5D%20Intel%20ME%20-%20Two%20Years%20Later.pdf)
* [Reversing firmware using radare2 - 2014-10](http://xvilka.me/h2hc2014-reversing-firmware-radare-slides.pdf)
* [Intel ME: The Way of the Static Analysis - 201703](https://www.troopers.de/downloads/troopers17/TR17_ME11_Static.pdf), [presentation video](https://www.youtube.com/watch?v=2_aokrfcoUk)
* [Secrets of the Motherboard - 201709](https://labs.portcullis.co.uk/download/44CSOTM.pptx)
* [Intel AMT: Using & Abusing the Ghost in the Machine - 201710](https://drive.google.com/file/d/0BxMgdZPXsSLBYTBpWXZoRFJXZk0/view), [video](https://www.youtube.com/watch?v=aiMNbjzYMXo)
* [How to Hack a Turned - Off Computer, or Running Unsigned Code in Intel Management Engine - 201712](https://www.blackhat.com/docs/eu-17/materials/eu-17-Goryachy-How-To-Hack-A-Turned-Off-Computer-Or-Running-Unsigned-Code-In-Intel-Management-Engine.pdf), [white paper](https://www.blackhat.com/docs/eu-17/materials/eu-17-Goryachy-How-To-Hack-A-Turned-Off-Computer-Or-Running-Unsigned-Code-In-Intel-Management-Engine-wp.pdf).
* [Intel ME: Flash File System Explained: https://www.blackhat.com/docs/eu-17/materials/eu-17-Sklyarov-Intel-ME-Flash-File-System-Explained.pdf - 201712], [whiter paper](https://www.blackhat.com/docs/eu-17/materials/eu-17-Sklyarov-Intel-ME-Flash-File-System-Explained-wp.pdf).
* [Inside Intel Management Engine - 201712](https://media.ccc.de/v/34c3-8762-inside_intel_management_engine)
* [Intel ME: Myths and reality - 201712](https://media.ccc.de/v/34c3-8782-intel_me_myths_and_reality)
* [Intel ME Security keys Genealogy, Obfuscation and other Magic - 201807](https://github.com/ptresearch/IntelME-Crypto/blob/master/Intel%20ME%20Security%20keys%20Genealogy%2C%20Obfuscation%20and%20other%20Magic.pdf)
* [Intel VISA: Through the Rabbit Hole - 201903](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Goryachy-Ermolov-Intel-Visa-Through-the-Rabbit-Hole.pdf)


## Article/paper

* [mysteries_intel.txt - 2012-07](https://code.coreboot.org/p/flashrom/source/tree/HEAD/trunk/Documentation/mysteries_intel.txt)
* [Intel Management Engine - 2012-10](http://vpro.by/intel-management-engine)
* [Detecting Peripheral-based Attacks on the Host Memory - 201407](https://depositonce.tu-berlin.de/bitstream/11303/4494/1/stewin_patrick.pdf)
* [Intel x86 considered harmful - 2015-10](https://blog.invisiblethings.org/papers/2015/x86_harmful.pdf)
* [Безопасность прошивок на примере подсистемы Intel Management Engine - 2016-03](https://habrahabr.ru/company/dsec/blog/278549/)
* [Intel ME. Как избежать восстания машин? - 2016-04](https://habrahabr.ru/company/dsec/blog/282546/)
* [Why is the latest Intel hardware unsupported in libreboot?](https://libreboot.org/faq/#intelme)
* [Intel ME info on coreboot's wiki](https://www.coreboot.org/Intel_Management_Engine)
* [me.bios.io](http://me.bios.io), contains some early research about ME: [ME blob format](http://me.bios.io/ME_blob_format) might need update, get a proper version of [GNU toolchain for ARC](https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain) and then try [ARC disassembly](http://me.bios.io/ARC_disassembly) on earlier ME versions.
* [Starting point of minimizing ME](https://www.coreboot.org/pipermail/coreboot/2016-November/082331.html) and see the [current status of me_cleaner](https://github.com/corna/me_cleaner/issues/3).
* [Neutralize ME firmware on SandyBridge and IvyBridge platforms](https://hardenedlinux.github.io/firmware/2016/11/17/neutralize_ME_firmware_on_sandybridge_and_ivybridge.html) is an operational manual and we [have done it on some mainboards](https://github.com/hardenedlinux/hardenedlinux_profiles/tree/master/coreboot)( including a Skylake-based one) so far.
* [Reverse-engineering the Intel Management Engine’s ROMP module - 201705](https://puri.sm/posts/reverse-engineering-the-intel-management-engine-romp-module/), the [C pseudo code of ROMP module](https://github.com/kakaroto/purism-playground/tree/master/me_re) can help us better understand how it works and how crucial code modules of Intel ME could be exploited.
* [INTEL AMT. STEALTH BREAKTHROUGH](https://www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough.pdf), [whiter paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Evdokimov-Intel-AMT-Stealth-Breakthrough-wp.pdf).
* [Has Intel ME Analysis Tool Development Petered Out? - 201708](https://blog.fpmurphy.com/2017/08/has-intel-me-analysis-tool-development-petered-out.html), the 1st time disclosure to the public about >= MEv11 are running MINIX-based OS.
* [Disabling Intel ME 11 via undocumented mode - 201708](http://blog.ptsecurity.com/2017/08/disabling-intel-me.html), HAP/AltMeDisable bit is fully disclosured to the public that NSA treats Intel ME as a risk which unlike to avoid without high cost, so they have Intel added a killswitch for their defensive program.
* [Выключаем Intel ME 11, используя недокументированный режим](https://habrahabr.ru/company/pt/blog/336242/)
* [Deep dive into Intel Management Engine disablement - 201710](https://puri.sm/posts/deep-dive-into-intel-me-disablement/)
* [JTAG в каждый дом: полный доступ через USB - 201711](https://habrahabr.ru/company/pt/blog/341946/), Intel ME memory can be full access by JTAG debugging via USB DCI, which could also possibily doing SMRAM dump for the forensics.
* [Восстановление таблиц Хаффмана в Intel ME 11.x - 201712)(https://habrahabr.ru/company/pt/blog/344056/), [English version: Recovering Huffman tables in Intel ME 11.x](http://blog.ptsecurity.com/2017/12/huffman-tables-intel-me.html)
* [The Intel Management Engine - 201712](https://bitkeks.eu/blog/2017/12/the-intel-management-engine.html)
* [Как взломать выключенный компьютер или выполнить код в Intel ME( How to run code in Intel ME) - 201801](http://blog.ptsecurity.ru/2018/01/intel-me.html)
* [Exploiting Intel’s Management Engine – Part 1: Understanding PT’s TXE PoC (INTEL-SA-00086) - 201911](https://kakaroto.homelinux.net/2019/11/exploiting-intels-management-engine-part-1-understanding-pts-txe-poc/)
* [Exploiting Intel’s Management Engine – Part 2: Enabling Red JTAG Unlock on Intel ME 11.x (INTEL-SA-00086) - 201911](https://kakaroto.homelinux.net/2019/11/exploiting-intels-management-engine-part-2-enabling-red-jtag-unlock-on-intel-me-11-x-intel-sa-00086/)


## Free/libre open source tools

* [me_cleaner](https://github.com/corna/me_cleaner/), neutralize the ME by minimizing its functions.
* [me-tools](https://github.com/skochinsky/me-tools), extract code modules for further understanding.
* [intelmetool](https://github.com/zamaudio/intelmetool), get info from ME via [MEI interfaces](https://www.kernel.org/doc/Documentation/misc-devices/mei/mei.txt) on GNU/Linux
* [MEAnalyzer](https://github.com/platomav/MEAnalyzer), show details of a image contains ME firmware.
* [MCExtractor](https://github.com/platomav/MCExtractor), Intel, AMD & VIA Microcode Extraction Tool
* [Huffman decompression for version 11.x Intel ME modules](https://github.com/IllegalArgument/Huffman11)
* [Intel ME 11.x Firmware Images Unpacker](https://github.com/ptresearch/unME11)
* [Intel ME (Manageability engine) Huffman algorithm](https://io.netgarage.org/me/)
* [Intel Management Engine: Drivers, Firmware & System Tools](http://www.win-raid.com/t596f39-Intel-Management-Engine-Drivers-Firmware-amp-System-Tools.html), it's up-to-date Windows-only tools.
* [meitools](https://github.com/embedi/meitools)
* [jeff-tools](https://github.com/skochinsky/jeff-tools), can unpack the applets from JEFF files used by Intel ME's DAL.
* [unME11](https://github.com/ptresearch/unME11), Intel ME 11.x Firmware Images Unpacker 
* [parseMFS](https://github.com/ptresearch/parseMFS), Python 2.7 scripts for parsing MFS/MFSB partition and extracting contained files.
* [unME12](https://github.com/ptresearch/unME12), Intel ME 12.x Firmware Images Unpacker
* [Intel Management Engine JTAG Proof of Concept](https://github.com/ptresearch/IntelTXE-PoC)


## IDA Pro scripts

* [meloader](https://github.com/embedi/meloader)


## Intel ME/"apps" advisory

* [INTEL-SA-00075, CVE-2017-5689: Intel Active Management Technology, Intel Small Business Technology, and Intel Standard Manageability Escalation of Privilege - 20170501](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr), [vuln detection script](https://github.com/CerberusSecurity/CVE-2017-5689)
* [INTEL-SA-00081, CVE-2017-5697: Intel AMT Clickjacking Vulnerability - Jun 5 2017](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00081&languageid=en-fr)
* [CVE-2017-5705/INTEL-SA-00086: memory corruption affected ME 11.x, SPS 4.0, and TXE 3.0 - Nov 2017](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00086&languageid=en-fr), Intel released a [detection tool](https://downloadcenter.intel.com/download/27150) for GNU/Linux can determine the status of SPS at runtime.
* [Multiple vulnerabilities begin disclosured INTEL-SA-00241 included] - 201911](https://blogs.intel.com/technology/2019/11/ipas-november-2019-intel-platform-update-ipu/#gs.gi4m2m)


## AMD PSP advisory

* [13 vulns in AMD PSP - 201803](https://safefirmware.com/amdflaws_whitepaper.pdf)


## News

* [Red alert! Intel patches remote execution hole that's been hidden in biz, server chips since 2010 - 20170501](https://www.theregister.co.uk/2017/05/01/intel_amt_me_vulnerability/), [CVE-2017-5689](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr), [mjg59's write-up](https://mjg59.dreamwidth.org/48429.html) and [INTEL-SA-00075 Mitigation Guide](https://downloadcenter.intel.com/download/26754). Vendors like [SIEMENS fixed CVE-2017-5689](https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-874235.pdf) in late June.
* [Intel & ME, and why we should get rid of ME](https://www.fsf.org/blogs/licensing/intel-me-and-why-we-should-get-rid-of-me), by FSF( Free software foundation)
* [Researchers find vulnerability in older versions of Intel ME, but you probably don't need to worry](http://www.digitaltrends.com/computing/intel-me-vulnerability/)


## ME "apps"

* [iDRAC](http://www.dell.com/support/manuals/us/en/19/idrac8-with-lc-v2.05.05.05/iDRAC8_2.05.05.05_UG-v1/Monitoring-Performance-Index-of-CPU-Memory-and-IO-Modules?guid=GUID-CC66A8FC-4644-4633-9B24-1EAF448BC4EC&lang=en-us)

### Intel SGX

  * [State considered harmful - 201512](https://blog.invisiblethings.org/papers/2015/state_harmful.pdf)
  * [Intel SGX Explained - 2016](https://eprint.iacr.org/2016/086.pdf)
  * [Some notes on the Monotonic Counter in Intel SGX and ME - 201711](https://davejingtian.org/2017/11/10/some-notes-on-the-monotonic-counter-in-intel-sgx-and-me/)
  * [Overview of Intel SGX - Part 1, SGX Internals - 201807](https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html)

### Intel SGX attack, most of them via side channel

  * [Malware Guard Extension: Using SGX to Conceal Cache Attacks - 201702](https://arxiv.org/abs/1702.08719)
  * [DR.SGX: Hardening SGX Enclaves against Cache Attacks with Data Location Randomization](https://arxiv.org/abs/1709.09917)
  * [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/abs/1710.00551)
  * [SGX-Bomb: Locking Down the Processor via Rowhammer Attack - 2017](https://sslab.gtisc.gatech.edu/assets/papers/2017/jang:sgx-bomb.pdf)
  * [Some notes on the Monotonic Counter in Intel SGX and ME - 201711](https://davejingtian.org/2017/11/10/some-notes-on-the-monotonic-counter-in-intel-sgx-and-me/)
  * [CacheQuote: Efficiently Recovering Long-termSecrets of SGX EPID via Cache Attacks - 2018](https://tches.iacr.org/index.php/TCHES/article/view/879/831)
  * [ZeroTrace: Oblivious Memory Primitives from Intel SGX - 2018](https://eprint.iacr.org/2017/549.pdf), [source code](https://github.com/sshsshy/ZeroTrace).
  * [Spectre attack against SGX enclave - 201801](https://github.com/lsds/spectre-attack-sgx)
  * [Foreshadow - 201808](https://foreshadowattack.eu/)
  * [Interface-Based Side Channel Attack Against Intel SGX](https://arxiv.org/abs/1811.05378)
  * [SGX-Step: A Practical Attack Framework for Precise Enclave Execution Control](https://github.com/jovanbulck/sgx-step)
  * [Plundervolt - 201912](https://plundervolt.com/)
  * 202006: [SGAxe](https://sgaxe.com/) and [CROSSTalk](https://www.vusec.net/projects/crosstalk/) demonstrates enclave-2-enclave attack surface in practical.


#### Intel SGX implementation
  * [Intel SGX for Linux*](https://github.com/intel/linux-sgx),  comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW).
  * [Microsoft Haven](https://www.microsoft.com/en-us/research/publication/shielding-applications-from-an-untrusted-cloud-with-haven/)
  * [SCONE: Secure Linux Containers with Intel SGX](https://www.usenix.org/system/files/conference/osdi16/osdi16-arnautov.pdf)
  * [Graphene Library OS with Intelregistered SGX Support](https://github.com/oscarlab/graphene)
  * [Panoply: Low-TCB Linux Applications with SGX Enclaves](https://shwetasshinde24.github.io/Panoply/), the paper is [here](http://www.comp.nus.edu.sg/~tsunami/papers/panoply_ndss17.pdf).
  * [ZeroTrace: Oblivious Memory Primitives from Intel SGX - 2018](https://eprint.iacr.org/2017/549.pdf), the imp for server device >= skylake. [source code](https://github.com/sshsshy/ZeroTrace).

#### Enclave framework

  * [CCF](https://github.com/Microsoft/CCF)
  * [Asylo](https://github.com/google/asylo)


##### ITL

  * [Trusted Execution In Untrusted Cloud - 201112](https://blog.invisiblethings.org/2011/12/13/trusted-execution-in-untrusted-cloud.html)
  * [Thoughts on Intel's upcoming Software Guard Extensions (Part 1) - 201308](https://blog.invisiblethings.org/2013/08/30/thoughts-on-intels-upcoming-software.html)
  * [Thoughts on Intel's upcoming Software Guard Extensions (Part 2) - 201309](https://blog.invisiblethings.org/2013/09/23/thoughts-on-intels-upcoming-software.html)
  * [Introducing graphene-ng: running arbitrary payloads in SGX enclaves - 201806](https://blog.invisiblethings.org/2018/06/11/graphene-ng.html)


## Dark side of AMD

* [AMD x86 SMU firmware analysis - 201412](https://media.ccc.de/v/31c3_-_6103_-_en_-_saal_2_-_201412272145_-_amd_x86_smu_firmware_analysis_-_rudolf_marek), [slide](https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2503/original/ccc-final.pdf)
* [AMDFlaws - 201802](https://storage.googleapis.com/wzukusers/user-28822230/documents/5c5b3fd28b669cTWPzwo/AMDFlaws%20Lecture%20Slides.pdf), vuln/exploit on AMD PSP.
* [smutool](https://github.com/zamaudio/smutool)
