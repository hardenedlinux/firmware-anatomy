## Info about firmware security

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu 

Ring -2...

## Slide/presentation

* [Hacking the Extensible Firmware Interface - 200708](https://www.blackhat.com/presentations/bh-usa-07/Heasman/Presentation/bh-usa-07-heasman.pdf), [video](https://www.youtube.com/watch?v=g-n42Q-Pxsg)
* [Attacking Intel® BIOS - 200907](http://invisiblethingslab.com/resources/bh09usa/Attacking%20Intel%20BIOS.pdf)
* [Getting into the SMRAM: SMM Reloaded - 2009](https://www.ssi.gouv.fr/uploads/IMG/pdf/Cansec_final.pdf)
* [System Management Mode Design and Security Issues - 201002](http://www.ssi.gouv.fr/uploads/IMG/pdf/IT_Defense_2010_final.pdf)
* [DE MYSTERIIS DOM JOBSIVS Mac EFI Rootkits - 201207](https://media.blackhat.com/bh-us-12/Briefings/Loukas_K/BH_US_12_LoukasK_De_Mysteriis_Dom_Jobsivs_Slides.pdf), [paper](http://ho.ax/downloads/De_Mysteriis_Dom_Jobsivs_Black_Hat_Paper.pdf) and [video](https://www.youtube.com/watch?v=W21ZIaKf5HA)
* [A New Class of Vulnerabilities in SMI Handlers - 201503](https://cansecwest.com/slides/2015/A%20New%20Class%20of%20Vulnin%20SMI%20-%20Andrew%20Furtak.pdf)
* [How Many Million BIOSes Would you Like to Infect? - 201506](http://legbacore.com/Research_files/HowManyMillionBIOSWouldYouLikeToInfect_Full.pdf), [paper](http://legbacore.com/Research_files/HowManyMillionBIOSesWouldYouLikeToInfect_Whitepaper_v1.pdf)
* [ANALYSIS OF THE ATTACK SURFACE OF WINDOWS 10 VIRTUALIZATION - BASED SECURITY - 201608](https://www.blackhat.com/docs/us-16/materials/us-16-Wojtczuk-Analysis-Of-The-Attack-Surface-Of-Windows-10-Virtualization-Based-Security.pdf), [white paper](https://www.bromium.com/sites/default/files/us-16-wojtczuk-analysis-of-the-attack-surface-of-windows-10-virtualization-based-security-wp-v2.pdf) and [video](https://www.youtube.com/watch?v=_646Gmr_uo0)
* [BARing the System: New vulnerabilities in Coreboot & UEFI based systems - 201701](http://www.intelsecurity.com/advanced-threat-research/content/data/REConBrussels2017_BARing_the_system.pdf)
* [UEFI  Firmware  Rootkits: Myths  and  Reality - 201703](https://www.blackhat.com/docs/asia-17/materials/asia-17-Matrosov-The-UEFI-Firmware-Rootkits-Myths-And-Reality.pdf)
* [Attacking hypervisors through hardware emulation - 201703](https://www.troopers.de/downloads/troopers17/TR17_Attacking_hypervisor_through_hardwear_emulation.pdf)
* [Training: Security of BIOS/UEFI System Firmware from Attacker and Defender Perspectives - 201705](https://github.com/advanced-threat-research/firmware-security-training)
* [BETRAYING THE BIOS: WHERE THE GUARDIANS OF THE BIOS ARE FAILING - 201708](https://www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf), [write-up](https://threatvector.cylance.com/en_us/home/black-hat-vegas-where-the-guardians-of-the-bios-are-failing.html)
* [Digging Into The Core of Boot](https://recon.cx/2017/montreal/resources/slides/RECON-MTL-2017-DiggingIntoTheCoreOfBoot.pdf)
* [Replace Your Exploit-Ridden Firmware with Linux - 201710](https://schd.ws/hosted_files/osseu17/84/Replace%20UEFI%20with%20Linux.pdf), [video](https://www.youtube.com/watch?v=iffTJ1vPCSo)
* [Betraying the BIOS: Going Deeper into BIOS Guard Implementations - 201803](https://github.com/REhints/Publications/tree/master/Conferences/Betraying%20the%20BIOS), [video](https://www.youtube.com/watch?v=kSQVGFbTfqE)
* [Attacking Hardware Root of Trust from UEFI Firmware - 201903](https://www.youtube.com/watch?v=Ap-2CnoyBek)
* [Now You See It: TOCTOU Attacks Against Secure Boot and BootGuard - 201905](https://conference.hitb.org/hitbsecconf2019ams/materials/D1T1%20-%20Toctou%20Attacks%20Against%20Secure%20Boot%20-%20Trammell%20Hudson%20&%20Peter%20Bosch.pdf), [bug track of CVE-2019-11098](https://bugzilla.tianocore.org/show_bug.cgi?id=1614) for TianoCore.


## Article/paper

* [SMM Rootkits: A New Breed of OS Independent Malware - 2008](http://www.co-c.net/repository-securite-informatique/Papers/SMM-Rootkits-Securecom08.pdf), [video](https://media.blackhat.com/bh-usa-08/video/bh-us-08-Embleton/black-hat-usa-08-embleton-smmrootkit-hires.m4v) at BH08 USA.
* [System Management Mode Hack Using SMM for "Other Purposes" - 200803](http://webcache.googleusercontent.com/search?q=cache:fpIz7WipFBUJ:phrack.org/issues/65/7.html+&cd=1&hl=zh-TW&ct=clnk&gl=hk)
* [Attacking SMM Memory via Intel® CPU Cache Poisoning - 200903](http://invisiblethingslab.com/resources/misc09/smm_cache_fun.pdf), code is [here](http://invisiblethingslab.com/resources/misc09/o68-2.tgz).
* [Another Way to Circumvent Intel Trusted Execution Technology - 200912](http://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf)
* [A Real SMM Rootkit: Reversing and Hooking BIOS SMI Handlers](http://webcache.googleusercontent.com/search?q=cache:-N3__o-F_Z4J:phrack.org/issues/66/11.html+&cd=1&hl=zh-TW&ct=clnk&gl=hk)
* [Following the White Rabbit: Software Attacks against Intel® VT-d - 201103](http://www.invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf)
* [Exploring new lands on Intel CPUs (SINIT code execution hijacking) - 201112](http://www.invisiblethingslab.com/resources/2011/Attacking_Intel_TXT_via_SINIT_hijacking.pdf)
* [Malicious Code Execution in PCI Expansion ROM](http://resources.infosecinstitute.com/pci-expansion-rom/)
* [BIOS Based Rootkits - 201306](http://www.exfiltrated.com/research-BIOS_Based_Rootkits.php)
* [Hardware and firmware attacks: Defending, detecting, and responding](https://code.facebook.com/posts/182707188759117/hardware-and-firmware-attacks-defending-detecting-and-responding/), video is [here](https://www.youtube.com/watch?v=z4-N2HyQMVU).
* [A Tour beyond BIOS Using Intel VT-d for DMA Protection in UEFI BIOS - 201501](https://firmware.intel.com/sites/default/files/resources/A_Tour_Beyond_BIOS_Using_Intel_VT-d_for_DMA_Protection.pdf), the [updated version](https://firmware.intel.com/sites/default/files/Intel_WhitePaper_Using_IOMMU_for_DMA_Protection_in_UEFI.pdf) is released in Oct 2017.
* [Detecting BadBIOS, Evil Maids, Bootkits, and Other Firmware Malware - 201710](https://ia601507.us.archive.org/2/items/seagl-2017/seagl-2017.pdf)
* [Reverse engineering the Intel FSP… a primer guide! - 201711](https://puri.sm/posts/primer-to-reverse-engineering-intel-fsp/)
* [LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group - 201809](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/), [paper](https://www.welivesecurity.com/wp-content/uploads/2018/09/ESET-LoJax.pdf)
* [CODE CHECK(MATE) IN SMM - 201812](https://www.synacktiv.com/posts/exploit/code-checkmate-in-smm.html)
* [UEFI rootkit tricks( .ru version) - 201812](https://exelab.ru/f/index.php?action=vthread&forum=2&topic=25409&page=1#8)


## BootJail

* [Intel Boot Guard research - 2016](https://github.com/flothrone/bootguard)
* [Safeguarding rootkits: Intel BootGuard - 2016-12](https://github.com/flothrone/bootguard), ME is original set as ["Manufacturing Mode" until "OEM Public Key Hash" and "Boot Guard Profile Configuration" being copied to CPU fuses](https://trmm.net/Bootguard) to make it either enable or disable. Alexander Ermolov shows us the ["Schrodinger's Bootguard" is neither in enabled or disabled](https://support.lenovo.com/us/en/solutions/len_9903), which can be exploited for further persistent uses.
* [BETRAYING THE BIOS: WHERE THE GUARDIANS OF THE BIOS ARE FAILING - 201708](https://www.blackhat.com/docs/us-17/wednesday/us-17-Matrosov-Betraying-The-BIOS-Where-The-Guardians-Of-The-BIOS-Are-Failing.pdf)
* [Bypassing Intel Boot Guard - 201710](https://web.archive.org/web/20171006051839/https://embedi.com/blog/bypassing-intel-boot-guard)
* [ATTACKING HARDWARE ROOT OF TRUST FROM UEFI FIRMWARE - 201903](https://github.com/REhints/Publications/blob/master/Conferences/Bypassing%20Hardware%20Root%20of%20Trust/offcon2019_final.pdf)


## BMC

* [Common BMC VulnerabilitiesAnd How to Avoid Repeating Them - 201909](https://osfc.io/uploads/talk/paper/39/Common_BMC_vulnerabilities_and_how_to_avoid_repeating_them.pdf)
* [Subverting your server through its BMC - 201802](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Subverting-your-server-through-its-BMC-the-HPE-iLO4-case.pdf), [poc](Subverting your server through its BMC: the HPE iLO4 case)
* [The Unbearable Lightness of BMC - 201808](https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf), [white paper](https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC-wp.pdf)
* [Remotely Attacking System Firmware -201808](https://i.blackhat.com/us-18/Wed-August-8/us-18-Michael-Shkatov-Remotely-Attacking-System-Firmware.pdf)
* [Insecure Firmware Updates in Server Management Systems - 201809](https://blog.eclypsium.com/2018/09/06/insecure-firmware-updates-in-server-management-systems/)
* [Turning your BMC into a revolving door - 201811](https://airbus-seclab.github.io/ilo/ZERONIGHTS2018-Slides-EN-Turning_your_BMC_into_a_revolving_door-perigaud-gazet-czarny.pdf)
* [CVE-2019-6260: Gaining control of BMC from the host processor - 201901](https://www.flamingspork.com/blog/2019/01/23/cve-2019-6260-gaining-control-of-bmc-from-the-host-processor/)
* [Riding the lightning: iLO4&5 BMC security wrap-up - 201903](https://airbus-seclab.github.io/ilo/INSOMNIHACK2019-Slides-Riding_the_lightning_iLO4_5_BMC_security_wrapup-perigaud-gazet-czarny.pdf)
* [Defending Against Out-of-Band Management BMC Attacks - 201904](https://firmwaresecurity.files.wordpress.com/2019/05/lfnw2019-bmc.pdf), [video](https://www.youtube.com/watch?v=C6Q0_N54GcA)

## Intel docs

* [PCIe* Device Security Enhancements Specification](https://www.intel.com/content/www/us/en/io/pci-express/pcie-device-security-enhancements-spec.html)


## OEM update

* [Out-of-Box ExploitationA Security Analysis of OEM Updaters - 201605](https://duo.com/assets/pdf/out-of-box-exploitation_oem-updaters.pdf)
* [ASUS LiveUpdate of UEFI sent UNauthenticated - 201606](https://firmwaresecurity.com/2016/06/05/asus-liveupdate-of-uefi-sent-authenticated/)


## GPU-based attack
* [GPU-Assisted Malware - 2010](http://dcs.ics.forth.gr/Activities/papers/gpumalware.malware10.pdf)
* [You Can Type, but You Can’t Hide: A Stealthy GPU-based Keylogger - 201304](http://www.cs.columbia.edu/%7Emikepo/papers/gpukeylogger.eurosec13.pdf), [PoC code](https://github.com/x0r1/Demon)
* [jellyfish: GPU rootkit PoC - 201504](https://github.com/x0r1/jellyfish)


## HDD-based attack
* [Hard disks: more than just block devices - 201308](http://bofh.nikhef.nl/events/OHM/video/d2-t1-13-20130801-2300-hard_disks_more_than_just_block_devices-sprite_tm.m4v)
* [Implementation and Implications of a Stealth Hard-Drive Backdoor - 201403](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf)
* [Active disk antiforensics and hard disk backdoor - 201409](https://www.dfrws.org/sites/default/files/session-files/pres-some_practical_thoughts_concerning_active_disk_antiforensics.pdf), [video](https://www.youtube.com/watch?v=8Zpb34Qf0NY)


## Countermeansure
* [SBAP: Software-Based Attestation for Peripherals](http://www.netsec.ethz.ch/publications/papers/li_mccune_perrig_SBAP_trust10.pdf)
* [VIPER: Verifying the Integrity of PERipherals’ Firmware - 201110](https://pdfs.semanticscholar.org/4cde/50e94cada9bcaaec0f753e1b4dec3b6c355c.pdf)
* [What if you can’t trust your network card? - 2011](https://pdfs.semanticscholar.org/82c0/086755479360935ec73add346854df4d1304.pdf)


## Microcode
* [GLM uCode dumps](https://github.com/chip-red-pill/glm-ucode)
* [Intel LDAT notes - 202005](https://pbx.sh/ldat/)
* [Notes on Intel Microcode Updates - 201212](http://inertiawar.com/microcode/)
* [Reverse Engineering x86 Processor Microcode - 201708](http://syssec.rub.de/media/emma/veroeffentlichungen/2017/08/16/usenix17-microcode.pdf), [video](https://www.youtube.com/watch?v=I6dQfnb3y0I) and [PoC code](https://github.com/RUB-SysSec/Microcode)


## TPM
* [Chromebook: TPM firmware vulnerability: technical documentation - 201710](https://sites.google.com/a/chromium.org/dev/chromium-os/tpm_firmware_update)
* [TPM Genie: I2C bus interposer for discrete TPMs](https://github.com/nccgroup/TPMGenie)


## Free/libre open source project

* [CHIPSEC](https://github.com/chipsec/)
* [UEFITool](https://github.com/LongSoft/UEFITool)
* [Firmware research timeline](http://timeglider.com/timeline/5ca2daa6078caaf4)


### [coreboot](https://www.coreboot.org/)

  * [heads/nerf](https://github.com/osresearch/heads)
  * [linuxboot](https://github.com/linuxboot/linuxboot)

### Attestation

  * [Firmware TPM and SSL/TLS Protocol based Remote Attestation Framework for UEFI Secure Booting](https://github.com/Hecmay/UEFI-Attestation)

### BMC

* [OpenBMC](https://github.com/openbmc/openbmc)
* [u-bmc](https://u-bmc.readthedocs.io/en/latest/)
* [bmclib](https://github.com/bmc-toolbox/bmclib)


## IDA Pro scripts & RCE stuff

* [ida-efiutils](https://github.com/snare/ida-efiutils)
* [EFISwissKnife](https://github.com/gdbinit/EFISwissKnife)
* [IDAPython-scripts-for-UEFI-analisys](https://github.com/kyurchenko/IDAPython-scripts-for-UEFI-analisys)
* [Decompiler internals: microcode - 201802](https://recon.cx/2018/brussels/resources/slides/RECON-BRX-2018-Decompiler-internals-microcode.pdf)


## Vendor advisory

* [Unsafe Opcodes exposed in Intel SPI based products( INTEL-SA-00087/CVE-2017-5703)](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00087&languageid=en-fr), Lenovo released the [patch](https://support.lenovo.com/us/en/solutions/LEN-16445).


## Crazy security standard/Compliance

* [NIST SP 800-147: BIOS Protection Guidelines 201104](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-147.pdf)
* [NIST SP 800-147B: BIOS Protection Guidelines for Servers](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-147B.pdf)
* [NIST SP 800-193: DRAFT Platform Firmware Resiliency Guidelines](http://csrc.nist.gov/publications/PubsDrafts.html#SP-800-193)
* [NCSC-UK: EUD Security Guidance: Windows 10 - 1703](https://www.ncsc.gov.uk/guidance/eud-security-guidance-windows-10-1703#devicefirmware)
