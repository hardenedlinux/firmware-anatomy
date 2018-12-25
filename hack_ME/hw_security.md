## Info about hardware security

"If you know the enemy and know yourself, you need not fear the result of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer a defeat. If you know neither the enemy nor yourself, you will succumb in every battle." ---  Sun Tzu 

If the peripheral device and firmware( e.g: Intel ME) is called "Ring -3", so let's call "Ring -4" refered as hardware level( naming is one of the hardest issue in CS, isn't it;-)). Those knowledge from offensive side will help us to know better where we are and how we react.

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


## Hardware trojan

* [Silencing Hardware Backdoors - 2011](http://www.cs.columbia.edu/~simha/preprint_oakland11.pdf)
* [A2: Analog Malicious Hardware - 2016](https://ieeexplore.ieee.org/document/7546493)
* [TrojanZero: Switching Activity-Aware Design of Undetectable Hardware Trojans with Zero Power and Area Footprint - 201811](https://arxiv.org/abs/1812.02770)


## Free/libre open source project

* [Trust-Hub](http://www.trust-hub.org/home)
