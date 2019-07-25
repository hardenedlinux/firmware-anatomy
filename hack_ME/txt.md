## Intel Trusted Execution Technology


### Materials

* [Intel TXT website](https://www.intel.com/content/www/us/en/architecture-and-technology/trusted-infrastructure-overview.html)
* [Intel TXT white paper](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/trusted-execution-technology-security-paper.pdf)
* [Intel Trusted Execution Technology (Intel TXT) Enabling Guide](http://software.intel.com/en-us/articles/intel-trusted-execution-technology-intel-txt-enabling-guide)
* [Intel Trusted Execution Technology (Intel TXT) Software Development Guide](https://www.intel.com/content/dam/www/public/us/en/documents/guides/intel-txt-software-development-guide.pdf)
* [Intel® Trusted Execution Technology for Server Platforms - 2013](https://link.springer.com/content/pdf/10.1007%2F978-1-4302-6149-0.pdf)
* [Intel® Trusted Execution Technology (Intel® TXT) BIOS Enabling On Dell Servers Using Automation - 2012](https://software.intel.com/en-us/articles/intel-trusted-execution-technology-intel-txt-bios-enabling-on-dell-servers-using-automation)
* [Building the Infrastructure for Cloud Security - 2014](https://www.apress.com/us/book/9781430261452)
* [Intel TXT Platform Components](https://ebrary.net/24862/computer_science/intel_platform_components)


## coreboot implementation

* [Intel STM](https://firmware.intel.com/content/smi-transfer-monitor-stm)
* [Intel ACMs](https://github.com/coreboot/coreboot/blob/master/Documentation/security/intel/acm.md)
* [Intel IBB](https://github.com/coreboot/coreboot/blob/master/Documentation/security/intel/txt_ibb.md)


## Vendor's view

* [Trusted Cloud computing with Intel TXT: The challenge - 201404](https://www.mirantis.com/blog/trusted-cloud-intel-txt-security-compliance/)


## Vulnerablity assessment

* [Attacking Intel Trusted Execution Technology - 200902](https://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf), [slide](https://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20slides.pdf)


## Implementation

* [OpenAttestation](https://github.com/OpenAttestation/OpenAttestation)
* [STM](https://github.com/jyao1/STM.git)
* [OpenXT](https://github.com/OpenXT/)


## NOTES

You can see Intel TXT as a hardened version of measuredboot. Under TPMv2, SM3 digest algorithm can't work with the current( most?) TXT implementation.
