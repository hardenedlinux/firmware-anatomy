## Intel SGX and ME

SGX的设计和实现非常复杂，Intel为了实现SGX从x86平台各个层面都做了大量的改动：

* 硬件层面，比如QPI传输中硬编码MEE以实现一定程度抗击侵入式攻击
* 微码层面，实现特定指令
* 固件层面，大量使用Intel ME中的代码模块，另外更换了Intel ME的基础架构

因为牵涉[Intel ME](https://github.com/hardenedlinux/firmware-anatomy/blob/master/hack_ME/me_info.md)所以HardenedLinux社区有兴趣做一些分析，毕竟[Hardening the COREs方案的标准版本](https://github.com/hardenedlinux/hardenedlinux_profiles/blob/master/slide/hardening_the_core.pdf)中我们是清理掉了大部分ME code modules以及学习老大哥( NSA)的防御体系直接开启HAP/altdisable bit，在完全搞清楚code modules和ME基础核心组建( BUP/KERNEL/etc)之间关系以前我们不会使用代码模块白名单的方案，如果在这种高安全性场景下我们会使用其他方案去替代SGX所能提供的功能，比如remote attestation。


### SGX基础描述

* SGX把paging交给了不受信的OS，这一点和BASTION是类似的，主OS可以evict操作。
* SGX使用Intel EPID来实现attestation，这个feature如果使用microcode实现过于复杂，目前评估预计应该是ME中的code module作为privileged container被Intel私钥签名并且公钥是硬编码在自身中，EPID是remote attestation的重要功能。
* 除了EPID，SGX也使用其他ME的code module比如iclsClient使用CLS(Capability Licensing Services)


### Remote attestation

* Seal Secret和Provisisoning secret存放在e-fuses中，Provisioning Secret由Intel Key Generation Facility生成烧写到CPU后保存于Intel xx service，Seal secret是在CPU内部生成的，理论上讲对Intel是不可知的。
* EGETKEY使用certificate-based identify( MRSIGNER, ISVPRODID, ISVSVN)和SGX实现版本(CPUSVN)得到Provisioning key，这样可以让Intel provisioning service验证Provisioning Enclave被Intel签名，provisioning service也能根据CPUSVN判断是否有漏洞从而拒绝通信。
* 当Provisioning Enclave获得Provisioning key后去跟Intel provisioning service通信并且验证自己后，service生成Attestation key给Provisioning Enclave，enclave使用Provisionging Seal key对AK进行加密然后保存。
* AK使用EPID密码系统，EPID作为group signature scheme为signer提供一定的匿名性，Intel key provisioning service是签发方，它会公布Group Public Key而会自己保存Master Issuing Key，在provisioning enclave向service验证自己后，service会生成一个EPID member private key作为AK然后执行EPID Join protocol去加入group，之后Quoting Enclave使用EPID MPK生成attestation signature。

技术风险：
* issued SIGSTRUCT被泄漏，攻击者可以使用SGX调试特性构建debugging provisiong或者Quoting enclave去修改代码，也可以获得128-bit provisiong key去和Intel service通信


### K* of SGX

根据Intel专利的描述，SGX的实现依赖于CPU电路的global secret keys复杂KDF过程以及存放在eFUSE中，Chipworks报价$50-250k可以完整的提取Intel i5处理器的eFUSE，所以eFUSE内容是由一把master key( 专利中称为"global wrapping logic key")加密的。GWK用于加密一个用于重新生成CPU的EPID key的256-bit的信息和一把128-bit pre-seed key 0，eFUSE也包含了明文保存的128-bit pre-seed key 1和一个32-bit EPID group ID，GWK是硬编码到芯片电路中，所有的芯片生产厂都共享mask set，这样的流程增加了攻击成本，但也有被逆向的可能。

SGX也使用了PUF，用于在provisioning阶段为设备生成对称密钥，PUF key被GWK加密并且传输到key generation server，之后key generation server用PUB key加密芯片的fuse key然后传输给芯片，PUF key增加了获得chip fuse key的成本，攻击者必须同时攻陷provisioning stage。

ME也有一个eFUSE用于保存为fTPM提供的EPID key。CPU和ME之间通过DMI bus传输EPID key不安全，第一种方案是Provision enclave使用provisioning seal key加密DAK，这个方案假设ME是不可信的flash memeory，所以不能使用fTPM。另一种方案是使用key agreement protocol在DMI bus之间建立安全通信频道，ME fw可以用于存储DAK，也可以实现fTPM。

* [Secure provisioning of secret keys during integrated circuit manufacturing - US20140093074A1](https://patents.google.com/patent/US20140093074)
