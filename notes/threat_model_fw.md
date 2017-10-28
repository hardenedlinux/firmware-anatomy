# 关于固件安全评估的笔记 - Dec 2016

注：这个时间点上干掉ME的行为还未在社区大规模进行，而HAP bit也没有被发现。


Offensive side以压倒性的优势在"lower" level attack中非常明显，而重度依赖自由软件的IT基础设施至少在3个领域受到来自"lower" level的威胁：1) 数据中心里的服务器(GNU/Linux) 2) Mobile(Android) 3) IoT(混乱的BSP+ Linux/Android) 而固件作为核心基础架构的重要组成部分，这一块的防御是时候排上日程去完成早该完成的社区最佳实践。

Hi Hardenedlinux's fellow maintainers,

自从2009年以来自由软件世界都迫切的面临固件层面的威胁，主要原因有几个方面，第一是自由固件的实现一直以来都无法很好的大规模的适配各种机型，第二个方面则是从技术的层面上讲，以x86为例子，威胁建模在2009年之前大概是这样的：

RING 3，主要通过编译器层面的mitigation来进行，这个可以参考Hardenedlinux网站"Compiler/编译器相关" https://hardenedlinux.github.io/about3/
RING 0，当然是PaX/Grsecurity，KSPP是2015年12月以后的产物

进入2010年以后，虚拟化的普及以及UEFI secure boot被提上了日程，导致了在威胁建模里新增加了两个层面：

RING -1，hypervisor的威胁主要有逃逸，持久化的攻击披露是不久的事情( http://phrack.org/issues/69/15.html#article)
RING -2，针对SMM以及固件相关的攻击，对于UEFI Secureboot最但疼之事莫过于bypass signature verify;-)

而Intel在原本就很混乱的战场上为自由软件阵营引入了一个终极恶魔： RING -3，躲藏在RING -3世界里的ME，在这个层面上的厂商后门或者攻击者利用漏洞攻占ME并且持久化（注：XXX）都是对于上面层级的世界无法检测和感知的

ME随着x86平台的大规模部署已经是定局，但我们(HardenedLinux maintainers)仍然需要在某些层面上考虑与其对抗的可能性，根据极端场景设计了几种基于自由软件的防御方案，虽然大规模工程化难度很大，但对于保护数据核心资产比如根密钥还是可能的：

1，干掉ME的场景 + 自由软件固件Coreboot + 对kernel和kernel module进行验签，这种场景目前还没有确定是基于grub本身作为payload或者payload为seabios然后载入grub


2，干掉ME使用OEM BIOS的UEFI secure boot + 对kernel和kernel module进行验签，这种方案大概和Debian正在做的方案类似（除了干掉ME的部分，因为发行版社区不会做这个事情）


3，大规模部署的场景：不干掉ME，其他和2)一样

有2点需要大家注意：

1) 最极端的加固场景的前提是干掉ME，而这一步的最佳实践Persmule已经完成：
https://hardenedlinux.github.io//firmware/2016/11/17/neutralize_ME_firmware_on_sandybridge_and_ivybridge.html

2) 内核的部分都是基于PaX/Grsecurity内核做reproducible builds，这个也主要由icenowy完成了一段时间了，这里也感谢biergaizi完成了PaX/GRsecurity的桌面适配测试以及文档的工作：
https://github.com/hardenedlinux/grsecurity-reproducible-build

https://github.com/hardenedlinux/grsecurity-101-tutorials

我们会把关于这个项目的update到这里：

https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/debian_trust_chains.md


另外，以下一篇paper和一本书是记载了诸多关于我们所面对的“敌人”的特性，知己知彼很重要！

Intel x86 considered harmful
https://blog.invisiblethings.org/papers/2015/x86_harmful.pdf

Platform Embedded Security Technology Revealed: Safeguarding the
Future of Computing with Intel Embedded Security and Management Engine
http://download.springer.com/static/pdf/940/bok%253A978-1-4302-6572-6.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fbook%2F10.1007%2F978-1-4302-6572-6&token2=exp=1482307879~acl=%2Fstatic%2Fpdf%2F940%2Fbok%25253A978-1-4302-6572-6.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fbook%252F10.1007%252F978-1-4302-6572-6*~hmac=8dfe35980dc1ce90babcfe71699db6c5e9a745710f50ee2d3be6d58d053fee5b

下面是之前的笔记，也分享出来吧：

传统上把BIOS（最近称为UEFI firmware)称为操作系统执行的root of trust是因为：

1) BIOS是在CPU上执行的第一批代码，也可以恶意的修改操作系统镜像
2) BIOS具有权限访问所有的硬件，它可以对设备进行重编程，比如在某些时间点上开始DMA写操作预定义内存地址，这些地址是后面OS或者Hypervisor会加载的地方。
3) BIOS提供执行SMM的代码，可以轻易的植入Ring -2 rootkit

案例：LightEater偷取GPG keys


BIOS的威胁模型：

1) 厂商恶意的植入后门
2) 攻击者修改掉了原始的BIOS，由于:
    a) 不具备reflashing的保护机制( https://cansecwest.com/csw09/csw09-sacco-ortega.pdf)
    b) BIOS具有reflashing的保护机制，但通过针对原始BIOS的漏洞利用在reflashing前或者SMM lock前进行代码执行:
http://invisiblethingslab.com/resources/bh09usa/Attacking%20Intel%20BIOS.pdf
J. Butterworth, C. Kallenberg, and X. Kovah. BIOS chronomancy: Fixing
the Core Root of Trust for Measurement. In BlackHat, 2013
https://www.blackhat.com/docs/us-14/materials/us-14-Kallenberg-Extreme-Privilege-Escalation-On-Windows8-UEFI-Systems-WP.pdf
https://media.ccc.de/browse/congress/2014/31c3_-_6129_-_en_-_saal_2_-_201412282030_-_attacks_on_uefi_security_inspired_by_darth_venamis_s_misery_and_speed_racer_-_rafal_wojtczuk_-_corey_kallenberg.html#download
http://legbacore.com/Research_files/HowManyMillionBIOSesWouldYouLikeToInfect_Whitepaper_v1.pdf
    c) 物理攻击，攻击者通过SPI编程器替换firmware内容

可能的解决方案：

1) 芯片组强制firmware存储的flash内存保护，必须配对相关的签名才可以update( Secure Boot)
2) 使用硬件辅助，比如TPM和Intel TXT
3) 通过Intel Boot Guard，硬件强制CPU不会执行白名单以外的firmware

1)应该是可以在自由软件的实现范围内去实现，比如Secure Boot on
Debian如果能干掉微软的证书替换成Debian社区或者用户定制的，2)也是辅助手段，而3)在某种程度上危害到了软件自由，因为Boot
Guard一旦开启验签就会拒绝掉包括自由软件实现在内的firmware

简单的两种Firmware防护方案：
1) white-listing approach
2) Meansuring approach; Meansurement这个term在这个上下文下是指计算hash

常见的meansurement实现是通过TPM，通常通过LPC总线连接南桥，TPM通过PCR Extend操作提供API对只有TPM可知的私钥完成验证签名，或者有条件的开放一些secrets如果meansurement满足一个预定义值（SEAL/UNSEAL操作）。有价值的实现应该是在启动过程中满足一定的条件才去unlock一些功能或者apps如果firmware的hash是正确的。但只让机器对用户认证而没有针对用户去认证机器让EVIL Maid攻击变得可能。
https://en.wikipedia.org/wiki/BitLocker
http://blog.invisiblethings.org/2009/10/15/evil-maid-goes-after-truecrypt.html
http://testlab.sit.fraunhofer.de/content/output/project_results/bitlocker_skimming/

抗击Evil Maid:
http://blog.invisiblethings.org/2011/09/07/anti-evil-maid.html
https://mjg59.dreamwidth.org/35742.html

TCG spec里规定的CRTM( Core Root of TRust for
Measurement)必须存在于不可涂改的ROM类型的内存里，即使攻击着reflash了BIOS代码，原始的(可信)CRTM仍然会最早运行然后在flash中measure修改的代码，然后发送hash给TPM，这让恶意代码没机会运行。但CRTM是BIOS使用SPI flash内存实现的，这导致如果直接攻击BIOS，比如bypass signature verification也会成为可能。Intel TXT曾经尝试简化(排除BIOS/Boot/OS loader)和实现独立于BIOS提供的信任链条，但TXT的问题在于Intel过渡依赖于SMM用于加载hypervisor和OS，而问题BIOS一旦被日就可以随意加载SMM，后来就引入了BootGuard;-)

http://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf
http://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf

Boot Guard提供两种模式：1) Meausred boot 2) Verified boot，外加一种混合两种的模式，提供了一个处理器提供的基于ROM的"信任"代码会被最早执行，这样使得BG扮演者CRTM的角色，CRTM验证下一个块的代码（从flash中读）被称为IBB( Initial Boot Block)。OEM在制造芯片组时会做一些熔丝的设定来让过程不可逆，BG的CRTM会做 1)被动的扩展相应measured boot block的hash的TPM的PCRs,或者 2) 检查是否boot block被OEM硬编码在处理器熔丝里的key正确的签名，对于 2)的场景，BG有一个白名单只允许boot进入厂商认证的IBB，这也是用户的软件自由受到侵害的一个方面，这也多了一个威胁：如果后门是Intel埋的那将很难检测到，Joanna也谈到处理器的boot ROM代码 and/or 关联的ACM模块(Authenticated Code Modules) A里实现一个简单的判断if( IBB[OFFSET] == BACKDOOR_MAGIC)满足的话就直接跳过OEM烧写的公钥验签然后执行任何IBB，如果后门是在处理器内部的boot ROM里几乎没法去读取这个boot ROM。在Intel处理器的启动顺序里，会先启动bootROM然后是ACM，而ACM可以是OEM的binary blob，从这个层面上讲，Intel可以不需要自己去制造和分发后门，而只需要把为ACM签名的key交给攻击者即可。

在reset vector上执行第一条指令(如果开启BootGuard就是IBB)-->所有设备初始化(BIOS/UEFI)-->Bootloader-->OS
kernel:
http://invisiblethingslab.com/resources/bh09usa/Attacking%20Intel%20BIOS.pdf
http://www.ssi.gouv.fr/uploads/IMG/pdf/csw-trustnetworkcard.pdf

UEFI Secure Boot仍然面对上面所有的问题，而且PKI带来了新的问题，如果BIOS厂商被要求给FBI提供一个后门，厂商可以签发一个额外的证书，这样可以发起Evil
Maid攻击，当然如果把Secure Boot的meansurement存在TPM里可以解决这个问题，那问题是为什么还需要Secure
Boot?个人是支持Secure Boot for Debian的项目，如果能把厂商的证书换掉Secure
Boot也可以为自由软件的安全信任链条构建更好的防御。

SGX是继TXT后Intel的尝试，而这次不光把BIOS和firmware排除在信任链条外，也把内核也排除了，通过称为处理器提供的enclaves对程序的代码和数据进行保护，有消息称ME也跟SGX实现有关系:
Xiaoyu Ruan. Platform Embedded Security Technology Revealed:
Safeguarding the Future of Computing with Intel Embedded Security and
Management Engine. Apress, 2014

Joanna做了几个总结：
1) SGX不能替代Secure Boot
2) SGX看似不能防止用户app被ME监控，ME是来自Ring -3的恶魔
3) SGX可以允许创造运行在SGX DRAM保护下无法被逆向的软件和remote attestion(这个对于IAAS环境很有用)
4) SGX放弃使用额外的TPM芯片而是使用ME中的实现，这对于Intel把private key交给第三方是很好的抵赖:
http://blog.invisiblethings.org/2013/09/23/thoughts-on-intels-upcoming-software.html

外设的问题：
1) 植入ME或者SMM恶意firmware针对网络(Wifi/NIC)的操作进行相关攻击
2) USB控制器是PCIe设备可以用VT-d来实现sandbox，但连接在上面的设备则不行，就算能sandboxing所有的USB设备:
http://blog.invisiblethings.org/2011/05/31/usb-security-challenges.html
3) 防护整个图形系统是很难的(
http://blog.invisiblethings.org/2010/09/09/untrusting-your-gui-subsystem.html)，但针对恶意GPU防御还是可行:
a) 受限的IOMMU对frame buffer的细粒度控制 b) 其他被用于跟GPU交互的页 c)
其他页都不允许访问，这个方案会大大影响使用的体验。
4) 硬盘控制器，SATA controller被逆向和植入后门已经有案例
5) 声卡的三个主要安全问题：
    a) 声卡能控制麦克风，在OS或者声卡firmware被攻陷后可以监听用户的对话
    b) 声卡能控制喇叭，在OS,BIOS/SMM,ME被攻陷后可以建立某种信道进行通信：
Luke Deshotels. Inaudible sound as a covert channel in mobile devices.
In 8th USENIX Workshop on Offensive Technologies (WOOT 14), San Diego,
CA, August 2014. USENIX Association
    c) 声卡也是总线上的设备，firmware被植入后门，在没有恰当IOMMU的保护下可以干掉OS

在RING 0上实现covert channel是一件非常容易的事情，那假设RING -3上也有类似实现的后门，那ME可能的威胁模型
http://invisiblethingslab.com/resources/bh09usa/Ring%20-3%20Rootkits.pdf

ME是一个小型计算机，由一个ARC4的RISC指令级的处理器执行，有不少应用是基于ME架构的，永远处于运行状态的远程管理工具包AMT( Advanced Mgt Technology)是ME第一个的基于ME架构的应用，现在也有作为ME实现的TPM: PTT，用于remote attestion的信任链条的EPIDhe Boot Guard，PAVP( Protected Audio and Video Path)和SGX。
