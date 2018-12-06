Sanctum项目是基于RISC-V Rocket chip开放核(特权指令1.10)去实现了一套不需要制造商提供私钥并且也能做attestation的方案，其PUF的meansurement都是基于Xilinx Zynq 7000 device ( ZC706开发板)实现的，其建议值为450对ring oscillator对应混淆128-bit secret value。

* 根据制造过程的偏差PUF产生meansurement并提供给处理器作为crypto identity
* 处理器设备内置的bootloader将PUF输出转化成一对ECC key pair，公开的部分是被制造商私钥签名
* 重新生成PUF输出需要纠错，Sanctum实现了trapdoor computational fuzzy extractor
* 重新生成的私钥用于sign整个boot image的一部分，这部分负责与remote attestation
* remote attestation过程中使用DHE以及客户端请求boot image的平台签名

Sanctum方案的几种场景:

Ciphersuite信息：SHA3, ECDSA( ed25519)

* 半信任场景，比如一块FPGA安全处理器部署在云租户环境，租户分时的使用FPGA但彼此并不信任，这个场景云厂成了“制造商”，non-volatile keys并没有意义，设备的公私钥由hash过的TRNG来生成，安全处理器在boot阶段只跟当前的公钥建立信任关系，而endorsement key由云厂提供得到SignM( PKDEV)，这也是remote attestation的基础

* 在没有信任方能参与local attestation的场景必须存在永久性公钥，由PUF生成持久私钥，重新生成key pair的过程是通过fuzzy extractor把seed传给带POK( physically obfuscated key)的KDF，P256和P512使用唯一的ring oscilator pair，M-bit部分是可半重现的:
  ** 初始key provisioning生成由厂商通过PUF完成，当安全处理器生产完成后会root of trust会provisions一个128-bit的secret s。通过s，root of trust计算出公共M-bit vector b = As + e，A是一个 M * 128大小的矩阵在GF(2)中，b和A是公开的"helper data"用于未来形态的root of trust恢复s。provisioning流程大致上是hash(s) --> ed25519 KDF计算出key pair( PKDEV, SKDEV)，s和SKDEV在conveying(PKDEV,b,..)给payload阶段被root of trust销毁，厂商可以通过payload获得PKDEV，用自己的密钥给这把pubkey签名。防止厂商重复re-provisioning的方法(e的保密性)就是使用fuse，fuse的方法是LPN( learning parity with noise)

  ** 通过LPN PUF恢复key： 每次重启root of trust从公开的(b, A)重新构造128-bit的s然后重新计算(PKDEV,SKDEV)，root trust从ring oscillator pair阵列中获得e(在provisioning s时使用的)，最终通过复杂的过程找出可逆的bit从而恢复s

  ** Payload key和endorsement: H( P) = SHA3( payload)，带SKDEV的散列结果作为ed25519 KDF种子: (PKP, SDP) = KDF.ed25519( SHA3( SKDEV, H(P)))，即使恶意payload泄漏了hash和key也不会影响SKDEV，最终处理器为payload的endorsement产生证书，CertificatesP = SignedSKDEV( SHA3( H(P), PKP))，Certs( C.DEV, C.P)，SKP和正常payload可以作为remote attestation的基础

  ** Key加密和最小化root of trust: P256/P512 AES的场景下处理器会使用对称密钥对(SKD, SKPAYLOAD)进行加密，这把对称密钥来自PUF存放在未受信的NVRAM中，最终root of trust和一个可移植版本的AES + SHA3和ed25519 KDF(包括payload不提供加密key时执行ed25519 KDF的代码)绑定，另外需要注意的是在性能上AES比每次使用KDF重现key更好，但解密增加了复杂性以及code base，这是一个对于bootrom大小需要tradeoff的方面。


## RISC-V based security solution

### Keystone

* [Keystone](https://keystone-enclave.github.io/) is RISC-V based secure enclave has more improvement based on Sanctum. It has PMP.


### Sanctum

* [RISCV with Sanctum Enclaves](https://riscv.org/wp-content/uploads/2016/11/Tue1615-RISC-V-with-Sanctum-Enclaves-Lebedev-MIT.pdf)
* [Secure Boot and Remote Attestation in the Sanctum Processor - 201804](https://eprint.iacr.org/2018/427)
* [A Formal Foundation for Secure Remote Execution of Enclaves - 2017](https://people.eecs.berkeley.edu/~rsinha/research/pubs/ccs2017.pdf)
* [Secure Processors Part I: Background, Taxonomy for Secure Enclaves and Intel SGX Architecture - 2017](https://people.csail.mit.edu/devadas/pubs/part_1.pdf)
* [Secure Processors Part II: Intel SGX Security Analysis and MIT Sanctum Architecture - 2017](https://people.csail.mit.edu/devadas/pubs/part_2.pdf)
* [Sanctum: Minimal Hardware Extensions for Strong Software Isolation - 201608](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/costan), [PoC](https://github.com/pwnall/sanctum).

* Sanctum source code [repo](https://github.com/mit-sanctum)

