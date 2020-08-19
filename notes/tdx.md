Glad to see Intel made TDX( Trust Domain Extensions) white paper public:

https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html

Just skimmed a bit and found a few things should be noted if anyone interested to make it into your production:

* The latest microarchitecture "TigerLake" doesn't support it yet. AlderLake likely to be the one ship with TDX.

* According to the public white paper, SEAM( Secure-Arbitration Mode) loader work as a ACM within TXT which post-KBL must be provisioned w/ Bootguard. The provisioning tools are closed sources and you're able to get it by signing a NDA w/ Intel( the leaked one isn't legal to use). This won't be a problem for cloud vendor. As for other individual/enterprise users may still waiting for free/libre and open source provisoning tools. 

* Remote attestation is always a juciy feature for the cloud industry but some crucial problem may not be leveraged at low cost. For whatever reasons, TDX implemented it by utilizing the current features of SGX. To make the story short, you should do the risk assessment based on recent SGX attacks, e.g: #SGAxe #CrossTalk

* The threat model of Intel TDX could be wrong, maybe not so wrong as SGX does. SGX assumed that the Host/OS is a potential advisory, while TDX is doing the opposite. From an ordinary user's perspective, other tenant's VM running on the same physical machine is a big threat as the evil administrator. I'm not sure why the cloud operator should be trusted in TDX's threat model.

Well, TDX seems an interesting stuff but it's a better-than-none solution now. Btw: Intel's patent have more detail of TDX:

http://www.freepatentsonline.com/y2020/0202013.html
