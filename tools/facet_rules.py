"""Rules that derive filter facets (operating system, programming language, system type) for a CVE.

The CVE record has no such fields, so every value here is INFERRED from three things the record does
contain: vendor/product/assigner ("vp") and the free-text description ("desc"). Two kinds of evidence:

  text     the record itself names it   (".php" in a file path, "Windows 10", "Node.js", "router" ...)
  curated  a hand-written product list  (WordPress -> PHP, Kubernetes -> Go, Linux kernel -> C ...)

A CVE can carry several values per dimension (a bug in a WordPress plugin that also affects Linux
hosts), and a CVE that names nothing gets NO value: it is reported as "not stated", never guessed.
Reading "Language = PHP" as "the record points at PHP code", not "every PHP CVE is here".
"""
import re

I = re.I


def rx(p, flags=I):
    return re.compile(p, flags)


# Each dimension: list of (key, label, description, [(field, kind, regex), ...]).  field: vp | desc | any
OS = [
    ("windows", "Windows", "Microsoft Windows and Windows Server components", [
        ("any", "text", rx(r"\bwindows\b|\bwin32k?\b|\bNTFS\b|\.NET Framework|\bActive Directory\b|\bPowerShell\b"))]),
    ("linux", "Linux", "Linux kernel and Linux distributions", [
        ("any", "text", rx(r"\blinux\b|\bubuntu\b|\bdebian\b|\bred hat\b|\brhel\b|\bcentos\b|\bfedora\b|\bsuse\b|\balpine\b")),
        ("vp", "curated", rx(r"^linux\b|\bkernel\b"))]),
    ("macos", "macOS", "Apple macOS / OS X", [
        ("any", "text", rx(r"\bmac ?os\b|\bos x\b|\bmacos\b|\bmac os x\b"))]),
    ("ios", "iOS / iPadOS / watchOS / tvOS", "Apple's mobile and embedded operating systems", [
        ("any", "text", rx(r"\biOS\b|\biPadOS\b|\bwatchOS\b|\btvOS\b|\bvisionOS\b", 0)),
        ("any", "text", rx(r"\biphone\b|\bipad\b"))]),
    ("android", "Android", "Android OS, vendor builds and Android apps", [
        ("any", "text", rx(r"\bandroid\b")),
        ("vp", "curated", rx(r"google_android|\bpixel\b"))]),
    ("bsd_unix", "BSD / commercial Unix", "FreeBSD, OpenBSD, NetBSD, Solaris, AIX, HP-UX, illumos", [
        ("any", "text", rx(r"\bfreebsd\b|\bopenbsd\b|\bnetbsd\b|\bsolaris\b|\baix\b|\bhp-ux\b|\billumos\b|\bdragonfly\b"))]),
    ("netos", "Network-device OS", "Cisco IOS/NX-OS, Junos, FortiOS, PAN-OS, RouterOS and similar", [
        ("any", "text", rx(r"cisco ios|\bios xe\b|\bios xr\b|\bnx-os\b|\bjunos\b|\bfortios\b|\bpan-os\b|\brouteros\b|\barubaos\b|\bsonicos\b|\bbig-ip\b|\btmos\b|\bnx-os\b"))]),
    ("rtos", "RTOS / embedded OS", "VxWorks, FreeRTOS, Zephyr, QNX, ThreadX and other real-time OSes", [
        ("any", "text", rx(r"\bvxworks\b|\bfreertos\b|\bzephyr\b|\bqnx\b|\bthreadx\b|\brt-thread\b|\bcontiki\b|\bnuttx\b|\bazure rtos\b|\briot os\b|\bmbed ?os\b"))]),
    ("other_os", "Other mobile / consumer OS", "HarmonyOS, OpenHarmony, Tizen, KaiOS, ChromeOS, webOS, Fuchsia", [
        ("any", "text", rx(r"\bharmonyos\b|\bopenharmony\b|\btizen\b|\bkaios\b|\bchrome ?os\b|\bwebos\b|\bfuchsia\b|\bemui\b|\bmiui\b"))]),
    ("openwrt", "OpenWrt / embedded Linux", "OpenWrt, DD-WRT, Yocto, Buildroot, BusyBox-based firmware", [
        ("any", "text", rx(r"\bopenwrt\b|\bdd-wrt\b|\byocto\b|\bbuildroot\b|\bbusybox\b|\blede\b"))]),
    ("mainframe", "Mainframe / IBM i", "z/OS, IBM i (OS/400), AS/400", [
        ("any", "text", rx(r"\bz/os\b|\bos/400\b|\bibm i\b|\bas/400\b|\bmainframe\b"))]),
]

LANG = [
    ("c_cpp", "C / C++", "Native code: C, C++ and Objective-C++ components", [
        ("desc", "text", rx(r"\b[\w/.-]+\.(?:c|h|cc|cpp|cxx|hpp|hh)\b(?!\w)")),
        ("any", "text", rx(r"\bC\+\+|\bin C\b|\bC language\b", 0)),
        ("vp", "curated", rx(r"^linux$|\bopenssl\b|\blibpng\b|\blibtiff\b|\blibxml2?\b|\bffmpeg\b|\bimagemagick\b|\bcurl\b|\bzlib\b|\bglibc\b|\bsudo\b|\bchrome\b|\bchromium\b|\bfirefox\b|\bthunderbird\b|\bwebkit\b|\bsafari\b|\bqemu\b|\bxen\b|\bsystemd\b|\bopenssh\b|\bwireshark\b|\bfreerdp\b|\bredis\b|\bsqlite\b|\bvlc\b|\bpoppler\b|\blibwebp\b|\bbusybox\b|\bu-boot\b|\bsamba\b|\bsnapdragon\b|\bmediatek\b|\bunisoc\b|\bnginx\b|\bhttpd\b|\bmysql server\b|\bmariadb\b"))]),
    ("php", "PHP", "PHP applications, WordPress/Joomla/Drupal core and plugins", [
        ("any", "text", rx(r"\.php\b|\bphp\b|\.phtml\b|\bcomposer\b")),
        ("vp", "curated", rx(r"wordpress|patchstack|wordfence|wpscan|joomla|drupal|phpmyadmin|laravel|magento|moodle|prestashop|symfony|codeigniter|sourcecodester|phpgurukul|code-projects|itsourcecode|campcodes|woocommerce|mediawiki|nextcloud|owncloud|roundcube"))]),
    ("java", "Java / JVM", "Java, Jakarta EE, Kotlin and other JVM code", [
        ("any", "text", rx(r"\.java\b|\.jsp\b|\.jar\b|\bjava\b(?!\s?script)|\bjvm\b|\bjakarta\b|\bjdk\b|\bjre\b|\bkotlin\b|\bgroovy\b")),
        ("any", "text", rx(r"spring (framework|boot|cloud|security|data)|\bstruts\b|\btomcat\b|\blog4j\b|\bjboss\b|\bwildfly\b|\bweblogic\b|\bjenkins\b|\bhibernate\b|\bjackson\b|\bmaven\b|\bgradle\b|\bjetty\b|\bkeycloak\b|\belasticsearch\b|\bkafka\b"))]),
    ("javascript", "JavaScript / TypeScript", "Browser and Node.js code, npm packages", [
        ("any", "text", rx(r"\.js\b|\.jsx\b|\.ts\b|\.tsx\b|\bjavascript\b|\btypescript\b|\bnode\.?js\b|\bnpm\b|\belectron\b|\bdeno\b")),
        ("any", "text", rx(r"\breact\b|\bangular\b|\bvue(\.js)?\b|\bexpress(\.js)?\b|\bnext\.js\b|\bwebpack\b|\bjquery\b", 0))]),
    ("python", "Python", "Python programs and PyPI packages", [
        ("any", "text", rx(r"\.py\b|\bpython\b|\bpypi\b|\bdjango\b|\bflask\b|\bpillow\b|\bnumpy\b|\bpytorch\b|\btensorflow\b|\bjupyter\b|\bfastapi\b|\bpip\b|\bansible\b"))]),
    ("ruby", "Ruby", "Ruby and Ruby on Rails", [
        ("any", "text", rx(r"\.rb\b|\bruby\b|\brails\b|\brubygems\b|\bsinatra\b|\bgitlab\b"))]),
    ("go", "Go", "Go programs and modules", [
        ("any", "text", rx(r"\.go\b|\bgolang\b|\bgo (module|package|standard library|library|toolchain)\b|\bkubernetes\b|\bdocker\b|\bmoby\b|\bcontainerd\b|\bterraform\b|\betcd\b|\bgitea\b|\bprometheus\b|\bgrafana\b|\bhelm\b"))]),
    ("rust", "Rust", "Rust crates and programs", [
        ("any", "text", rx(r"\.rs\b|\brust\b|\bcrates?\.io\b|\bcargo\b|\bcrate\b"))]),
    ("dotnet", "C# / .NET", ".NET, ASP.NET, C# and Visual Basic", [
        ("any", "text", rx(r"\.cs\b|\.aspx?\b|\.vb\b|\basp\.net\b|\.net (core|framework|5|6|7|8|9)\b|\bc#|\bnuget\b|\bblazor\b|\bmsbuild\b"))]),
    ("perl", "Perl", "Perl scripts and CPAN modules", [
        ("any", "text", rx(r"\.pl\b|\.pm\b|\bperl\b|\bcpan\b"))]),
    ("swift_objc", "Swift / Objective-C", "Apple-platform application languages", [
        ("any", "text", rx(r"\.swift\b|\.mm?\b|\bobjective-c\b|\bswiftui\b|\bswift (package|code|language|compiler|runtime|library)\b|\buikit\b|\bappkit\b|\bcocoa touch\b"))]),
    ("kotlin", "Kotlin", "Kotlin / Android-first JVM code", [
        ("any", "text", rx(r"\.kt\b|\bkotlin\b|\bktor\b"))]),
    ("shell", "Shell / PowerShell / batch", "Shell scripts, PowerShell and batch files", [
        ("any", "text", rx(r"\.sh\b|\.ps1\b|\.bat\b|\.cmd\b|\bbash\b|\bzsh\b|\bshell script\b|\bpowershell\b|\bbatch file\b"))]),
    ("lua", "Lua", "Lua scripts and embedded Lua", [
        ("any", "text", rx(r"\.lua\b|\blua\b|\bluajit\b"))]),
    ("solidity", "Solidity / smart contracts", "Ethereum and other smart-contract code", [
        ("any", "text", rx(r"\.sol\b|\bsolidity\b|\bsmart contracts?\b"))]),
    ("dart", "Dart / Flutter", "Dart and Flutter applications", [
        ("any", "text", rx(r"\.dart\b|\bdart\b|\bflutter\b"))]),
    ("scala", "Scala / Clojure / other JVM", "Scala, Akka, Clojure, Groovy-adjacent JVM languages", [
        ("any", "text", rx(r"\.scala\b|\bscala\b|\bakka\b|\bclojure\b|\.clj\b"))]),
]

SYSTEM = [
    ("web", "Web application / CMS", "Web apps, CMS plugins, admin panels, web APIs", [
        ("any", "text", rx(r"cross-site (scripting|request forgery)|\bxss\b|\bcsrf\b|sql injection|web (application|interface|server|site|page|console|ui|gui|admin)|admin(istration)? panel|\bwordpress\b|\bplugin\b|\bjoomla\b|\bdrupal\b|\bphp\b|\.php\b|\.jsp\b|\.aspx?\b|rest api|\bgraphql\b|http request|login page|\bportal\b")),
        ("vp", "curated", rx(r"patchstack|wordfence|wpscan|wordpress|sourcecodester|phpgurukul|code-projects|itsourcecode|campcodes"))]),
    ("os_kernel", "Operating system / kernel", "Kernels, system services and OS components", [
        ("any", "text", rx(r"\bkernel\b|\bsyscall\b|\bsystemd\b|\bwin32k\b|windows (kernel|print spooler|common log|installer|smb|remote desktop|update)|\bxnu\b|\bhypercall\b")),
        ("vp", "curated", rx(r"^linux$"))]),
    ("browser", "Browser / web engine", "Browsers, JavaScript engines, embedded web views", [
        ("any", "text", rx(r"\bchrome\b|\bchromium\b|\bfirefox\b|\bsafari\b|\bwebkit\b|\bmicrosoft edge\b|\bv8\b|\bwebview\b|\bblink\b|\bgecko\b|\bbrowser\b|\bopera\b|\bbrave\b|\bspidermonkey\b|\bjavascriptcore\b"))]),
    ("network", "Network device / security appliance", "Routers, firewalls, VPNs, switches, gateways", [
        ("any", "text", rx(r"\brouters?\b|\bfirewalls?\b|\bvpn\b|\bswitch(es)?\b|\bgateway\b|\baccess point\b|\bmodem\b|\bwi-?fi\b|cisco ios|\bjunos\b|\bfortios\b|\bpan-os\b|\bd-link\b|\btenda\b|\btp-link\b|\bnetgear\b|\bzyxel\b|\bmikrotik\b|\bubiquiti\b|\bbig-ip\b|\bfortigate\b|\bpalo alto\b|\bsonicwall\b|\bpulse secure\b|\bivanti connect\b|\bnetscaler\b")),
        ("vp", "curated", rx(r"^cisco$|juniper|fortinet|palo alto|d-link|tenda|tp-link|netgear|zyxel|mikrotik|ubiquiti|\bf5\b|sonicwall|aruba"))]),
    ("iot", "IoT / embedded device", "Smart devices, cameras, printers, consumer and embedded firmware", [
        ("any", "text", rx(r"\biot\b|\bfirmware\b|smart (home|camera|plug|lock|speaker|tv|bulb|watch|meter|thermostat)|\bdvr\b|\bnvr\b|ip camera|\bwebcam\b|\bprinter\b|set-top|\bembedded\b|\besp32\b|\bzigbee\b|\bbluetooth\b|\bsmart ?watch\b|\bwearable\b|\bdrone\b|\bwallbox\b|\bev charger\b"))]),
    ("ics", "Industrial control / OT", "SCADA, PLCs, HMIs, medical and building automation", [
        ("any", "text", rx(r"\bscada\b|\bplc\b|\bhmi\b|\bsimatic\b|\bmodbus\b|\bopc ua\b|industrial control|\bschneider\b|\brockwell\b|\bmitsubishi electric\b|\bmoxa\b|\bsiemens\b|\bhirschmann\b|\bbuilding automation\b|\binfusion pump\b|\bmedical device\b")),
        ("vp", "curated", rx(r"icscert|siemens|schneider|rockwell|moxa|mitsubishi electric|\babb\b|honeywell|emerson"))]),
    ("mobile", "Mobile platform / app", "Phones, mobile OS components and mobile apps", [
        ("any", "text", rx(r"\bandroid\b|\biphone\b|\bipad\b|\bharmonyos\b|mobile (app|application|device|phone)|\bsamsung (mobile|galaxy)\b|\bgalaxy\b|\bemui\b|\bmiui\b|\bapk\b|\bipa\b app")),
        ("any", "text", rx(r"\biOS\b|\biPadOS\b", 0)),
        ("vp", "curated", rx(r"google_android|samsung mobile|huawei|xiaomi|oppo|vivo|oneplus"))]),
    ("database", "Database / data platform", "Relational, NoSQL, search and analytics engines", [
        ("any", "text", rx(r"\bmysql\b|\bmariadb\b|\bpostgres(ql)?\b|\bmongodb\b|\bredis\b|oracle database|\bsqlite\b|\belasticsearch\b|\bkibana\b|\bcassandra\b|\bcouchdb\b|sql server|\bclickhouse\b|\binfluxdb\b|\bdatabase (server|engine)\b|\bsnowflake\b"))]),
    ("cloud_devops", "Cloud / container / DevOps", "Orchestrators, CI/CD, cloud services and infrastructure-as-code", [
        ("any", "text", rx(r"\bkubernetes\b|\bdocker\b|\bcontainer(d|s)?\b|\bjenkins\b|\bgitlab\b|\bgithub (actions|enterprise)\b|\bterraform\b|\bansible\b|\bhelm\b|\bargo ?cd\b|\bteamcity\b|ci/cd|\baws\b|\bazure\b|google cloud|\bserverless\b|\bopenstack\b|\bharbor\b|\bistio\b|\bconsul\b|\bvault\b|\bgrafana\b|\bprometheus\b"))]),
    ("enterprise", "Enterprise / business software", "ERP, CRM, collaboration, ITSM and middleware", [
        ("any", "text", rx(r"\bsap\b|\bpeoplesoft\b|e-business suite|\bweblogic\b|\bsiebel\b|jd edwards|\batlassian\b|\bconfluence\b|\bjira\b|\bsharepoint\b|exchange server|\bsalesforce\b|\bservicenow\b|\bcitrix\b|\bwebsphere\b|\bmaximo\b|\bcognos\b|\bsplunk\b|\berp\b|\bcrm\b|\bmattermost\b|\bslack\b|\bzimbra\b|\bsolarwinds\b|\bmanageengine\b"))]),
    ("docs_media", "Document / media parser", "PDF, Office, image, audio and video libraries and viewers", [
        ("any", "text", rx(r"\bpdf\b|\bacrobat\b|\bfoxit\b|microsoft (office|word|excel|powerpoint|outlook)|\bimagemagick\b|\bffmpeg\b|\blibpng\b|\blibtiff\b|\blibwebp\b|\blibjpeg\b|\bgstreamer\b|\bvlc\b|media player|\bcodec\b|image (file|parser|processing|format)|\bfont\b|\bopenoffice\b|\blibreoffice\b|\bpoppler\b|\bghostscript\b|\bexif\b|\bsvg\b|\bxml parser\b"))]),
    ("virt", "Virtualization / hypervisor", "Hypervisors, VMs and guest/host boundaries", [
        ("any", "text", rx(r"\bvmware\b|\besxi\b|\bvsphere\b|\bxen\b|\bvirtualbox\b|\bqemu\b|\bkvm\b|hyper-v|\bhypervisor\b|virtual machine|\bguest (os|vm)\b|\bparallels\b"))]),
    ("hardware", "CPU / hardware / platform firmware", "Processors, BIOS/UEFI, SoCs, GPUs, secure enclaves", [
        ("any", "text", rx(r"\bbios\b|\buefi\b|\bmicrocode\b|speculative|\bspectre\b|\bmeltdown\b|\bsmm\b|\bsgx\b|\btrustzone\b|secure boot|\bbaseband\b|\bbootloader\b|\bjtag\b|\browhammer\b|\bthunderbolt\b|\bbmc\b|\bcpus?\b(?! (consumption|usage|exhaustion|utili[sz]ation|load|time|resources?))|(intel|amd) (processors?|chips?|platform|firmware|management engine|csme|txe|graphics)|\bnvidia (gpu|display driver|vgpu|jetson|bootloader)|\bgpu\b|\bsnapdragon\b|\bmediatek\b|\bunisoc\b|\bexynos\b|\bsoc\b"))]),
    ("libs_pkg", "Library / package ecosystem", "Reusable libraries, SDKs and package-manager ecosystems", [
        ("any", "text", rx(r"\bnpm\b|\bpypi\b|\brubygems\b|\bcrates?\.io\b|\bmaven\b|\bpackagist\b|\bnuget\b|\bpackage manager\b|\bopenssl\b|\blibxml2?\b|\bcurl\b|\bzlib\b|\bglibc\b|\blibssh\b|\bgnutls\b|\bboringssl\b|\bsdk\b|\bthird[- ]party (library|component|package)\b|\bdependenc(y|ies)\b|\bpackage\b"))]),
    ("ai_ml", "AI / ML systems", "ML frameworks, LLM apps, agents and model-serving tools", [
        ("any", "text", rx(r"\btensorflow\b|\bpytorch\b|\bllm\b|large language model|machine learning|\bneural\b|\blangchain\b|\bllama(\.cpp|index)?\b|\bollama\b|model context protocol|\bmcp (server|client)\b|prompt injection|\bchatgpt\b|\bopenai\b|hugging ?face|\bai agent\b|generative ai|\bn8n\b|\bcopilot\b|\bonnx\b|\bmlflow\b|\bgradio\b"))]),
    ("net_services", "Network service / protocol", "Servers and protocol implementations: web, mail, DNS, SSH, SMB, TLS", [
        ("any", "text", rx(r"apache http|\bhttpd\b|\bnginx\b|\bopenssh\b|\bsamba\b|\bisc bind\b|\bbind ?9\b|\bnamed\b dns|\bpostfix\b|\bexim\b|\bsendmail\b|\bdovecot\b|\bopenvpn\b|\bsmb(v[123])?\b|\brdp\b|\bftp\b|\bdns\b|\bsmtp\b|\bimap\b|\bldap\b|\bntp\b|\bsnmp\b|\bkerberos\b|\btls\b|\bssl\b|\bipsec\b|\bhttp/2\b|\bwebsocket\b|\bmqtt\b|\bsip\b"))]),
]


HARDWARE = [
    ("cpu", "CPU / microarchitecture", "Processor flaws: speculative execution, microcode, SGX, Rowhammer", [
        ("any", "text", rx(r"microarchitectur|speculative execution|\bspectre\b|\bmeltdown\b|\bsgx\b|\browhammer\b|\bmicrocode\b|\b(intel|amd|arm|apple) (core|xeon|atom|ryzen|epyc|zen|cortex|silicon|processors?|cpus?|chips?)\b|\bcpu (cache|frequency|vulnerab|microarch|instruction)"))]),
    ("gpu", "GPU / graphics hardware", "GPU drivers and graphics firmware", [
        ("any", "text", rx(r"\bgpus?\b|nvidia (gpu|display driver|vgpu|geforce|quadro|tesla|cuda)|\bradeon\b|\bgraphics (card|driver|processor)\b|\bmali\b|\badreno\b"))]),
    ("soc", "SoC / baseband / chipset", "Mobile and embedded SoCs, modems, vendor chipsets", [
        ("any", "text", rx(r"\bsnapdragon\b|\bqualcomm\b|\bmediatek\b|\bunisoc\b|\bspreadtrum\b|\bexynos\b|\bkirin\b|\bbaseband\b|\brealtek\b|\bbroadcom (wi-?fi|bluetooth|chip)|\bsoc\b|\bchipset\b|\bmarvell\b|\bamlogic\b|\brockchip\b"))]),
    ("firmware", "BIOS / UEFI / bootloader", "Platform firmware and the boot chain", [
        ("any", "text", rx(r"\bbios\b|\buefi\b|\bsmm\b|\bbootloader\b|\bboot ?rom\b|\bsecure boot\b|\bu-boot\b|\bedk ?ii\b|\bcoreboot\b|\bflash (chip|memory)\b"))]),
    ("secure_hw", "TPM / secure enclave / smart card", "Hardware roots of trust and tokens", [
        ("any", "text", rx(r"\btpm\b|trusted platform|\btrustzone\b|\bhsm\b|secure enclave|\bsmart ?card\b|\bsecure element\b|\btee\b|hardware security (module|key)|\byubikey\b|\bfido2?\b"))]),
    ("storage", "Storage device / NAS", "SSD, HDD, USB storage, NAS appliances", [
        ("any", "text", rx(r"\bssd\b|\bhdd\b|\bnvme\b|hard (disk|drive)|\busb (drive|storage|flash)\b|\bsd card\b|\braid\b|\bnas (server|device|appliance|box)\b")),
        ("vp", "curated", rx(r"synology|qnap|western digital|seagate|netapp|buffalo"))]),
    ("peripheral", "Peripheral / bus / NIC", "PCI, USB stack, NICs, DMA, docks, input devices", [
        ("any", "text", rx(r"\bnic\b|network (interface )?(card|adapter|controller)|\bethernet (controller|adapter)\b|\bpcie?\b|\bthunderbolt\b|\busb (device|controller|host|stack|driver)\b|\bhid\b|\bkeyboard\b|\bdocking station\b|\bdma\b|\biommu\b"))]),
    ("wireless_chip", "Wi-Fi / Bluetooth / NFC radio", "Wireless chipsets, radio firmware, RFID/NFC", [
        ("any", "text", rx(r"\bwi-?fi (chip|chipset|firmware|driver)|\bbluetooth (chip|controller|stack|firmware)|\bnfc\b|\brfid\b|\bwlan (driver|firmware)"))]),
    ("router", "Router / modem / access point", "Home and SMB routers, modems, mesh and CPE", [
        ("any", "text", rx(r"\brouters?\b|\baccess points?\b|\bmodem\b|\bwi-?fi (router|extender|repeater)\b|\bonts?\b|\bcpe\b|\bgpon\b|\bdsl\b|\bd-link\b|\btenda\b|\btp-link\b|\bnetgear\b|\bzyxel\b|\blinksys\b|\bmikrotik\b|\bubiquiti\b|\bopenwrt\b|\bdd-wrt\b"))]),
    ("fw_switch", "Firewall / switch / appliance", "Security appliances, switches, load balancers", [
        ("any", "text", rx(r"\bswitch(es)?\b|\bfirewalls?\b|\bload balancer\b|\butm\b|\bappliance\b|\bfortigate\b|\bsonicwall\b|\bpalo alto\b|\bbig-ip\b|\bjuniper\b|\bcisco (asa|firepower|catalyst|nexus)\b"))]),
    ("camera", "Camera / DVR / surveillance", "IP cameras, NVR/DVR, video doorbells", [
        ("any", "text", rx(r"\b(ip |web |security |surveillance )?cameras?\b|\bdvr\b|\bnvr\b|\bcctv\b|\bhikvision\b|\bdahua\b|\bvideo (surveillance|recorder|doorbell)\b|\bdoorbell\b|\bbaby monitor\b"))]),
    ("printer", "Printer / scanner / MFP", "Printers, multifunction devices, print servers", [
        ("any", "text", rx(r"\bprinters?\b|\bmfp\b|multifunction|\bcups\b|\bscanner\b")),
        ("vp", "curated", rx(r"canon|epson|brother|hp inc|xerox|ricoh|kyocera|konica|lexmark|sharp"))]),
    ("tv_media", "Smart TV / media / console", "TVs, set-top boxes, speakers, game consoles", [
        ("any", "text", rx(r"\bsmart tv\b|\bset-top\b|\bchromecast\b|\bapple tv\b|\broku\b|\bfire tv\b|\bandroid tv\b|\bhbbtv\b|\bsoundbar\b|\bsmart speaker\b|\balexa\b|\bsonos\b|\bgame console\b|\bplaystation\b|\bxbox\b|\bnintendo\b"))]),
    ("phone_wearable", "Phone / tablet / wearable", "Smartphones, tablets, watches, earbuds", [
        ("any", "text", rx(r"\bsmart ?watch\b|\bwearable\b|\bfitbit\b|\bapple watch\b|\bgalaxy watch\b|\bearbuds\b|\bairpods\b|\bsmartphones?\b|\btablets?\b|\bipad\b|\biphone\b|\bpixel (phone|\d)\b"))]),
    ("smart_home", "Smart home device", "Plugs, locks, thermostats, hubs, home automation", [
        ("any", "text", rx(r"\bsmart (home|plug|lock|bulb|light|thermostat|meter|switch|hub|door)\b|\bthermostat\b|\bhomekit\b|\bzigbee\b|\bz-wave\b|\bphilips hue\b|\btuya\b|\bshelly\b|\bsonoff\b|\bhome assistant\b"))]),
    ("medical", "Medical device", "Infusion pumps, monitors, imaging, clinical devices", [
        ("any", "text", rx(r"\bmedical (device|equipment|imaging)\b|\binfusion pump\b|\bpacemaker\b|\bpatient monitor|\bdicom\b|\bhl7\b|\bglucose\b|\binsulin\b|\bventilator\b|\bmri\b|\bpacs\b|\bdefibrillator\b"))]),
    ("vehicle", "Vehicle / automotive / EV charger", "Cars, ECUs, infotainment, telematics, EV charging", [
        ("any", "text", rx(r"\bautomotive\b|\bvehicles?\b|\bcan bus\b|\becu\b|\binfotainment\b|\btesla\b|\bbmw\b|\btoyota\b|\bhonda\b|\bvolkswagen\b|\bautosar\b|\btelematics\b|\bev charger\b|\bcharging (station|point)\b|\bocpp\b"))]),
    ("industrial", "Industrial controller / PLC / building", "PLCs, RTUs, SCADA gear, building automation", [
        ("any", "text", rx(r"\bplc\b|\bscada\b|\bhmi\b|\bmodbus\b|\bdnp3\b|\bopc ua\b|industrial control|\bsiemens (simatic|s7)\b|\brtu\b|\bprofinet\b|\bethernet/ip\b|\biec 61850\b|\bbacnet\b|\bbuilding automation\b")),
        ("vp", "curated", rx(r"icscert"))]),
    ("server_bmc", "Server management / BMC", "BMC, IPMI, iDRAC/iLO, blade and mainframe management", [
        ("any", "text", rx(r"\bbmc\b|\bipmi\b|\bidrac\b|\bilo ?[0-9]?\b|\bredfish\b|\bsupermicro\b|\bserver (firmware|management)\b|\bblade\b|\bcisco ucs\b"))]),
    ("pos_atm", "POS / ATM / kiosk", "Payment terminals, ATMs, kiosks, vending", [
        ("any", "text", rx(r"point[- ]of[- ]sale|\bpos terminal\b|\batm\b|\bpayment terminal\b|\bcard reader\b|\bkiosk\b|\bvending\b"))]),
    ("drone_robot", "Drone / robot", "UAVs, robots, ROS, flight controllers", [
        ("any", "text", rx(r"\bdrones?\b|\buav\b|\bquadcopter\b|\brobots?\b|\bros2?\b|\bdji\b|\bpx4\b|\bardupilot\b"))]),
    ("mcu", "Microcontroller / dev board / FPGA", "ESP32, STM32, Arduino, Raspberry Pi, FPGAs", [
        ("any", "text", rx(r"\bmicrocontroller\b|\bmcu\b|\besp32\b|\besp8266\b|\barduino\b|\braspberry pi\b|\bstm32\b|\bnordic\b|\bfpga\b|\bsingle-board\b"))]),
]

ARCH = [
    ("x86", "x86 / x86-64", "Intel/AMD PC and server architecture", [("any", "text", rx(r"\bx86(-64)?\b|\bx64\b|\bamd64\b|\bi[3-6]86\b|\bintel 64\b"))]),
    ("arm", "ARM / AArch64", "ARM cores and Apple silicon", [("any", "text", rx(r"\barm(v\d+)?\b|\baarch64\b|\barm64\b|\bcortex-?[amr]\d+|\bapple silicon\b"))]),
    ("riscv", "RISC-V", "RISC-V cores and boards", [("any", "text", rx(r"\brisc-?v\b"))]),
    ("mips", "MIPS", "MIPS routers and embedded devices", [("any", "text", rx(r"\bmips(el)?\b"))]),
    ("ppc", "PowerPC / POWER", "PowerPC and IBM POWER", [("any", "text", rx(r"\bpower ?pc\b|\bppc(64)?\b|\bpower(8|9|10)\b"))]),
    ("s390", "IBM Z (s390x)", "s390x and z/Architecture", [("any", "text", rx(r"\bs/?390x?\b|\bz/?architecture\b"))]),
    ("sparc", "SPARC", "SPARC systems", [("any", "text", rx(r"\bsparc(64)?\b"))]),
    ("wasm", "WebAssembly", "WASM modules and runtimes", [("any", "text", rx(r"\bwebassembly\b|\bwasm\b|\bwasmtime\b|\bwasmer\b"))]),
    ("b32", "32-bit specific", "Wording says 32-bit", [("any", "text", rx(r"\b32-?bit\b"))]),
    ("b64", "64-bit specific", "Wording says 64-bit", [("any", "text", rx(r"\b64-?bit\b"))]),
]

NETWORK = [
    ("http", "HTTP / web server", "HTTP/1-3, web servers, request handling, smuggling", [("any", "text", rx(r"\bhttps?\b|\bhttp/[123]\b|\bweb server\b|\bhttp (request|header|response|server|smuggling)"))]),
    ("tls", "TLS / SSL / certificates", "TLS, DTLS, X.509, certificate validation", [("any", "text", rx(r"\btls\b|\bssl\b|\bdtls\b|\bx\.?509\b|certificate (validation|verification|chain)|\bhandshake\b"))]),
    ("dns", "DNS", "Resolvers, authoritative servers, DNSSEC, mDNS", [("any", "text", rx(r"\bdns\b|\bdnssec\b|\bmdns\b|\bisc bind\b|\bbind ?9\b|\bunbound\b|\bdnsmasq\b|\bresolver\b|\bnxdomain\b"))]),
    ("ip_stack", "TCP/IP stack (IP, TCP, UDP, ICMP, ARP)", "Network-stack implementations and low-layer protocols", [("any", "text", rx(r"\btcp\b|\budp\b|\bsctp\b|\bquic\b|\bicmp(v6)?\b|\barp\b|\bndp\b|\bipv[46]\b|\bip (fragment|option|header)|\btcp/ip\b|network stack"))]),
    ("dhcp", "DHCP", "DHCP clients and servers", [("any", "text", rx(r"\bdhcp(v6)?\b"))]),
    ("routing", "Routing / switching protocols", "BGP, OSPF, RIP, MPLS, VLAN, STP, SDN", [("any", "text", rx(r"\bbgp\b|\bospf\b|\brip(v2)?\b|\bis-is\b|\bmpls\b|\bvrrp\b|\bhsrp\b|\bspanning tree\b|\bvxlan\b|\bvlan\b|\bsdn\b|\bopenflow\b"))]),
    ("file_sharing", "File sharing (SMB / NFS / FTP / WebDAV)", "Network file protocols", [("any", "text", rx(r"\bsmb(v[123])?\b|\bcifs\b|\bsamba\b|\bnfs\b|\bwebdav\b|\bafp\b|\bftp\b|\bsftp\b|\btftp\b|\brsync\b|\bnetbios\b"))]),
    ("ssh_telnet", "SSH / Telnet", "Remote shells", [("any", "text", rx(r"\bssh\b|\bopenssh\b|\btelnet\b|\bdropbear\b|\blibssh\b"))]),
    ("mail", "Email (SMTP / IMAP / POP3)", "Mail servers, clients and anti-spoofing", [("any", "text", rx(r"\bsmtp\b|\bimap\b|\bpop3\b|\bmime\b|\be-?mail (server|client|gateway)|\bpostfix\b|\bexim\b|\bdovecot\b|\bsendmail\b|\bexchange server\b|\bdkim\b|\bdmarc\b"))]),
    ("vpn", "VPN / IPsec / tunnels", "IPsec, OpenVPN, WireGuard, SSL VPN", [("any", "text", rx(r"\bvpn\b|\bipsec\b|\bikev?[12]\b|\bwireguard\b|\bopenvpn\b|\bl2tp\b|\bpptp\b|\bssl vpn\b|\bzerotier\b|\btailscale\b"))]),
    ("wifi", "Wi-Fi (802.11)", "WPA/WPS, hostapd, Wi-Fi stacks", [("any", "text", rx(r"\bwi-?fi\b|\bwlan\b|\b802\.11\b|\bwpa[23]?\b|\bwps\b|\bwep\b|\bssid\b|\bhostapd\b"))]),
    ("bluetooth", "Bluetooth / BLE", "Bluetooth stacks and profiles", [("any", "text", rx(r"\bbluetooth\b|\bble\b|\bbluez\b|\bl2cap\b|\bgatt\b"))]),
    ("cellular", "Cellular (2G-5G, SIM, SMS)", "Baseband, LTE/5G cores, SIM, messaging", [("any", "text", rx(r"\b[2345]g\b|\blte\b|\bgsm\b|\bumts\b|\bvolte\b|\b3gpp\b|\bsim card\b|\besim\b|\bimsi\b|\bsms\b|\bmms\b"))]),
    ("iot_proto", "Low-power / IoT protocols", "Zigbee, Z-Wave, LoRa, MQTT, CoAP", [("any", "text", rx(r"\bzigbee\b|\bz-wave\b|\blora(wan)?\b|\b6lowpan\b|\bmqtt\b|\bcoap\b|\bnb-iot\b"))]),
    ("discovery", "Discovery / UPnP / name resolution", "UPnP, SSDP, mDNS, LLMNR, WPAD", [("any", "text", rx(r"\bupnp\b|\bssdp\b|\bbonjour\b|\bllmnr\b|\bavahi\b|\bwpad\b|\bws-discovery\b"))]),
    ("directory_auth", "Directory / SSO (LDAP, Kerberos, SAML, OAuth)", "Identity protocols and directories", [("any", "text", rx(r"\bldap\b|\bkerberos\b|\bactive directory\b|\bradius\b|\btacacs\b|\bsaml\b|\boauth2?\b|\boidc\b|\bopenid\b|\bntlm\b|\bsso\b|\bscim\b|\bjwt\b"))]),
    ("remote_access", "Remote desktop (RDP / VNC / X11)", "Remote access and display protocols", [("any", "text", rx(r"\brdp\b|remote desktop|\bvnc\b|\bteamviewer\b|\banydesk\b|\bx11\b|\bspice\b|\bguacamole\b"))]),
    ("voip", "VoIP / SIP / WebRTC", "Voice, video and real-time communication", [("any", "text", rx(r"\bsip\b|\bvoip\b|\brtp\b|\bwebrtc\b|\basterisk\b|\bfreeswitch\b|\bh\.323\b|\bpbx\b|\bxmpp\b"))]),
    ("mgmt", "Management / monitoring (SNMP, NTP, TR-069)", "Device management and time protocols", [("any", "text", rx(r"\bsnmp\b|\bntp\b|\bsyslog\b|\bnetflow\b|\bnetconf\b|\bcwmp\b|\btr-069\b|\bwinrm\b"))]),
    ("api_rpc", "API / RPC (REST, GraphQL, gRPC, WebSocket)", "Application-level APIs and RPC", [("any", "text", rx(r"\brest(ful)? api\b|\bgraphql\b|\bgrpc\b|\bsoap\b|\bjson-?rpc\b|\bxml-?rpc\b|\bwebsocket\b|\bwebhook\b|\bapi endpoint\b|\bopenapi\b|\bswagger\b|\bcorba\b|\bthrift\b|\brpc\b"))]),
    ("messaging", "Message brokers / queues", "MQTT, AMQP, Kafka, RabbitMQ", [("any", "text", rx(r"\bmqtt\b|\bamqp\b|\brabbitmq\b|\bkafka\b|\bactivemq\b|\bzeromq\b|\bnats\b"))]),
    ("proxy_cdn", "Proxy / CDN / WAF / gateway", "Reverse proxies, caches, WAFs, API gateways", [("any", "text", rx(r"\breverse proxy\b|\bproxy server\b|\bsquid\b|\bvarnish\b|\bhaproxy\b|\benvoy\b|\bcdn\b|\bcache poisoning\b|\bload balancer\b|\bwaf\b|\bapi gateway\b|\bingress\b"))]),
    ("p2p_chain", "Blockchain / peer-to-peer", "Blockchain nodes, wallets, smart contracts, P2P", [("any", "text", rx(r"\bblockchain\b|\bbitcoin\b|\bethereum\b|\bsmart contracts?\b|\bsolidity\b|\bp2p\b|\bpeer-to-peer\b|\bbittorrent\b|\bwallet\b|\bdefi\b"))]),
]

VECTOR = [
    ("remote", "Remote / over the network", "Record says a remote attacker is enough", [("any", "text", rx(r"\bremote (unauthenticated )?(attackers?|users?|authenticated)\b|\bover the network\b|\bnetwork[- ]based\b|\bnetwork attackers?\b|\bunauthenticated remote\b"))]),
    ("unauth", "No authentication needed", "Pre-auth: unauthenticated attackers", [("any", "text", rx(r"\bunauthenticated\b|\bwithout (any )?authentication\b|\bpre-?auth\b|\bno authentication (is )?required\b|\bdoes not require authentication\b"))]),
    ("auth_req", "Needs an account / privileges", "Authenticated or low-privilege attackers", [("any", "text", rx(r"\bauthenticated (remote |local )?(attackers?|users?)\b|\blow[- ]privileged?\b|\bprivileged attacker\b|\b(admin(istrator)?|valid) (credentials|account|access)\b|\bwith (admin|user|valid|low)[a-z -]{0,12}(privileges|credentials|access)\b"))]),
    ("local", "Local access", "Local users or local code execution first", [("any", "text", rx(r"\blocal (attackers?|users?|privilege|access)\b|\blocally\b"))]),
    ("adjacent", "Adjacent network / proximity", "Same LAN, Wi-Fi or Bluetooth range", [("any", "text", rx(r"\badjacent (network|attackers?)\b|\bsame (local )?(network|subnet)\b|\bbluetooth range\b|\bwi-?fi range\b|\bnearby\b|\bproximity\b|\bon the same lan\b"))]),
    ("physical", "Physical access", "Hands-on access to the device or port", [("any", "text", rx(r"\bphysical(ly)? (access|attackers?|proximity)\b|\bphysical attack\b|\bevil maid\b|\bhardware access\b|\busb (device|port)\b"))]),
    ("user_interaction", "User must click / open / visit", "Needs a victim action", [("any", "text", rx(r"\buser interaction\b|\bvictim (must|to|clicks|opens|visits)\b|\btrick(s|ing)? (a |the )?(user|victim)\b|\bconvinc(e|ing) (a |the )?user\b|\bsocial engineering\b|\bif (a |the )?user (opens|clicks|visits)\b|\benticing\b"))]),
    ("crafted_file", "Crafted / malicious file", "Triggered by opening a file", [("any", "text", rx(r"\b(specially )?crafted (file|document|image|pdf|archive|video|font|mp[34]|zip|png|jpe?g|svg|office|docx?|xlsx?)\b|\bmalicious (file|document|image|pdf|archive)\b|\bopening (a )?(malicious|crafted)\b"))]),
    ("crafted_network", "Crafted packet / request", "Triggered by a network message", [("any", "text", rx(r"\b(specially )?crafted (packets?|requests?|messages?|http|url|quer(y|ies)|responses?|network|dns|frames?|headers?|payloads?|input|api)\b|\bmalformed (packets?|requests?|messages?)\b"))]),
    ("web_page", "Malicious web page / link", "Drive-by or link-click scenarios", [("any", "text", rx(r"\bmalicious (web ?site|web ?page|link|url)\b|\bvisiting (a )?(malicious|crafted)\b|\bcrafted (web ?page|html|link)\b|\bdrive-by\b"))]),
    ("email_msg", "Email / message / SMS", "Delivered by email or messaging", [("any", "text", rx(r"\be-?mail (message|attachment)s?\b|\bcrafted (e-?mail|message)\b|\bphishing\b|\bmms\b|\bsms\b|\bmalicious (e-?mail|attachment)\b"))]),
    ("supply_chain_vec", "Malicious package / update", "Poisoned dependency, plugin or update", [("any", "text", rx(r"\bmalicious (package|dependency|plugin|extension|update)\b|\btyposquat|\bdependency confusion\b|\bcompromised (build|update|repository)\b"))]),
]

IMPACT = [
    ("rce", "Code / command execution", "Arbitrary code or command execution", [("any", "text", rx(r"\brce\b|code execution|execute arbitrary|execute (code|commands?)\b|run arbitrary|arbitrary (command|code|script)s?\b"))]),
    ("privesc", "Privilege escalation", "Gain higher privileges", [("any", "text", rx(r"privilege escalation|escalat(e|ion) (of )?privileges?|elevation of privilege|gain (root|admin|elevated|higher|system)|root privileges|obtain (root|admin)|\blpe\b"))]),
    ("infoleak", "Information disclosure", "Read data the attacker should not see", [("any", "text", rx(r"information (disclosure|leak|exposure)|disclos(e|es|ure of) (sensitive|confidential|private)|obtain sensitive|read (arbitrary )?(files|memory)|leak(s|ing)? (sensitive|memory|credentials)|exfiltrat|sensitive (information|data)"))]),
    ("dos", "Denial of service / crash", "Crash, hang or exhaust resources", [("any", "text", rx(r"denial[- ]of[- ]service|\bdos\b|\bcrash(es)?\b|infinite loop|resource exhaustion|memory exhaustion|\bhang\b|unresponsive|out of memory|cpu consumption"))]),
    ("auth_bypass", "Authentication / authorization bypass", "Get in or act without the right", [("any", "text", rx(r"bypass(es|ing)? (the )?(authentication|authorization|access control|security|restrictions?|protections?|sandbox|login|2fa|mfa|signature|verification)|authentication bypass|unauthorized access"))]),
    ("tamper", "Data modification / file write", "Alter, overwrite or delete data", [("any", "text", rx(r"modify (arbitrary|files|data|settings|configuration)|overwrite (arbitrary )?files|write arbitrary files|delete (arbitrary )?(files|data)|\btamper|arbitrary file (write|upload|deletion|overwrite)"))]),
    ("takeover", "Account / session takeover", "Hijack accounts or sessions", [("any", "text", rx(r"account takeover|\btakeover\b|hijack(ing)? (a |an |the )?(account|session|user|admin)|session hijack|steal (a )?(session|cookie|token|credentials?)|credential theft"))]),
    ("escape", "Sandbox / VM / container escape", "Break an isolation boundary", [("any", "text", rx(r"sandbox escape|escape (the )?(sandbox|container|jail|vm)\b|container escape|vm escape|guest[- ]to[- ]host|\bbreakout\b"))]),
    ("script_exec", "Client-side script injection", "Run attacker script in a victim's browser", [("any", "text", rx(r"arbitrary web script|inject (arbitrary )?(web script|html|javascript)|execute (arbitrary )?(javascript|script|html)"))]),
    ("spoofing", "Spoofing / deception", "Impersonation or misleading the user", [("any", "text", rx(r"\bspoof(ing)?\b|\bimpersonat|\bphishing\b|\bmisrepresent|trick (the )?user"))]),
]

FORMAT = [
    ("image", "Image formats", "PNG, JPEG, GIF, TIFF, WebP, SVG...", [("any", "text", rx(r"\b(png|jpe?g|gif|bmp|tiff?|webp|heic|avif|jp2|ico|psd)\b|image (file|parser|processing|decoder|format)"))]),
    ("av", "Audio / video / codecs", "MP3, MP4, MKV, codecs, media players", [("any", "text", rx(r"\b(mp[34]|avi|mkv|flv|webm|ogg|flac|wav|aac|h\.?26[45]|hevc)\b|\b(audio|video|media|image) codecs?\b|\bvideo\b|\baudio\b|media (file|player)"))]),
    ("pdf", "PDF / PostScript", "PDF readers and generators", [("any", "text", rx(r"\bpdf\b|\bpostscript\b|\bghostscript\b"))]),
    ("office", "Office documents / macros", "Word, Excel, PowerPoint, OLE, VBA", [("any", "text", rx(r"\.docx?\b|\.xlsx?\b|\.pptx?\b|\brtf\b|word document|\bexcel\b|\bpowerpoint\b|\bms office\b|office document|\bole\b|\bvba macro\b|\bopenoffice\b|\blibreoffice\b"))]),
    ("archive", "Archives / compression", "ZIP, TAR, RAR, 7z, gzip, zip-slip", [("any", "text", rx(r"\b(zip|tar|rar|7z|gz|bz2|xz|cab)\b|\barchive\b|\bunzip\b|\bzip slip\b|\bdecompress"))]),
    ("xml_html", "XML / HTML / SVG", "Markup parsers, XXE, XSLT", [("any", "text", rx(r"\bxml\b|\bxslt?\b|\bsvg\b|\bhtml\b|\bxxe\b|\bdtd\b"))]),
    ("json_yaml", "JSON / YAML / config formats", "Structured data parsers", [("any", "text", rx(r"\bjson\b|\byaml\b|\btoml\b|\bprotobuf\b|\bmessagepack\b|\bcsv\b"))]),
    ("font", "Fonts", "TrueType, OpenType, WOFF, FreeType", [("any", "text", rx(r"\bfonts?\b|\btrue ?type\b|\bopentype\b|\bwoff2?\b|\bfreetype\b"))]),
    ("serialized", "Serialized objects", "Pickle, Java serialization, Marshal, BinaryFormatter", [("any", "text", rx(r"\bserializ|\bunserializ|\bpickle\b|\bobjectinputstream\b|\bmarshal\b|\bbinaryformatter\b"))]),
    ("template_regex", "Templates / regex / expression languages", "Template engines, OGNL, SpEL, regular expressions", [("any", "text", rx(r"\bregular expression|\bregex\b|\btemplate (engine|injection)|\bjinja2?\b|\bvelocity\b|\bfreemarker\b|\bthymeleaf\b|\btwig\b|\bsmarty\b|\bognl\b|\bspel\b|expression language"))]),
    ("firmware_img", "Firmware images / updates", "Firmware files and update packages", [("any", "text", rx(r"\bfirmware (image|update|file|upgrade)\b|\bflash image\b|\bbinwalk\b"))]),
]

DEPLOY = [
    ("cloud", "Cloud service / SaaS", "Hosted services and cloud platforms", [("any", "text", rx(r"\b(aws|azure|gcp|google cloud|amazon web services|cloudflare|heroku|digitalocean|alibaba cloud|oracle cloud|saas)\b|\bcloud (service|platform|instance|storage|function)\b|\bserverless\b|\blambda\b"))]),
    ("container", "Container / Kubernetes", "Containers, orchestrators, runtimes", [("any", "text", rx(r"\bkubernetes\b|\bk8s\b|\bdocker\b|\bcontainerd?\b|\bpodman\b|\bhelm\b|\bopenshift\b|\bkubelet\b|\bcontainer image\b|\brunc\b"))]),
    ("webapp", "Web application / portal", "Browser-delivered applications", [("any", "text", rx(r"web (application|app|service|portal|dashboard)|\bportal\b|\bonline (service|platform)\b|\bmulti-?tenant\b"))]),
    ("desktop", "Desktop application / installer", "Installed desktop software", [("any", "text", rx(r"desktop (application|app|client|software)|\bwindows (installer|service)\b|\bmsi\b|\binstaller\b|\bsetup\.exe\b|\bgui (application|client)\b|\belectron\b"))]),
    ("mobile_app", "Mobile app", "Android and iOS applications", [("any", "text", rx(r"\b(android|ios|iphone|mobile) (app|application)\b|\bapk\b|\bapp store\b|\bgoogle play\b|\bmobile (sdk|client)\b"))]),
    ("extension", "Browser extension / plug-in runtime", "Extensions, add-ons, Flash, Java applets, ActiveX", [("any", "text", rx(r"browser (extension|add-?on|plug-?in)|\bchrome extension\b|\bfirefox (add-?on|extension)\b|\bweb extension\b|\buserscript\b|\bactivex\b|\bflash player\b|\bjava applet\b|\bsilverlight\b"))]),
    ("daemon", "Server daemon / network service", "Long-running listeners", [("any", "text", rx(r"\bdaemon\b|\bserver (software|process)\b|\bsystemd service\b|\bwindows service\b|\binetd\b|listening (on|port)|\bport \d+\b"))]),
    ("library", "Library / SDK / framework", "Code others link or import", [("any", "text", rx(r"\blibrary\b|\bsdk\b|\bmodule\b|\bpackage\b|\bgem\b|\bcrate\b|\bnpm\b|\bpypi\b|\bmaven\b|\bframework\b"))]),
    ("cli", "CLI tool / setuid utility", "Command-line programs and privileged binaries", [("any", "text", rx(r"\bcommand[- ]line (tool|utility|interface|argument)\b|\bcli\b|\butility\b|\bsetuid\b|\bsudo\b"))]),
    ("firmware_dev", "Firmware / embedded product", "Software shipped inside a device", [("any", "text", rx(r"\bfirmware\b|\bembedded\b|\bdevice (firmware|software)\b|\bover[- ]the[- ]air\b|\bota update\b"))]),
    ("devtool", "IDE / developer tool / CI", "Editors, compilers, CI, notebooks, AI coding tools", [("any", "text", rx(r"\bide\b|\bvisual studio( code)?\b|\bvscode\b|\bintellij\b|\beclipse\b|\bjenkins\b|\bgithub actions\b|\bgitlab ci\b|\bci/cd\b|\bbuild (system|pipeline|server)\b|\bcompiler\b|\bdebugger\b|\bjupyter\b|\bnotebook\b|\bcopilot\b"))]),
    ("cms_plugin", "CMS plugin / theme / extension", "WordPress, Joomla, Drupal, Shopify add-ons", [("any", "text", rx(r"\bwordpress plugin\b|\bplugin\b|\btheme\b|\bextension for\b|\bjoomla\b|\bdrupal\b|\bwoocommerce\b|\bshopify app\b")),
        ("vp", "curated", rx(r"patchstack|wordfence|wpscan|wordpress"))]),
]

SECTOR = [
    ("health", "Healthcare", "Hospitals, EHR, medical software", [("any", "text", rx(r"\bhealthcare\b|\bhospital\b|\bpatient\b|\behr\b|\bemr\b|\bclinic(al)?\b|\bpharmacy\b|\bdicom\b|\bhl7\b|\bmedical\b"))]),
    ("automotive", "Automotive & transport", "Vehicles, fleets, EV charging, aviation, rail", [("any", "text", rx(r"\bautomotive\b|\bvehicles?\b|\bfleet\b|\baviation\b|\bairline\b|\brailway\b|\bev charg|\btelematics\b|\binfotainment\b"))]),
    ("energy", "Energy & utilities", "Power, solar, metering, oil and gas", [("any", "text", rx(r"\bsmart meter\b|power (plant|grid|system)\b|\bsubstation\b|\bsolar\b|\binverter\b|\bwind turbine\b|\boil and gas\b|\bpipeline\b|\butilit(y|ies)\b|\bdnp3\b|\biec 61850\b|\benergy management\b"))]),
    ("telecom", "Telecom", "Carriers, 5G cores, base stations, VoIP", [("any", "text", rx(r"\btelecom\b|\b5g\b|\bcarrier\b|\bcore network\b|\bbase station\b|\bims\b|\bnokia\b|\bericsson\b|\bhuawei\b|\bvolte\b"))]),
    ("finance", "Finance & payments", "Banking, payments, accounting, crypto wallets", [("any", "text", rx(r"\bbank(ing)?\b|\bpayments?\b|\bfinancial\b|\bcredit card\b|\bfintech\b|\binvoic(e|ing)\b|\baccounting\b|\bstripe\b|\bpaypal\b|\bcryptocurrency\b"))]),
    ("ecommerce", "E-commerce", "Shops, carts, storefront platforms", [("any", "text", rx(r"\bwoocommerce\b|\bmagento\b|\bprestashop\b|\bopencart\b|\bshopify\b|\bshopping cart\b|\be-?commerce\b|\bonline (store|shop)\b|\bcheckout\b"))]),
    ("education", "Education", "LMS, schools, student systems", [("any", "text", rx(r"\bmoodle\b|\bschool\b|\buniversity\b|\bstudents?\b|\bcourses?\b|\blms\b|\be-?learning\b|\bclassroom\b"))]),
    ("gaming", "Gaming & entertainment", "Games, engines, launchers, streaming", [("any", "text", rx(r"\bgame\b|\bgaming\b|\bsteam\b|\bunity (engine|editor|webplayer)\b|\bunreal engine\b|\bminecraft\b"))]),
]

CRYPTO = [
    ("aes", "AES / Rijndael", "AES in any mode or key size", [("any", "text", rx(r"\baes([-_ ]?(128|192|256|ni|gcm|cbc|ctr|ecb|xts|ccm))?\b|\brijndael\b"))]),
    ("des", "DES / 3DES", "DES, Triple-DES, Sweet32", [("any", "text", rx(r"\b3des\b|\btriple[- ]des\b|\btdea\b|\bsweet32\b|\bdes\b(?= (hash|crypt|cipher|encryption|key|algorithm|cbc|ecb|ede))|\bdes-(cbc|ecb|ede3?)\b"))]),
    ("legacy_cipher", "RC4 / RC2 / Blowfish / other legacy ciphers", "Broken or obsolete symmetric ciphers", [("any", "text", rx(r"\brc[24]\b|\barcfour\b|\bblowfish\b|\bcast5\b|\bxor (cipher|encryption)\b|\bweak (cipher|encryption)\b"))]),
    ("chacha", "ChaCha20 / Salsa20 / Poly1305", "Modern stream ciphers and MACs", [("any", "text", rx(r"\bchacha\d*\b|\bsalsa\d*\b|\bpoly1305\b"))]),
    ("rsa", "RSA / PKCS#1", "RSA keys, padding, Bleichenbacher-style oracles", [("any", "text", rx(r"\brsa\b|\bpkcs ?#?1\b|\bbleichenbacher\b|\boaep\b|\bcoppersmith\b"))]),
    ("ecc", "Elliptic curves (ECDSA, ECDH, Ed25519)", "ECC signatures and key agreement", [("any", "text", rx(r"\becdsa\b|\becdh\b|\bed25519\b|\beddsa\b|\belliptic[- ]curve\b|\bsecp256|\bp-?256\b|\bcurve25519\b|\becc\b|\bcurveball\b"))]),
    ("dh", "Diffie-Hellman / key exchange", "DH, DHE, Logjam, key agreement", [("any", "text", rx(r"\bdiffie|\blogjam\b|\bdh parameters\b|\bffdhe\b|\bkey exchange\b|\bkey agreement\b"))]),
    ("hash_weak", "MD5 / SHA-1 / CRC (weak hashes)", "Collision-prone or non-cryptographic hashes used for security", [("any", "text", rx(r"\bmd[245]\b|\bsha-?1\b|\bcrc-?(16|32)?\b|\bcollision attacks?\b|\bweak hash\b"))]),
    ("hash_strong", "SHA-2 / SHA-3 / BLAKE", "Modern hash functions", [("any", "text", rx(r"\bsha-?(2|3|224|256|384|512)\b|\bblake2?\b|\bripemd\b|\bkeccak\b"))]),
    ("mac", "HMAC / MAC / authentication tags", "Message authentication", [("any", "text", rx(r"\bhmac\b|\bcmac\b|\bmessage authentication\b|\bauthentication tag\b|\bmac (tag|check|verification)\b"))]),
    ("modes", "Cipher modes / padding / IV and nonce use", "ECB, CBC, CTR, GCM, padding oracles, IV reuse", [("any", "text", rx(r"\becb\b|\bcbc\b|\bctr mode\b|\bgcm\b|\bxts\b|\bpadding oracle\b|\bpkcs ?#?7\b|\bblock cipher\b|\bstatic iv\b|\biv reuse\b|\bnonce reuse\b|\bnonce (is )?reused\b"))]),
    ("kdf", "Password hashing / KDF (bcrypt, scrypt, PBKDF2, Argon2)", "Password storage and key derivation", [("any", "text", rx(r"\bpbkdf2?\b|\bbcrypt\b|\bscrypt\b|\bargon2\b|password hash|key derivation|\bhkdf\b|\bunsalted\b|\bsalted (hash|password)|\bpassword salt\b|\bwithout (a )?salt\b"))]),
    ("prng", "Random number generation", "PRNG/CSPRNG quality, seeds, entropy", [("any", "text", rx(r"\bprng\b|random number generator|\bcsprng\b|\brand\(\)|\bmath\.random\b|\bmt19937\b|\bmersenne\b|\bpseudo-?random\b|\bpredictable (random|seed|token|number|value)s?\b|\binsufficient(ly)? (random|entropy)\b|\blow entropy\b|\bentropy (source|pool)\b|\bweak seed\b|\bseed(ed)? (the )?(random|prng|generator)\b|\binsecure(ly)? random\b"))]),
    ("pqc", "Post-quantum (Kyber, Dilithium, ML-KEM)", "Post-quantum algorithms", [("any", "text", rx(r"\bpost-?quantum\b|\bkyber\b|\bml-?kem\b|\bdilithium\b|\bml-?dsa\b|\bsphincs"))]),
    ("tls_suites", "TLS cipher suites / downgrade / protocol attacks", "Export-grade ciphers, POODLE, Lucky13, downgrade", [("any", "text", rx(r"\bcipher suites?\b|\bexport[- ]grade\b|\bpoodle\b|\blucky ?13\b|\bsweet32\b|\blogjam\b|\bfreak\b|\bbeast attack\b|\bdowngrade attack\b|\bcertificate pinning\b"))]),
    ("signature_cert", "Signatures / certificates / PGP", "Digital signatures, X.509, code signing, PGP", [("any", "text", rx(r"\bdigital signatures?\b|\bsignature (verification|validation|forg)|\bx\.?509\b|\bcertificate (validation|verification)\b|\bcode signing\b|\bpgp\b|\bgpg\b|\bgnupg\b|\bs/mime\b"))]),
    ("sidechannel", "Side channels / timing attacks", "Timing, cache and power side channels", [("any", "text", rx(r"\bside[- ]channel\b|\btiming (attack|side channel|leak)|\bconstant[- ]time\b|\bcache[- ]timing\b|\bpower analysis\b|\bfault injection\b"))]),
    ("key_handling", "Key / secret handling", "Hard-coded, exposed or mishandled keys and secrets", [("any", "text", rx(r"\bhard-?coded (key|crypto|secret|password|credential)s?\b|\bprivate key\b|\bsecret key\b|\bencryption key\b|\bkey (material|storage)\b|\bapi keys? (is|are) (exposed|leaked|disclosed|hard-?coded)\b|\b(exposed|leak(s|ed|ing)?|disclos\w+) (of )?(the )?api keys?\b"))]),
]

ALGO = [
    ("compression", "Compression / decompression", "zlib, deflate, gzip, bzip2, LZ4, zstd, Huffman, zip bombs", [("any", "text", rx(r"\b(zlib|deflate|inflate|gzip|bzip2|lzma|lz4|lzo|zstd|zstandard|brotli|lz77|huffman)\b|\bdecompress(ion|or)?\b|\bcompress(ion|ed data)\b|\bzip bomb\b"))]),
    ("regex", "Regex backtracking (ReDoS)", "Catastrophic backtracking in regular expressions", [("any", "text", rx(r"\bredos\b|regular expression denial|catastrophic backtracking|\bbacktracking\b|inefficient regular expression"))]),
    ("hash_collision", "Hash tables / hash flooding", "Hash-collision denial of service, algorithmic complexity", [("any", "text", rx(r"hash (collision|flooding|table|dos)|\bhashdos\b|algorithmic complexity|quadratic (time|complexity|behavior)|worst-case (time|complexity)|computationally expensive"))]),
    ("recursion", "Recursion / nesting depth", "Stack exhaustion from deeply nested input", [("any", "text", rx(r"\brecursi(on|ve|vely)\b|stack exhaustion|deeply nested|nesting depth|\bdepth limit\b|\bunbounded recursion\b|\bnested (arrays|objects|elements|structures)\b"))]),
    ("sorting", "Sorting / searching algorithms", "qsort, binary search, comparison functions", [("any", "text", rx(r"\b(quick|merge|heap|bubble|radix)sort\b|\bsorting\b|\bbinary search\b|\bqsort\b|\bbsearch\b|comparison function"))]),
    ("numeric", "Numeric / floating-point / big-number math", "Rounding, precision, BigInt, modular arithmetic", [("any", "text", rx(r"floating[- ]point|\brounding\b|\bbigint\b|\bbignum\b|\bmodular (arithmetic|exponent)|\bnan\b|big (integer|number)s?|\b(integer|arithmetic) (multiplication|division)\b"))]),
    ("structures", "Data structures (lists, trees, tries, queues)", "Linked lists, B-trees, tries, bloom filters, maps", [("any", "text", rx(r"\blinked list\b|\bbinary tree\b|\bb-?tree\b|\bred-?black\b|\btrie\b|\bbloom filter\b|\bhash map\b|\bpriority queue\b|\bdata structures?\b|\bring buffer\b|\blinked-list\b"))]),
    ("parsing", "Parsing / state machines", "Parsers, tokenizers, grammars, protocol state machines", [("any", "text", rx(r"\bparser\b|\bparsing\b|\bgrammar\b|\btokeni[sz]er\b|\blexer\b|\bstate machine\b"))]),
    ("encoding", "Encodings / checksums (Base64, UTF-8, Unicode)", "Character encodings, normalization, checksums, punycode", [("any", "text", rx(r"\bbase64\b|\butf-?(8|16|7)\b|\bunicode\b|\bnormali[sz]ation\b|\bchecksum\b|\bpunycode\b|\bcharacter (encoding|set)\b|\bcharset\b|\burl[- ]?encod"))]),
]

DIMENSIONS = {"os": OS, "lang": LANG, "system": SYSTEM, "hardware": HARDWARE, "arch": ARCH,
              "network": NETWORK, "vector": VECTOR, "impact": IMPACT, "format": FORMAT,
              "deploy": DEPLOY, "sector": SECTOR, "crypto": CRYPTO, "algo": ALGO}
DIM_LABELS = {
    "os": "Operating system / platform", "lang": "Programming language / runtime", "system": "System type",
    "hardware": "Hardware / device class", "arch": "CPU architecture", "network": "Network protocol / technology",
    "vector": "Attack vector / precondition (as worded)", "impact": "Impact (as worded)",
    "format": "File format / data parser", "deploy": "How it is delivered / deployed", "sector": "Sector / domain",
    "crypto": "Cryptographic algorithm / primitive", "algo": "Algorithm / data structure",
}
DIM_GROUPS = [
    {"title": "Platform", "dims": ["os", "arch"]},
    {"title": "Software", "dims": ["lang", "system", "deploy", "format"]},
    {"title": "Hardware", "dims": ["hardware"]},
    {"title": "Network", "dims": ["network"]},
    {"title": "Cryptography & algorithms", "dims": ["crypto", "algo"]},
    {"title": "Attack", "dims": ["vector", "impact"]},
    {"title": "Sector", "dims": ["sector"]},
]
assert all(len(v) <= 32 for v in DIMENSIONS.values()), "a dimension has more than 32 values"


def rules_json():
    """Export the rules in a dialect both Python and JavaScript regex engines read identically."""
    out = {}
    for dim, defs in DIMENSIONS.items():
        out[dim] = []
        for bit, (key, _label, _doc, rules) in enumerate(defs):
            out[dim].append({"key": key, "bit": bit, "rules": [
                {"field": f, "kind": k, "pattern": r.pattern, "flags": "i" if r.flags & re.I else ""} for f, k, r in rules]})
    return out
