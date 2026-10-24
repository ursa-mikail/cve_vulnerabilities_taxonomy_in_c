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

DIMENSIONS = {"os": OS, "lang": LANG, "system": SYSTEM}
DIM_LABELS = {"os": "Operating system / platform", "lang": "Programming language / runtime", "system": "System type"}


def rules_json():
    """Export the rules in a dialect both Python and JavaScript regex engines read identically."""
    out = {}
    for dim, defs in DIMENSIONS.items():
        out[dim] = []
        for bit, (key, _label, _doc, rules) in enumerate(defs):
            out[dim].append({"key": key, "bit": bit, "rules": [
                {"field": f, "kind": k, "pattern": r.pattern, "flags": "i" if r.flags & re.I else ""} for f, k, r in rules]})
    return out
