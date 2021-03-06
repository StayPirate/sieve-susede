require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include", "imap4flags", "body" ];

###################################
##### CRAZYBYTE SECURITY FEED #####
###################################
# Notifications are generated by a rss2email daemon. Source code and configuration
# can be found here: https://github.com/StayPirate/rss2email
#
# Feed
# ├── Weekly update
# │   ├── Ubuntu sec podcast
# │   ├── SSD
# │   ├── LWN
# │   └── AT&T
# ├── Blog
# │   ├── TOR
# │   ├── Darknet Diaries
# │   ├── Mozilla
# │   ├── Github
# │   ├── Microsoft
# │   ├── Chromium
# │   ├── Chrome
# │   ├── Google
# │   ├── Cloudflare
# │   ├── Sentinelone
# │   ├── Intezer
# │   ├── Avast
# │   ├── Good Reads
# │   ├── Activism
# │   └── Guerredirete
# ├── Ezine
# │   ├── AppSec
# │   ├── POCorGTFO
# │   └── Uninformed
# ├── SA
# │   ├── Distro
# │   │   ├── Debian
# │   │   ├── Ubuntu
# │   │   ├── RedHat
# │   │   ├── SUSE
# │   │   │   ├── container
# │   │   │   └── image
# │   │   ├── openSUSE
# │   │   ├── Gentoo
# │   │   ├── Fedora
# │   │   ├── Slackware
# │   │   ├── Archlinux
# │   │   └── Oracle
# │   ├── Github
# │   ├── PowerDNS
# │   ├── Rust
# │   ├── Drupal
# │   ├── Tomcat
# │   ├── Jenkins
# │   ├── WebKit
# │   ├── Nmap
# │   ├── Xen
# │   ├── OpenJDK
# │   ├── Weechat
# │   ├── TOR
# │   ├── VLC
# │   └── GCP
# ├── Release
# │   ├── Podman
# │   ├── ClamAV
# │   ├── Chrome
# │   ├── SUSE
# │   │   ├── Secbox
# │   │   └── Userscripts
# │   └── ucode
# │       └── Intel
# └── News Letter
#     ├── CyberSaiyan
#     └── Linux Foundation

if header :is "X-RSS-Instance" "crazybyte-security-feed" {

    # rule:[convert X-RSS-Tags to IMAP-flags]
    # This rule takes the whole string in the header X-RSS-Tags and use it to set IMAP-flags.
    # The string is expected to be either a single word or multiple words separated by a single space.
    if exists "X-RSS-Tags" {
        if header :matches "X-RSS-Tags" "*" {
            addflag "${1}";
        }
    }

#   ██╗    ██╗███████╗███████╗██╗  ██╗██╗  ██╗   ██╗    ██╗   ██╗██████╗ ██████╗  █████╗ ████████╗███████╗
#   ██║    ██║██╔════╝██╔════╝██║ ██╔╝██║  ╚██╗ ██╔╝    ██║   ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
#   ██║ █╗ ██║█████╗  █████╗  █████╔╝ ██║   ╚████╔╝     ██║   ██║██████╔╝██║  ██║███████║   ██║   █████╗  
#   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗ ██║    ╚██╔╝      ██║   ██║██╔═══╝ ██║  ██║██╔══██║   ██║   ██╔══╝  
#   ╚███╔███╔╝███████╗███████╗██║  ██╗███████╗██║       ╚██████╔╝██║     ██████╔╝██║  ██║   ██║   ███████╗
#    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝        ╚═════╝ ╚═╝     ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

    # rule:[Ubuntu security podcast]
    # https://ubuntusecuritypodcast.org
    if header :is "X-RSS-Feed" "https://ubuntusecuritypodcast.org/" {
        fileinto :create "INBOX/Feed/Weekly update/Ubuntu sec podcast";
        stop;
    }

    # rule:[SSD Secure Disclosure]
    # https://www.youtube.com/channel/UC9ZnYbYqOe6Y3eRdw0TMz9Q
    if header :is "X-RSS-Feed" "https://www.youtube.com/channel/UC9ZnYbYqOe6Y3eRdw0TMz9Q" {
        fileinto :create "INBOX/Feed/Weekly update/SSD";
        stop;
    }

    # rule:[AT&T Youtube tech channel]
    # https://www.youtube.com/channel/UCnpDurxReTSpFs5-AhDo8Kg
    if header :is "X-RSS-Feed" "https://www.youtube.com/channel/UCnpDurxReTSpFs5-AhDo8Kg" {
        fileinto :create "INBOX/Feed/Weekly update/AT&T";
        stop;
    }

    # rule:[Dayzerosec Podcast]
    # https://dayzerosec.com/podcast/
    if header :is "X-RSS-Feed" "https://dayzerosec.com/" {
        fileinto :create "INBOX/Feed/Weekly update/Dayzerosec";
        stop;
    }

    #### TODO # In order to only get security-related article from LWN I could use
    #### TODO # this page: https://lwn.net/headlines/text, but I need to use urlwatch.

#   ██████╗ ██╗      ██████╗  ██████╗ 
#   ██╔══██╗██║     ██╔═══██╗██╔════╝ 
#   ██████╔╝██║     ██║   ██║██║  ███╗
#   ██╔══██╗██║     ██║   ██║██║   ██║
#   ██████╔╝███████╗╚██████╔╝╚██████╔╝
#   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ 

    # rule:[Chromium Blog (security)]
    # http://blog.chromium.org
    if allof ( header :contains "X-RSS-Feed" "blog.chromium.org",
               header :contains "Keywords" "security" ) {
        fileinto :create "INBOX/Feed/Blog/Chromium";
        stop;
    }

    # rule:[Chrome Blog (security)]
    # http://security.googleblog.com/
    if header :contains "X-RSS-Feed" "http://security.googleblog.com/" {
        fileinto :create "INBOX/Feed/Blog/Chrome";
        stop;
    }

    # rule:[Google Blog (security)]
    # https://blog.google
    if allof ( header :is "X-RSS-Feed" "https://blog.google/",
               header :contains "Keywords" "security" ) {
        fileinto :create "INBOX/Feed/Blog/Google";
        stop;
    }

    # rule:[Microsoft Security Blog]
    # https://www.microsoft.com/security/blog
    if header :is "X-RSS-Feed" "https://www.microsoft.com/security/blog" {
        fileinto :create "INBOX/Feed/Blog/Microsoft";
        stop;
    }

    # rule:[Microsoft Security Response Center Blog]
    # https://msrc-blog.microsoft.com
    if header :is "X-RSS-Feed" "https://msrc-blog.microsoft.com" {
        fileinto :create "INBOX/Feed/Blog/Microsoft";
        stop;
    }

    # rule:[GitHub Security Blog]
    # https://github.blog/category/security/feed/
    if header :is "X-RSS-Feed" "https://github.blog" {
        fileinto :create "INBOX/Feed/Blog/Github";
        stop;
    }

    # rule:[Mozilla Security Blog]
    # https://blog.mozilla.org/security
    if header :is "X-RSS-Feed" "https://blog.mozilla.org/security" {
        fileinto :create "INBOX/Feed/Blog/Mozilla";
        stop;
    }

    # rule:[Darknet Diaries Podcast]
    # https://darknetdiaries.com/
    if header :is "X-RSS-Feed" "https://darknetdiaries.com/" {
        fileinto :create "INBOX/Feed/Blog/Darknet Diaries";
        stop;
    }

    # rule:[TOR blog]
    # https://blog.torproject.org/
    # Ignore release notifications
    if allof (  header :is "X-RSS-Feed" "https://blog.torproject.org/",
                not header :contains "Subject" "New",
                not header :contains "Subject" "Release:" ) {
        fileinto :create "INBOX/Feed/Blog/TOR";
        stop;
    }

    # rule:[Guerre di rete]
    # https://guerredirete.substack.com
    if header :is "X-RSS-Feed" "https://guerredirete.substack.com" {
        fileinto :create "INBOX/Feed/Blog/Guerredirete";
        addflag "italian";
        stop;
    }

    # rule:[Stackoverflow]
    # Essays, opinions, and advice on the act of computer programming from Stack Overflow.
    # https://stackoverflow.blog
    if header :is "X-RSS-Feed" "https://stackoverflow.blog" {
        if header :contains "Keywords" "security" {
            fileinto :create "INBOX/Feed/Blog/Stackoverflow";
            stop;
        }
    }

    # rule:[Justin Steven SA]
    # https://github.com/justinsteven/advisories
    if header :is "X-RSS-Feed" "https://github.com/justinsteven/advisories/commits/main" {
        fileinto :create "INBOX/Feed/Blog/Good Reads";
        stop;
    }

    # rule:[Cryptography Dispatches]
    # Cryptography Dispatches by Filippo Valsorda (AKA FiloSottile)
    # https://buttondown.email/cryptography-dispatches
    if header :is "X-RSS-Feed" "https://buttondown.email/cryptography-dispatches" {
        fileinto :create "INBOX/Feed/Blog/Good Reads";
        stop;
    }

    # rule:[0pointer]
    # Lennart Poettering personal blog
    # https://0pointer.net/blog
    if header :is "X-RSS-Feed" "https://0pointer.net/blog/" {
        fileinto :create "INBOX/Feed/Blog/Good Reads";
        stop;
    }

    # Grapl Security
    # https://www.graplsecurity.com/subscribe

    # rule:[Hermes Press]
    # Center for Transparency and Digital Human Rights
    # https://www.hermescenter.org/press/
    if header :is "X-RSS-Feed" "https://www.hermescenter.org" {
        fileinto :create "INBOX/Feed/Blog/Activism";
        addflag "italian";
        stop;
    }

    # rule:[copernicani]
    # https://www.copernicani.it
    if allof ( header :is "X-RSS-Feed" "https://www.copernicani.it",
               header :contains "Keywords" [ "cybersecurity", "cyberwarfare" ] ) {
        fileinto :create "INBOX/Feed/Blog/Activism";
        addflag "italian";
        stop;
    }

    # rule:[Sentinelone]
    # https://sentinelone.com/blog/
    if allof (  header :contains "X-RSS-Feed" "sentinelone.com",
                header :contains "Keywords" [ "security", "cybercrime", "malware", "escape" ] ) {

                    # They use Cloudflare CDN which in turn redirects (302) to the italian
                    # blog (it.sentinelone.com) if the request comes from an italian IP.
                    # (╯°□°)╯︵ ┻━┻
                    if header :contains "X-RSS-Feed" "https://it.sentinelone.com" { 
                        addflag "italian";
                    }

                    fileinto :create "INBOX/Feed/Blog/Sentinelone";
                    stop;
    }

    # rule:[Cloudflare]
    # https://blog.cloudflare.com
    if allof ( header :is "X-RSS-Feed" "https://blog.cloudflare.com/",
               header :contains "Keywords" [ "security", "Vulnerabilit" ] ) {
        fileinto :create "INBOX/Feed/Blog/Cloudflare";
        stop;
    }

    # rule:[Grsecurity]
    # https://www.grsecurity.net/blog
    if header :is "X-RSS-Feed" "https://www.grsecurity.net/blog.rss" {
        fileinto :create "INBOX/Feed/Blog/Good Reads";
        stop;
    }

    # rule:[Intezer]
    # https://www.intezer.com/blog/
    if header :is "X-RSS-Feed" "https://www.intezer.com" {
        fileinto :create "INBOX/Feed/Blog/Intezer";
        stop;
    }

    # rule:[Avast]
    # https://decoded.avast.io/
    if header :is "X-RSS-Feed" "https://decoded.avast.io" {
        fileinto :create "INBOX/Feed/Blog/Avast";
        stop;
    }

#   ███████╗███████╗██╗███╗   ██╗███████╗
#   ██╔════╝╚══███╔╝██║████╗  ██║██╔════╝
#   █████╗    ███╔╝ ██║██╔██╗ ██║█████╗  
#   ██╔══╝   ███╔╝  ██║██║╚██╗██║██╔══╝  
#   ███████╗███████╗██║██║ ╚████║███████╗
#   ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝

    # rule:[AppSec]
    # https://github.com/Simpsonpt/AppSecEzine
    if header :is "X-RSS-Feed" "https://github.com/Simpsonpt/AppSecEzine/commits/master" {
        fileinto :create "INBOX/Feed/Ezine/AppSec";
        stop;
    }

    # rule:[POCorGTFO]
    # POC||GTFO Ezine feed - from the Evan Sultanik website (one of the main mirrors)
    # https://www.sultanik.com/pocorgtfo/
    if allof ( header :is       "X-RSS-Feed" "https://www.sultanik.com/",
               header :contains "X-RSS-Link" "https://www.sultanik.com/pocorgtfo" ) {
        fileinto :create "INBOX/Feed/Ezine/POCorGTFO";
        stop;
    }

    # rule:[uninformed]
    # http://uninformed.org/
    if header :is "X-RSS-Feed" "http://uninformed.org/" {
        fileinto :create "INBOX/Feed/Ezine/Uninformed";
        stop;
    }

#   ███████╗███████╗ ██████╗     █████╗ ██████╗ ██╗   ██╗██╗███████╗ ██████╗ ██████╗ ██╗   ██╗
#   ██╔════╝██╔════╝██╔════╝    ██╔══██╗██╔══██╗██║   ██║██║██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
#   ███████╗█████╗  ██║         ███████║██║  ██║██║   ██║██║███████╗██║   ██║██████╔╝ ╚████╔╝ 
#   ╚════██║██╔══╝  ██║         ██╔══██║██║  ██║╚██╗ ██╔╝██║╚════██║██║   ██║██╔══██╗  ╚██╔╝  
#   ███████║███████╗╚██████╗    ██║  ██║██████╔╝ ╚████╔╝ ██║███████║╚██████╔╝██║  ██║   ██║   
#   ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

    # rule:[GitHub Security Advisory]
    # https://securitylab.github.com/
    if header :is "X-RSS-Feed" "https://securitylab.github.com/" {
        fileinto :create "INBOX/Feed/SA/Github";
        stop;
    }

    # rule:[Drupal]
    # https://www.drupal.org/security
    if header :is "X-RSS-Feed" "https://www.drupal.org/security" {
        fileinto :create "INBOX/Feed/SA/Drupal";
        stop;
    }

    # rule:[PowerDNS]
    # https://powerdns.com
    if allof ( header :is "X-RSS-Feed" "https://blog.powerdns.com",
               header :contains "Subject" "Security Advisory" ) {
        fileinto :create "INBOX/Feed/SA/PowerDNS";
        stop;
    }

    # rule:[RustSec]
    # https://rustsec.org - SA for Rust crates published via crates.io
    if header :is "X-RSS-Feed" "https://rustsec.org/" {
        addflag "rustsec";
        fileinto :create "INBOX/Feed/SA/Rust";
        stop;
    }

    # rule:[Rust]
    # https://blog.rust-lang.org/ - SA from the main Rust blog
    if allof (  header :is "X-RSS-Feed" "https://blog.rust-lang.org/",
                header :contains "Subject" "Security advisory" ) {
                    addflag "rust-blog";
                    fileinto :create "INBOX/Feed/SA/Rust";
                    stop;
    }

    # Debian Security Advisories (DSA) are fetched from the debian-security-announce ML, since
    # it provides much more detailed information compared to the DSA RSS-feed.
    # DSA ML:       https://lists.debian.org/debian-security-announce/
    # DSA RSS-feed: https://www.debian.org/security/dsa

    # Ubuntu Security Notice (USN) are fetched from the ubuntu-security-announce ML.
    # USN:          https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce

    # RedHat Security Advisories (RHSA) are gotten by the rhsa-announce ML.
    # RHSA:         https://listman.redhat.com/mailman/listinfo/rhsa-announce

    # openSUSE Security Update (openSUSE-SU/SUSE-SU) are fetched from the security-announce ML.
    # If the update is shipped to both openSUSE and SUSE, then the name is SUSE-SU, while if
    # it's exclusive for openSUSE it is named openSUSE-SU.
    # openSUSE-SU:  https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org

    # SUSE Security Update (SUSE-SU) are fetched from the sle-security-updates ML.
    # It also notify about "SUSE Container Update Advisory" and "SUSE Image Update Advisory" as well. 
    # SUSE-SU:      https://lists.suse.com/mailman/listinfo/sle-security-updates

    # Arch Linux Security Advisory (ASA) are fetched from the arch-security ML.
    # ASA:          https://lists.archlinux.org/listinfo/arch-security

    # Gentoo Linux Security Advisories (GLSA) are fetched from the gentoo-announce ML.
    # GLSA:         https://security.gentoo.org/glsa

    # Slackware Security Advisories (SSA) are fetched from the slackware-security ML.
    # SSA:          http://www.slackware.com/lists/archive/

    # Oracle Linux Security Advisories (ELSA) are fetched from the el-errata ML.
    # ELSA:         https://oss.oracle.com/mailman/listinfo/el-errata

    # rule:[Fedora]
    # https://bodhi.fedoraproject.org/updates/?search=&type=security
    if header :is "X-RSS-Feed" "https://bodhi.fedoraproject.org/rss/updates/?search=&status=stable&type=security" {
        fileinto :create "INBOX/Feed/SA/Distro/Fedora";
        stop;
    }

    # rule:[GCP]
    # https://cloud.google.com/support/bulletins
    if header :contains "X-RSS-Link" "https://cloud.google.com/support/bulletins/index#" {
        fileinto :create "INBOX/Feed/SA/GCP";
        stop;
    }

    # Jenkins SA are fetched from the osss ML.
    # http://oss-security.openwall.org/wiki/mailing-lists/oss-security

    # WebKit SA are fetched from the osss ML.
    # http://oss-security.openwall.org/wiki/mailing-lists/oss-security

    # Xen SA (XSA) are fetched from the xen-announce ML.
    # https://lists.xenproject.org/cgi-bin/mailman/listinfo/xen-announce

    # Weechat SA are fetched from the weechat-security ML.
    # https://lists.nongnu.org/mailman/listinfo/weechat-security

    # rule:[TOR SA]
    # https://tails.boum.org/security/index.en.html
    if header :contains "X-RSS-Feed" "https://tails.boum.org/security/index.en.html" {
        fileinto :create "INBOX/Feed/SA/TOR";
        stop;
    }

    # rule:[VLC]
    # https://www.videolan.org/security/
    if allof( header :contains "X-RSS-Feed" "http://www.videolan.org/",
              body :contains [ "security", "affected" ] ) {
        fileinto :create "INBOX/Feed/SA/VLC";
        stop;
    }

    # OpenJDK Vulnerability Advisory are fetched from the vuln-announce ML.
    # https://mail.openjdk.org/mailman/listinfo/vuln-announce

#   ██████╗ ███████╗██╗     ███████╗ █████╗ ███████╗███████╗
#   ██╔══██╗██╔════╝██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
#   ██████╔╝█████╗  ██║     █████╗  ███████║███████╗█████╗  
#   ██╔══██╗██╔══╝  ██║     ██╔══╝  ██╔══██║╚════██║██╔══╝  
#   ██║  ██║███████╗███████╗███████╗██║  ██║███████║███████╗
#   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝

    # rule:[Chrome]
    # https://chromereleases.googleblog.com
    if allof ( header :contains "X-RSS-Feed" "chromereleases.googleblog.com",
               header :contains "Keywords" "Desktop Update",
               header :contains "Keywords" "Stable updates" ) {
        fileinto :create "INBOX/Feed/Release/Chrome";
        stop;
    }

    # rule:[ClamAV]
    # https://www.clamav.net/
    if header :is "X-RSS-Feed" "http://blog.clamav.net/" {
        fileinto :create "INBOX/Feed/Release/ClamAV";
        stop;
    }

    # rule:[Podman]
    # https://www.drupal.org/security
    if header :is "X-RSS-Feed" "https://github.com/containers/podman/releases" {
        fileinto :create "INBOX/Feed/Release/Podman";
        stop;
    }

    # rule:[SUSE userscripts]
    # https://gitlab.suse.de/gsonnu/userscripts
    if header :is "X-RSS-Feed" "https://gitlab.suse.de/gsonnu/userscripts" {
        fileinto :create "INBOX/Feed/Release/SUSE/Userscripts";
        stop;
    }

    # rule:[SUSE secbox]
    # https://github.com/StayPirate/secbox
    if header :is "X-RSS-Feed" "https://github.com/StayPirate/secbox/releases" {
        fileinto :create "INBOX/Feed/Release/SUSE/Secbox";
        stop;
    }

    # Nmap/Npcap announcements are fetched from the nmap announce ML.
    # https://nmap.org/mailman/listinfo/announce

    # rule:[intel ucode]
    # https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files
    if header :is "X-RSS-Feed" "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases" {
        fileinto :create "INBOX/Feed/Release/ucode/Intel";
        stop;
    }

#   ███╗   ██╗███████╗██╗    ██╗███████╗    ██╗     ███████╗████████╗████████╗███████╗██████╗ 
#   ████╗  ██║██╔════╝██║    ██║██╔════╝    ██║     ██╔════╝╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
#   ██╔██╗ ██║█████╗  ██║ █╗ ██║███████╗    ██║     █████╗     ██║      ██║   █████╗  ██████╔╝
#   ██║╚██╗██║██╔══╝  ██║███╗██║╚════██║    ██║     ██╔══╝     ██║      ██║   ██╔══╝  ██╔══██╗
#   ██║ ╚████║███████╗╚███╔███╔╝███████║    ███████╗███████╗   ██║      ██║   ███████╗██║  ██║
#   ╚═╝  ╚═══╝╚══════╝ ╚══╝╚══╝ ╚══════╝    ╚══════╝╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝

    # Linux Foundation
    # https://linuxfoundation.org

    # CyberSaiyan (ITA)
    # https://cybersaiyan.us17.list-manage.com


    #_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#
    #                                                       #
    #   If no rule matched the notification is discarded.   #
    #                                                       #
    #_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#

    #discard;
    fileinto :create "INBOX/Trash";

}