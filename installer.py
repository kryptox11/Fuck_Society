#!/usr/bin/python
# coding: utf8
# Autore: Skull00
try:
    import os,sys,time,readline,socket,requests,platform
    from time import sleep
    #
    global end,red,blue,bright_green,bright_yellow,underline
    end = '\033[0m'
    red = '\033[1;31m'
    blue = '\033[1;34m'
    bright_green = '\033[1;32m'
    bright_yellow = '\033[1;33m'
    black = "\033[1;30m"
    underline = '\033[4m'
except KeyboardInterrupt:
    sys.exit("")

sys.stdout.write("\x1b]2;Fuck Society Installer\x07") # Titolo finestra

euid = os.geteuid()
if euid != 0:
    print("-# Permessi di root richiesti")
    try:
        time.sleep(.5)
    except KeyboardInterrupt:
        sys.exit("")
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    # the next line replaces the currently-running process with the sudo
    os.execlpe('sudo', *args)

def main():
    # verifica se installato anonym8
    try:
        verify_anonym8 = open("/usr/bin/anonym8")
        print("")
        print("-# %sAnonym8%s è installato e potrebbe entrare in conflitto con %sTorGhost%s."%(blue,end, blue,end))
        print("")
        print("-# Disinstallare Anonym8?")
        try:
            command_input = raw_input("(si/no) > ")
        except (KeyboardInterrupt, EOFError):
            sys.exit("")
        tokens = command_input.split()
        try:
            command = tokens[0]
        except IndexError:
            command = None
        if command == 'si' or command == 's' or command == None:
            os.system("xterm -T 'Disinstallo Anonym8...' -e 'rm -rf /opt/anonym8 /usr/share/applications/anonym8.desktop /etc/init.d/anonym8.sh /usr/bin/anonym8 /usr/bin/anON /usr/bin/anOFF'")
            print("-# %sAnonym8%s disinstallato"%(blue,end))
            print("")
        else:
            pass
    except IOError:
        pass
    try:
        print("-# Verranno installati tutti i Pacchetti e Tools. Continuare?")
        command = raw_input("(si/no) > ")
        tokens = command.split()
        command = tokens[0]
    except IndexError:
        command = None
    except (KeyboardInterrupt,EOFError):
        sys.exit("\n")
    if command == 'si' or command == 's' or command == None:
        installer()
    elif command == 'no' or command == 'n':
        sys.exit("")
    else:
        print("(%s-%s) > Scelta non valida"%(red,end))
        return main()
def installer():
    print("")
    print("-# Avvio...")
    try:
        time.sleep(2)
    except (KeyboardInterrupt,EOFError):
        sys.exit("\n\n-# Interrotto\n")
    os.system("reset")
    print("")
    print(" %sProcesso Attuale%s                  %sStato%s\n"%(underline,end, underline,end))
    sys.stdout.write(" Preliminari ")
    sys.stdout.flush()
    os.system("xterm -T 'Updating' -e 'dpkg --add-architecture i386 && apt update && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y'") ; sleep(.1)
    os.system("xterm -T 'Updating' -e 'dpkg --configure -a && pip install --upgrade pip lxml'") ; sleep(.1)
    # cartelle (vecchie)
    if os.path.exists("Logs"): os.system("xterm -e 'rm Logs/ -r'")
    if os.path.exists("Oth"): os.system("xterm -e 'rm Oth/ -r'")
    if os.path.exists("Exploits"): os.system("xterm -e 'rm Exploits/ -r'")
    if os.path.exists("Tools"): os.system("xterm -e 'rm Tools/ -r'")
    #
    os.system("xterm -T 'Setup' -e 'rm -rf exploits/ output/ tools/'") ; sleep(.1)
    os.system("xterm -T 'setup' -e 'mkdir exploits output tools'")
    os.system("xterm -T 'Setup' -e 'mkdir output/fsociety'")
    sys.stdout.write(22 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Installo Librerie e Pacchetti ")
    sys.stdout.flush()
    time.sleep(.1)
    apt = [
"xprobe oscanner intersect ophcrack 0trace arachni clusterd pandoc bluesnarfer cmospwd rkhunter wapiti jboss-autopwn python-libpcap lynis dirbuster libncurses5-dev fimap t50 lynx xspy libssl-doc libssl-dev libdata-random-perl libfile-modified-perl default-jre openjdk-8-jdk openjdk-8-jre zlib1g-dev python-crypto python-requests libhtml-tableextract-perl libhtml-tokeparser-simple-perl libterm-shell-perl libtext-autoformat-perl bettercap thc-ssl-dos libhook-lexwrap-perl dirb medusa libxslt1-dev screen lighttpd python-pycurl python-whois maven default-jdk lib32ncurses5 libwww-mechanize-formfiller-perl php-xml php-curl php7.0-cgi skipfish driftnet btscanner zmap"
    ]
    apt_2 = [
"hash-identifier routersploit vega responder tor curl libxml2-utils sslyze commix sslscan libpcap-dev hostapd mitmf zaproxy hydra parsero cisco-torch dnsenum cookie-cadger whois bc dnsutils libjpeg62-turbo-dev wondershaper libtext-reform-perl maltegoce figlet httrack nmap python-nmap python-nfqueue wifiphisher gcc set golang upx-ucl wifite armitage joomscan sublist3r zenmap python-geoip goldeneye python-netifaces php-cgi theharvester python-pip python3-pip dnsmasq wireshark u3-pwn jsql uniscan voiphopper gnome-terminal libgd-perl findmyhash powerfuzzer sslstrip wol-e miranda cdpsnarf automater sqldict nikto jsql bluelog libxml2-dev amap siege whatweb termineter ipmitool recon-ng libffi-dev driftnet inspy libhtml-display-perl cutycapt smtp-user-enum p0f yersinia intrace hping3 dotdotpwn dnsmap python3 lib32z1"
    ]
    pip = ["cssselect validators terminaltables wget service_identity humanfriendly pybluez passlib flask wtforms pysocks pyopenssl twisted pcapy dnspython urllib3 ipaddress bs4 droopescan beautifulsoup4 sslyze requests netifaces capstone pefile colorama pylzma nmap jsonrpclib PyPDF2 olefile slowaes"]
    pip2 = ["cmd2 humanfriendly netlib"]
    excpts = ["python3 -m pip install mitmproxy","easy_install wtforms scapy mechanize lxml html5lib validate_email pyDNS stem netifaces","sudo cpan JSON"]
    for e in apt:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e apt install %s -y"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto\n")
    for e in apt_2:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e apt install %s -y"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto\n")
    #
    for e in pip:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e pip install %s"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto\n")
    #
    for e in pip2:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e pip2 install %s"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto\n")
    #
    for e in excpts:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e %s"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto\n")
    sys.stdout.write(4 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    #
    sys.stdout.write(" Scarico e Installo Exploits ")
    sys.stdout.flush()
    exp_download = [
"https://github.com/nccgroup/shocker.git",
"https://github.com/zcgonvh/cve-2017-7269.git",
"https://github.com/dreadlocked/Drupalgeddon2.git",
"https://github.com/BlackMathIT/Esteemaudit-Metasploit.git",
"https://github.com/joaomatosf/jexboss.git"
    ]
    exp_install = [
#Esteemaudit
"mkdir -p /usr/share/metasploit-framework/modules/exploits/windows/rdp/",
"cp Esteemaudit-Metasploit/esteemaudit.rb /usr/share/metasploit-framework/modules/exploits/windows/rdp/",
#
"cp cve-2017-7269/cve-2017-7269.rb /usr/share/metasploit-framework/modules/exploits/windows/iis/"
    ]
    os.chdir("exploits/")
    for e in exp_download:
        try:
            os.system("xterm -e 'git clone %s'"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto.\n")
    sys.stdout.write(6 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    os.chdir("..")
    #
    sys.stdout.write(" Scarico Tools ")
    sys.stdout.flush()
    # git clone
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        pass
    os.chdir("tools/")
    git_clone = ["--recursive https://github.com/FluxionNetwork/fluxion.git","https://github.com/susmithHCK/torghost.git",
"https://github.com/Screetsec/TheFatRat.git","https://www.github.com/v1s1t0r1sh3r3/airgeddon","https://github.com/PowerScript/KatanaFramework.git",
"https://www.github.com/AresS31/wirespy.git","https://github.com/4shadoww/hakkuframework.git","https://github.com/RedLectroid/OverThruster.git/",
"https://github.com/shawarkhanethicalhacker/D-TECT.git","https://github.com/4w4k3/BeeLogger.git","https://www.github.com/tiagorlampert/CHAOS",
"https://github.com/neoneggplant/EggShell","https://github.com/zanyarjamal/xerxes.git","https://www.github.com/1N3/Sn1per",
"https://github.com/cys3c/secHub.git","https://github.com/scriptedp0ison/FakeAuth.git","https://github.com/graniet/operative-framework.git",
"https://www.github.com/zanyarjamal/zambie","https://github.com/Gameye98/OWScan.git","https://github.com/m4ll0k/iCloudBrutter.git",
"https://www.github.com/epsylon/ufonet.git","https://github.com/EgeBalci/ARCANUS.git","https://github.com/toxic-ig/Trity.git",
"https://github.com/r00t-3xp10it/morpheus.git","https://github.com/chrizator/netattack2","https://github.com/SilentGhostX/HT-WPS-Breaker.git",
"https://www.github.com/Tuhinshubhra/RED_HAWK.git","https://github.com/Hood3dRob1n/BinGoo.git","https://www.github.com/vasco2016/shellsploit-framework",
"https://github.com/M4sc3r4n0/Evil-Droid.git","https://github.com/rand0m1ze/ezsploit.git","https://github.com/susmithHCK/cpscan.git",
"https://github.com/anilbaranyelken/tulpar.git","https://github.com/tiagorlampert/sAINT.git","https://github.com/Screetsec/Brutal.git",
"https://github.com/Moham3dRiahi/XAttacker.git","https://github.com/UltimateHackers/Blazy.git","https://github.com/pasahitz/zirikatu.git",
"https://github.com/4w4k3/KnockMail.git","https://github.com/lightos/credmap.git","https://github.com/samyoyo/weeman.git",
"https://github.com/gbrindisi/xsssniper.git","https://github.com/M4sc3r4n0/astroid.git","https://github.com/ZettaHack/PasteZort.git",
"https://github.com/Skull00/Eflood.git","https://github.com/evict/SSHScan.git","https://github.com/x3omdax/PenBox.git",
"https://github.com/xdavidhu/mitmAP.git","https://github.com/Gameye98/Black-Hydra.git","https://github.com/zerosum0x0/koadic.git",
"https://github.com/GinjaChris/pentmenu.git","https://github.com/skysploit/simple-ducky.git","https://github.com/hatRiot/zarp.git",
"https://github.com/praetorian-inc/pentestly.git","https://github.com/samratashok/Kautilya.git","https://github.com/AnarchyAngel/IPMIPWN.git",
"https://github.com/leebaird/discover.git","https://github.com/1N3/XSSTracer.git","https://github.com/UndeadSec/Debinject.git",
"https://github.com/vergl4s/instarecon.git","https://github.com/lostcitizen/sb0x-project.git","https://github.com/LOoLzeC/DarkSploit.git",
"https://github.com/ParrotSec/car-hacking-tools.git","https://github.com/Screetsec/BruteSploit.git","https://github.com/Manisso/Crips.git",
"https://github.com/rezasp/vbscan.git","https://github.com/foreni-packages/cisco-global-exploiter.git","https://github.com/sunnyelf/cheetah.git",
"https://github.com/cxdy/pybomber.git","https://github.com/thehappydinoa/iOSRestrictionBruteForce.git","https://github.com/UltimateHackers/XSStrike.git",
"https://github.com/DanMcInerney/wifijammer.git","https://github.com/stamparm/DSXS.git","https://github.com/UltimateHackers/Hash-Buster",
"https://github.com/AlisamTechnology/ATSCAN.git","https://github.com/ihebski/angryFuzzer.git","https://github.com/UltimateHackers/Breacher.git",
"https://github.com/eschultze/URLextractor.git","https://github.com/codingo/NoSQLMap.git","https://github.com/Karlheinzniebuhr/torshammer.git",
"https://github.com/kamorin/DHCPig.git","https://github.com/m4ll0k/Drup.git","https://github.com/Screetsec/Microsploit.git",
"https://github.com/m4ll0k/Infoga.git","https://www.github.com/Skull00/Gen2kr.git/","https://github.com/Ethical-H4CK3R/InstaBurst.git",
"https://github.com/roissy/l0l.git","https://github.com/hahwul/a2sv.git","https://github.com/websploit/websploit.git",
"https://github.com/joker25000/Dzjecter.git","https://github.com/UndeadSec/SocialFish.git","https://github.com/D4Vinci/One-Lin3r.git",
"https://github.com/D4Vinci/Cr3dOv3r.git","https://github.com/joker25000/Devploit.git","https://github.com/1N3/BruteX.git",
"https://github.com/lgandx/PCredz.git","https://github.com/stinkymonkeyph/FuckScrap.git","https://github.com/v3n0m-Scanner/V3n0M-Scanner.git",
"https://github.com/m4ll0k/WAScan.git","https://github.com/abaykan/53R3N17Y","https://github.com/leviathan-framework/leviathan.git",
"https://github.com/zigoo0/webpwn3r.git","https://github.com/k4m4/dymerge.git","https://github.com/jekyc/wig.git",
"https://github.com/fadinglr/Parat.git","https://github.com/r00t-3xp10it/netool-toolkit.git","https://github.com/Mebus/cupp.git",
# estensioni
"https://github.com/wifiphisher/extra-phishing-pages.git" # wifiphisher
    ]
    wget = [
"https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip","https://dl.packetstormsecurity.net/UNIX/scanners/witcxtool-v1.1.tar.gz",
"https://downloads.sourceforge.net/project/inguma/inguma/Inguma%200.1.0%20%28R1%29/inguma-0.1.1.tar.gz",
"https://github.com/angryip/ipscan/releases/download/3.5.2/ipscan_3.5.2_amd64.deb"
    ]
    for e in git_clone:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e 'git clone %s'"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto.\n")
    for e in wget:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e 'wget %s'"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto.\n")
    sys.stdout.write(20 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    # tools installer
    sys.stdout.write(" Installo Tools ")
    sys.stdout.flush()
    install = [
# manuali
"chmod +x TheFatRat/setup.sh && cd TheFatRat/ && ./setup.sh",
"cd secHub/ && echo -# Press ENTER 2 times && python installer.py && chmod +x /usr/bin/sechub",
"cd Crips/ && chmod +x install.sh && ./install.sh",
"cd ATSCAN/ && chmod +x install.sh && ./install.sh",
"cd Trity && python install.py",
"cd Sn1per/ && chmod +x install.sh && ./install.sh",
# automatici
"chmod +x torghost/install.sh && cd torghost/ && ./install.sh",
"cd KatanaFramework/ && sh dependencies && python install",
"unzip ngrok-*.zip && rm ngrok-*.zip && mv ngrok  && cp ngrok /usr/local/sbin/",
"chmod +x sAINT/configure.sh && cd sAINT/ && ./configure.sh",
"cd hakkuframework/ && ./install",
"cd EggShell && easy_install pycrypto",
"gcc xerxes/xerxes.c -o xerxes/xerxes",
"pip install -r operative-framework/requirements.txt",
"chmod +x zambie/Installer.sh && ./zambie/Installer.sh",
"cd ufonet/ && python setup.py install && chmod +x ufonet",
"cd shellsploit-framework/ && python setup.py -s install && cd ..",
"pip install -r tulpar/requirements",
"cd astroid/ && chmod +x astroid.sh setup.sh && ./setup.sh",
"cd simple-ducky/ && ./install.sh",
"cd a2sv/ && ./install",
"cd pentestly/ && rm REQUIREMENTS && ./install.sh",
"cd Kautilya && bundle install",
"cd l0l/ && make",
"cd zarp/ && pip install -r requirements.txt",
"cd car-hacking-tools/ && make install",
"cd instarecon/ && python setup.py install",
"cd NoSQLMap/ && python setup.py install",
"cd XSStrike/ && pip2 install -r requirements.txt",
"cd Microsploit/ && chmod +x Microsploit",
"cd DarkSploit/Install/ && pip2 install -r requirements.txt",
"cd Dzjecter/ && chmod +x installer.sh && ./installer.sh",
"cd Cr3dOv3r/ && pip3 install -r requirements.txt",
"cd Devploit/ && chmod +x install && ./install",
"dpkg -i ipscan_*_amd64.deb && rm ipscan_*_amd64.deb",
"cd V3n0M-Scanner/ && python3 setup.py install --user",
"cd 53R3N17Y/ && chmod +x serenity",
"cd leviathan/ && pip install -r requirements.txt",
"cd PasteZort/ && chmod +x encode.rb",
# witchxtool
"tar -xf witcxtool-v1.1.tar.gz && rm witcxtool-v1.1.tar.gz && mkdir witchxtool && mv ver1.1/ witchxtool/ && cpan Data::Validate::IP"
# wifiphisher extra phishing pages
"cd extra-phishing-pages/ && cp -r * /usr/local/lib/python2.7/dist-packages/wifiphisher-*-py2.7.egg/wifiphisher/data/phishing-pages/ ; sleep 3 ; cd .. ; rm -rf extra-phishing-pages/",
# inguma
"tar -xf inguma-*.tar.gz && rm inguma-*.tar.gz 'inguma-0.1.1.tar.gz?r=' wget-log",
# * chmod
"chmod +x Gen2kr/gen2kr BruteSploit/Brutesploit Brutal/Brutal.sh zirikatu/zirikatu.sh Evil-Droid/evil-droid ARCANUS/ARCANUS websploit/websploit ezsploit/ezsploit.sh airgeddon/airgeddon.sh wirespy/wirespy.sh D-TECT/d-tect.py BeeLogger/bee.py",
"chmod -R 775 InstaBurst/web"
    ]
    for e in install:
        try:
            os.system("xterm -T 'Fuck Society Installer' -e '%s'"%(e))
            time.sleep(.1)
        except (KeyboardInterrupt,EOFError):
            sys.exit("\n-# Interrotto.\n")
    sys.stdout.write(19 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    # fase finale
    sys.stdout.write(" Installo per Utilità ")
    sys.stdout.flush()
    os.system("xterm -T 'Fuck Society Installer' -e 'apt install wine32 playonlinux ftp python3-setuptools python3-dev netdiscover dsniff yum -y && easy_install3 pip && pip install wafw00f request pythonwhois && pip3 install pyasn1 tabulate impacket six termcolor colorama && dpkg --configure -a'")
    sys.stdout.write(13 * " " + "( %sOK%s )\n"%(bright_green,end))
    sys.stdout.flush()
    #
    os.chdir("../")
    os.system("touch /usr/local/sbin/fsociety && chmod +x /usr/local/sbin/fsociety && echo '#!/bin/bash' > /usr/local/sbin/fsociety && echo 'cd %s/ && python fsociety' >> /usr/local/sbin/fsociety && chmod +x fsociety"%(os.getcwd()))
    os.system("xterm -e 'mv installer.py bin/'")
    os.system("echo '!!! Non cancellare questo file !!!' > output/fsociety/completed") # Verifica installazione fsociety
    print("")
    print("-# Installazione completata")
    print("-# Digita %sfsociety%s ovunque nella shell oppure %s./fsociety%s dalla cartella"%(bright_green,end, bright_green,end))
    sys.exit("")

def connection_detector():
    try:
        compatible = ["KaliLinux"]
        get_sys = platform.linux_distribution()[0] + platform.system()
        if get_sys not in compatible:
            print("-# (%s-%s) Spiacente, programma non compatibile col tuo sistema"%(red,end))
            print("-# Sistemi supportati:\n - Kali Linux".format(bright_green,end))
            sys.exit()
        print("-# %sFuck Society Installer%s"%(bright_green,end))
        time.sleep(.2)
        sys.stdout.write("-# Verifico connessione internet ")
        sys.stdout.flush()
        requests.get('http://ip.42.pl/raw')
        sys.stdout.write("- %sOK%s"%(bright_green,end))
        sys.stdout.flush()
        print("\n")
        print("-# %sAttenzione%s:"%(bright_yellow,end))
        print("   Una volta eseguita l'installazione non rinominare o spostare la cartella")
        print("   di %sfsociety%s."%(bright_green,end))
        print("")
        return main()
    except requests.exceptions.ConnectionError:
        sys.stdout.write("- %sFail%s\n"%(red,end))
        sys.stdout.flush()
        sys.exit("-# Verifica la tua connessione e riprova\n")
    except KeyboardInterrupt:
        sys.exit("\n")

if __name__ == "__main__":
    os.system("clear")
    connection_detector()
