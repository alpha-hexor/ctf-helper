#Creating directories

mkdir ~/exploit
if [ ! -d "~/ctf" ]
then
	mkdir ~/ctf
	mkdir ~/ctf/try_hack_me
	mkdir ~/ctf/htb
fi

echo '[*]Installing Windows Exploit Suggester'
git clone https://github.com/bitsadmin/wesng.git

mv wesng ~/exploit/

echo "[*]Installing Python3-xlrd"
sudo apt-get install python3-xlrd

echo '[*]Installing Linux Exploit Suggester'
curl https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -o ~/exploit/linux_exploit_suggester.pl


echo "[*]Checking files"

if [ ! -d "/usr/share/wordlists" ]
then
	echo "[*]Making directory"
	sudo mkdir /usr/share/wordlists
fi

PASSWORD_FILE = /usr/share/wordlists/rockyou.txt

if [ ! -f "$PASSWORD_FILE" ]; then

    wget https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz
    sudo mv rockyou.txt.gz /usr/sahre/wordlists/
	sudo gunzip /usr/share/wordlists/rockyou.txt.gz

fi

WORDLIST_FILE = /usr/share/wordlists/dirb/common.txt

if [ ! -f "$WORDLIST_FILE" ]; then
	sudo mkdir /usr/sharre/wordlists/dirb
	curl https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt > /usr/share/wordlists/drb/common.txt
fi



echo "[*]Checking for ffuf"


if ! which ffuf > /dev/null; then
   echo "[*]Installing ffuf"
   sudo apt-get install ffuf
   
fi

if ! which dig > /dev/null; then
   echo "[*]Installing ffuf"
   sudo apt-get install dnsutils
   
fi

echo "[*]Changing permission"
chmod +x host.sh
chmod +x wordpress_scan.sh
chmod +x wp_brute.sh

chmod +x tool.py
