# Install hostname in /etc/hosts
echo "Enter the ip: " ;read ADDRESS
echo "Enter the host: "; read HOSTNAME
if ! [ "$ADDRESS" = "$HOSTNAME" ]; then
	if ! grep -E "$ADDRESS\s+$HOSTNAME" /etc/hosts 2>&1 >/dev/null; then
		echo "installing $HOSTNAME in /etc/hosts"
		hosts_line=`echo -e "# init-machine.sh - $NAME\n$ADDRESS\t$HOSTNAME"`
		sudo sh -c "cat - >>/etc/hosts"<<END
#CUSTOM ADDRESS - $NAME
$ADDRESS	$HOSTNAME
END
	else
		echo "machine already added to /etc/hosts"
	fi
else
	echo "no hostname provided; not adding to /etc/hosts"
    
fi
