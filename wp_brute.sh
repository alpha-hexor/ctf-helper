#!/bin/bash

echo '[*]Enter the url: ';read url
echo '[*]Enter username or username-list(with full path): ';read username
echo '[*]Do you want to use rockyou.txt as password-list(Y/N): ';read choice

str1='Y'

if [ "$choice" = "$str1" ]
then
	echo '[+]Using rockyou.txt as password file'
	pass_file=$(locate rockyou.txt)
else
	echo '[*]Enter full password file path: ';read pass_file
fi


#starting Bruteforcing

file="wp_brute.txt"

wpscan --url $url --passwords $pass_file --usernames $username | tee $file

