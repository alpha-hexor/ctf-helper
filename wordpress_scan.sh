#!/bin/bash


echo  '[*]Enter the url to scan: ';read url

file="wordpress_scan.txt"

#wordpress scan

wpscan --url $url --enumerate u | tee $file
