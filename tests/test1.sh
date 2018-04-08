#!/bin/bash
echo `pwd`
#cd ../
python fakedns.py -c dns.conf.example &
nslookup reddit.com 127.0.0.1
