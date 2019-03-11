#!/bin/bash

MD=`mktemp '/tmp/expired-certs-XXXXX'`
wget -q https://metadata.eduid.cz/entities/eduid -O $MD && /home/mdx/emd2/bin/expired-certs.pl $MD
rm $MD
