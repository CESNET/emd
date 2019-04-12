#!/bin/bash

set -e

mkdir -p /tmp/resign-rr

pidfile=/tmp/resign-rr/pidfile
if [ -f "$pidfile" ] && kill -0 `cat $pidfile` 2>/dev/null; then
    echo still running
    exit 1
fi  
echo $$ > $pidfile

trap "rm $pidfile" EXIT

for CONF in /home/mdx/resign/conf/*.conf
do
  . $CONF

  # Mame nastaveny set -e takze pri kazdy chybe to zhebne. Defaulty
  # jsou tak aby se metadata stahla.
  cd /tmp/resign-rr
  BEFORE=`(stat -c "%y" $SRC 2>/dev/null || echo '2000-01-01 00:00:01.000000000 +0100')`
  wget -q -N $SRC_CHANGED
  AFTER=`(stat -c "%y" $SRC 2>/dev/null || echo '2020-01-01 00:00:01.000000000 +0100')`

  cd /home/mdx/resign/out
  if [ "$BEFORE" != "$AFTER" ] || [ ! -s $MD_SIGNED ]
  then
    wget $SRC_MD -q -O $MD_UNSIGNED

    /usr/bin/java -jar /opt/signer/XmlSigner.jar -cfg /etc/signer/signer.cfg -i $MD_UNSIGNED -o $MD_SIGNED 2>/dev/null
  else
    true
  fi
done
