#!/bin/sh
BIN=apache2ctl

### If you're on an older OS, you may not have apache2ctl, so use a
### fallback.
if [ ! -x apache2ctl ]; then
  BIN=apachectl
fi

### What config file do we load? subtle differences per OS :(
if[ `grep -i ubuntu /etc/issue` -eq 0 ]; then
    CONF='ubuntu'
elif [ `grep -i centos /etc/issue` -eq 0 ]; then
    CONF='centos'
else
    echo "Unkonwn OS - please update this script for better detection"
    exit 1;
fi

$BIN -d `pwd` -f `pwd`/test/httpd.conf.$CONF -X -k start
