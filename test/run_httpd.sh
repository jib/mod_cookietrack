#!/bin/sh
set -x
BIN=apache2ctl

### If you're on an older OS, you may not have apache2ctl, so use a
### fallback.
if [ ! -x apache2ctl ]; then
  BIN=apachectl
fi

RELEASE=`cat /etc/issue`
case $RELEASE in
  *CentOS*) CONF=centos;;
  *Ubuntu*) CONF=ubuntu;;
  *) echo "Release not supported - update this script please!" && exit 1;;
esac

$BIN -d `pwd` -f `pwd`/test/conf/httpd.conf.$CONF -X -k start
