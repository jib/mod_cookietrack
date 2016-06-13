#!/bin/sh
BIN=apache2ctl

### If you're on an older OS, you may not have apache2ctl, so use a
### fallback.
if [ ! -x apache2ctl ]; then
  BIN=apachectl
fi

$BIN -d `pwd` -f `pwd`/test/httpd.conf -X -k start
