#!/bin/sh
apache2ctl -d `pwd` -f `pwd`/test/httpd.conf -X -k start
