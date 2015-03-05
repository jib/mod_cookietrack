mod_cookietrack
===============

A vastly improved version of mod_usertrack, supporting DNT, rolling expires,
redirects and much much more.

Building
--------

Make sure you have apxs2 and perl installed, which on Ubuntu
you can get by running:

```
  $ sudo apt-get install apache2-dev perl
```

From the checkout directory run:

```
  $ sudo perl build.pl --install
```

This will build, install & enable the module on your system


Configuration
-------------

See the file 'DOCUMENTATION' in the same directory as this
README for all the extra features this module has compared to
mod_usertrack, as well as documentation on the configuration
directives supported.


Custom UID generation
---------------------

Create a C file or library that has a 'gen_uid' function with
the following prototype:

```
  void gen_uid( char *uid, char *timestamp, char *ip );
```

Where 'timestamp' is a 16 character microtime, 'ip' is the
remote IP address and 'uid' is a char pointer for you to store
the UID to use for this request.

And then, build the module like this (any gcc linking target
is acceptable):

```
  $ sudo perl build.pl --inc /where/my_uid/lives --lib my_uid.c
```

Testing
-------

*** Note: for this will you will need Apache, NodeJS
*** and Perl installed.

First, start the backend node based server. It serves
as an endpoint and shows you the received url & headers
for every call:

```
  $ test/run_backend.sh
```

Next, start a custom Apache server. This will have all
the modules needed and the endpoints for testing:

```
  $ sudo test/run_httpd.sh
```

Then, run the test suite:

```
  $ perl test/01_cookietrack.pl
```

Run it as follows to enable diagnostic/debug output:

```
  $ perl test/01_cookietrack.pl --debug
```

Note that if you're using a custom library for generating
the UID, be sure to pass the length of the expected cookie
as the second argument. So, if your library generates UIDs
of 12-16 characters, use:

```
  $ perl test/01_cookietrack.pl --cookielength 12,16
```

There will be an error log available, and that will be
especially useful if you built the library with --debug:

```
  $ tail -F test/error.log
```

Building your own package
-------------------------

Make sure you have **dpkg-dev**, **cdbs** and **debhelper** installed, which on Ubuntu you can get by running:

```
$ sudo apt-get install dpkg-dev cdbs debhelper
```

Then build the package by first compiling the module, then running buildpackage:

```
$ perl build.pl
$ dpkg-buildpackage -d -b
```
