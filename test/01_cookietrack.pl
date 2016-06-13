#!/usr/bin/perl

### XXX I don't know how to test the apache notes from perl

use strict;
use warnings;
use Test::More      'no_plan';
use HTTP::Date      qw[str2time];
use Getopt::Long;
use Data::Dumper;
use HTTP::Cookies;
use LWP::UserAgent;


my $Base        = "http://localhost:7000/";
my $Debug       = 0;
my $CookieLen   = '24,36'; # default length is 24 to 36 chars: $ip.$microtime
my $XFFSupport  = 1;
my $TestPattern = '.*'; # run any tests

### Maximum size of cookies - make sure we get at least that much data back
### for longer cookies. 140 is the default in mod_cookietrack.c. Change that,
### change this.
my $CookieMaxLen = 40;

GetOptions(
    'base=s'            => \$Base,
    'debug'             => \$Debug,
    'cookielength=s'    => \$CookieLen,
    'maxcookielength=s' => \$CookieMaxLen,
    'xff=i'             => \$XFFSupport,
    'tests=s'           => \$TestPattern,
);

### make sure we have a cookie the lenght of the default cookie
### something like 12345678901234456 for length 16
my $CValue      = join '', map { $_ % 10 }
                        1.. do { $CookieLen =~ /(\d+),/ ? $1 : $CookieLen };
my $CookieRe    = qr/^.{$CookieLen}$/;
my $CDomain     = '.example.com';
my $CAttr       = "; path=/; expires=Sat, 11-Jan-12 00:45:43 GMT; domain=$CDomain";
my $CRest       = "=" . $CValue . $CAttr;

### seconds in the future a standard cookie should be set to expire to
### correlate this to the httpd.conf, using 6 months currently.
my $Age     = 6 * 30 * 86400; # 6 months

### Expires/max-age value for when DNT is set
my $DNTExpires  = 'Fri, 01-Jan-38 00:00:00 GMT';
### Age is the date above, minus the current timestamp
my $DNTAge      = 2145916800 - time();

### When set  specificially
my $KName   = "uuid";
my $KCookie = $KName . $CRest;
my $KHeader = "X-MY-UUID";
my $KDNT    = "MY-DNT";

### When using the default
my $DName   = "Apache";
my $DCookie = $DName . $CRest;
my $DHeader = "X-UUID";

### When dealing with legacy mod_usertrack values
my $LValue  = '123.123.123.123.1234567890123456';   # $ip.$timestamp
my $LCookie = $DName .'='. $LValue . $CAttr;

### Browser UA constants
my $IE9     = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)';
my $IE10    = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)';

### https://github.com/jib/mod_cookietrack/issues/4
### Cookies that are too long cause buffer overflows on Centos
my $B4name   = $DName;
my $B4value  = 'rlW1qJyxVwc7VvO1VwbvMQHkBQLkLGt1LGxkAQVkMTWzBGNlBTH2AGWzMwAwZTVvsK0.Pnu9ut.bTXEMaZ95cwdnHr9g-RDy7dZmqV-rlW1qJyxVwc7VvO1VwbvMQHkBQLkLGt1LGxkAQVkMTWzBGNlBTH2AGWzMwAwZTVvsK0.Pnu9ut.bTXEMaZ95cwdnHr9g-RDy7dZmqV';
my $B4cookie = "_psqhvq=q89800n4op1rr9s7o227287n7q24157n01435568869; pK_F=vxsro85i98uqa043; pK_C=vxsro85joptcn5ce; frffvba=rlW1qJyxVwc7VvO1VwbvMQHkBQLkLGt1LGxkAQVkMTWzBGNlBTH2AGWzMwAwZTVvsK0.Pnu9ut.bTXEMaZ95cwdnHr9g-RDy7dZmqV; f_cref=%20f_ae%3Q1457967298476-Ercrng%7P1465743298476%3O%20op%3Q1%7P1458053698479%3O; f_frff=%20f_pp%3Qgehr%3O%20f_fd%3Q%3O; sfe.n=1457967298564; sfe.f=%7O%22i2%22%3N-2%2P%22i1%22%3N1%2P%22evq%22%3N%22qr07oq3-79144505-4s08-1s01-8054s%22%2P%22eh%22%3N%22uggc%3N%2S%2Sjjj.tbbtyr.pbz%2Shey%3Sd%3Quggc%253N%252S%252Sqri.kkkkkkkkkk.pbz%252Scnegare%252Sanfqnd%252SvsenzrQrzb%252SanfqndQrzb.rcy%26fn%3QQ%26fagm%3Q1%26hft%3QNSDwPATj64G_CfxJnZDqRgYmmLeJbJAZCj%22%2P%22e%22%3N%22jjj.tbbtyr.pbz%22%2P%22fg%22%3N%22uggc%3N%2S%2Sqri.kkkkkkkkkk.pbz%2Scnegare%2Sanfqnd%2SvsenzrQrzb%2SanfqndQrzb.rcy%22%2P%22gb%22%3N3%2P%22p%22%3N%22uggc%3N%2S%2Sqri.kkkkkkkkk.pbz%2Scnegare%2Sanfqnd%2SvsenzrQrzb%2SanfqndQrzb.rcy%22%2P%22ci%22%3N1%2P%22yp%22%3N%7O%22q0%22%3N%7O%22i%22%3N1%2P%22f%22%3Nsnyfr%7Q%7Q%2P%22pq%22%3N0%7Q; OVTvcFreireCBBY-212.100.237.224-443=650294026.20736.0000; qwnatbFrffvbaVq=no997q3773prs1o2399rq0ns4o8p58q6; __hgzn=86428557.1169378542.1435570010.1463066992.1463560681.56; __hgzp=86428557; __utmc=86428557; __utmz=86428557.1463560681.56.34.utmcsr=xxxxxxxxxxxxxxxx.co.uk|utmccn=(referral)|utmcmd=referral|utmcct=/; " . $DName .'='. $B4value . "; mod_auth_openidc_session=e2dbe9dc-caed-4e0f-9e63-114c0fee473b";

### Making sure the expiry is in the future
my $_ExpSub   = sub {
    my $key = shift or return;
    my $val = shift or return;
    my $rel = shift() ? 1 : 0;      # using max age, so time is relative?
    my $dnt = shift() ? 1 : 0;      # dnt expires, or dynamic one?

    my $t   = $val =~ /^\d+$/ ? $val : str2time( $val );

    ### how many days before/after we allow the returned timestamp to be
    my $delta   = 2 * 86400;

    ### for relative time (Max-Age), the base is 0, for absolute time
    ### (Expires), the base is now.
    my $base = $rel ? 0 : time();

    ### timestamp before and after that are reasonable windows.
    my $min = ($dnt ? $DNTAge   : $Age) + $base - $delta ;
    my $max = ($dnt ? $DNTAge   : $Age) + $base + $delta ;

    ### we set expiry +6m, so test for +5 months & 15 days, roughly
    cmp_ok( $t, '>', $min,      "    Time $t > min time $min" );
    cmp_ok( $t, '<', $max,      "    Time $t < max time $max" );
};

my $ExpSub      = sub { $_ExpSub->( @_, 0, 0 ) };  # Absolute, DNT is off
my $DNTExpSub   = sub { $_ExpSub->( @_, 0, 1 ) };  # Absolute, DNT is on
my $AgeSub      = sub { $_ExpSub->( @_, 1, 0 ) };  # Relative, DNT is off
my $DNTAgeSub   = sub { $_ExpSub->( @_, 1, 1 ) };  # Relative, DNT is on

### if under no circumstance this header/value should be set,
### we can just use this struct:
            # COOKIE NO     YES
my $AllUnset = [ [ undef, undef ],  # DNT OFF
                 [ undef, undef ],  # DNT ON
               ];

### if we're testing expiry, use this struct:
my $AllExpires  = [ [ $ExpSub,      $ExpSub     ],
                    [ $DNTExpSub,   $DNTExpSub  ],
                  ];

### if testing max-age, use this struct:
my $AllMaxAge   = [ [ $AgeSub,          $AgeSub     ],
                    [ $DNTAgeSub,       $DNTAgeSub  ],
                  ];


my %Map     = (
    ### module is not turned on
    none    => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
            "Set-Cookie"    => $AllUnset,
        },
    },
    ### module turned on with all defaults
    basic   => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### This will set expires in the cookie
    basic_expires   => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllExpires,
            domain          => $AllUnset,
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### This will set the domain in the cookie
    basic_domain   => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => [ [ $CDomain, $CDomain ],
                                 [ $CDomain, $CDomain ],
                               ],
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### This will set the response header as well as the cookie
    basic_header   => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => [ [ $CookieRe, $CValue ],
                                 [ "DNT",    "DNT"  ],
                               ],
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### This will not set DNT cookies, but actual ones
    basic_no_dnt_comply => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ $CookieRe, $CValue ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### This will not set cookies at all if DNT is present
    basic_no_dnt_cookie => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ undef,    undef   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### Here we change the value of the keys, like cookies, headers
    custom_name => {
        use_cookie          => $KCookie,
        headers => {
            $DHeader        => $AllUnset,
            $KHeader        => $AllUnset,
        },
        cookies => {
            $DName          => $AllUnset,
            $KName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### XXX storable's dclone() can't do regexes, so we have
    ### to copy the data for a minor different test :(
    ### Here we change the value of the returned header
    custom_header   => {
        use_cookie          => $KCookie,
        headers => {
            $DHeader        => $AllUnset,
            $KHeader        => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
        },
        cookies => {
            $DName          => $AllUnset,
            $KName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    custom_dnt_cookie => {
        use_cookie          => $KCookie,
        headers => {
            $DHeader        => $AllUnset,
            $KHeader        => $AllUnset,
        },
        cookies => {
            $DName          => $AllUnset,
            $KName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ $KDNT,    $KDNT   ], # DNT ON
                               ],
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### module turned on with all defaults, sending a legacy cookie
    legacy => {
        use_cookie          => $LCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $LValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    issue4 => {
        use_cookie          => $B4cookie,
        headers             => {},
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, substr($B4Value, 0, $CookieMaxLen) ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### test alternate cookie styles - testing code mostly copied
    ### from basic_expires, but adding domain tests.
    basic_expires_cookie => {
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            "max-age"       => $AllMaxAge,
            version         => $AllUnset,
            domain          => [ [ $CDomain, $CDomain ],
                                 [ $CDomain, $CDomain ],
                               ],
        },
    },
    basic_expires_cookie2 => {
        set_cookie          => 'Set-Cookie2',
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            "max-age"       => $AllMaxAge,
            domain          => [ [ $CDomain, $CDomain ],
                                 [ $CDomain, $CDomain ],
                               ],
            version         => [ [ 1, 1 ],      # only this style sets version=1
                                 [ 1, 1 ],
                               ],
        },
    },
    ### test non 2xx response codes -- all same as /basic, but
    ### with different response codes. Endpoint must be declared
    ### in httpd.conf though for test to work.
    301 => {
        use_cookie          => $DCookie,
        response_code       => 301,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    302 => {
        use_cookie          => $DCookie,
        response_code       => 302,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    404 => {
        use_cookie          => $DCookie,
        response_code       => 404,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    500 => {
        use_cookie          => $DCookie,
        response_code       => 500,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ "DNT",    "DNT"   ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### Test cookies that are DNT exempt
    ### DNT exempt cookies, when the cookie is SENT, do NOT get modified and
    ### therefor not returned to the client. That's why the 'YES' column is undef
    dnt_exempt  => {
        use_cookie          => $DName .'=OPTOUT'. $CAttr,
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, undef ], # DNT OFF
                                 [ "DNT",     undef ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### Test cookies that are DNT exempt
    ### DNT exempt cookies, when the cookie is SENT, do NOT get modified and
    ### therefor not returned to the client. That's why the 'YES' column is undef
    'dnt_exempt?notme'  => {
        use_cookie          => $DName .'=NOTME'. $CAttr,
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, undef ], # DNT OFF
                                 [ "DNT",     undef ], # DNT ON
                               ],
            $KName          => $AllUnset,
            expires         => $AllUnset,
            domain          => $AllUnset,
        },
    },
    ### Test browsers that are DNT exempt
    ### We ignore DNT for msie 10
    'dnt_exempt_browser/msie10' => {
        send_headers => [ 'User-Agent' => $IE10 ],
        cookies      => {       # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $CValue ], # DNT OFF
                                 [ $CookieRe, $CValue ], # DNT ON
                               ],
            expires         => [ [ $ExpSub, $ExpSub ],
                                 [ $ExpSub, $ExpSub ],
                               ],
        }
    },
    ### Test browsers that are DNT exempt
    ### But it's not ignored for MSIE 9.0
    'dnt_exempt_browser/msie9' => {
        send_headers => [ 'User-Agent' => $IE9 ],
        cookies      => {       # COOKIE NO     YES
            $DName           => [ [ $CookieRe, $CValue ], # DNT OFF
                                  [ "DNT",     "DNT"   ], # DNT ON
                                ],
            expires          => $AllExpires,
        }
    }
);


if( $XFFSupport ) {
    ### Test X-Forwarded-For support for remote IP
    $Map{xff} = {
        send_headers        => [ 'X-Forwarded-For' => '1.1.1.1' ],
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ qr/^1.1.1.1/, $CValue ], # DNT OFF
                                 [ "DNT",        "DNT"   ], # DNT ON
                               ],
        }
    };

    ### Test X-Forwarded-For support for multiple remote IPs
    $Map{'xff?multiple'} = {
        send_headers        => [ 'X-Forwarded-For' => '1.1.1.1, 2.2.2.2' ],
        use_cookie          => $DCookie,
        headers => {
            $DHeader        => $AllUnset,
        },
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ qr/^2.2.2.2/, $CValue ], # DNT OFF
                                 [ "DNT",        "DNT"   ], # DNT ON
                               ],
        }
    };
}

{   my $test_match = qr/$TestPattern/;

    for my $endpoint ( sort keys %Map ) {

        unless( $endpoint =~ $test_match ) {
            diag("Endpoint $endpoint does not match $TestPattern - skipping");
            next;
        }

        ### Don't send DNT, then set to 0, then set to 1
        for my $dnt_set ( undef,  0, 1 ) {
            for my $send_cookie ( 0, 1 ) {
                _do_test( $endpoint, $dnt_set, $send_cookie );
            }
        }
    }
}

sub _do_test {
    my $endpoint    = shift;
    my $dnt_set     = shift;
    my $send_cookie = shift;
    my $url             = "$Base/$endpoint";
    my $send_headers    = $Map{ $endpoint }->{ send_headers }   || [];
    my $header_tests    = $Map{ $endpoint }->{ headers }        || {};
    my $cookie_tests    = $Map{ $endpoint }->{ cookies }        || {};
    my $set_cookie      = $Map{ $endpoint }->{ set_cookie }     || 'Set-Cookie';
    my $rv              = $Map{ $endpoint }->{ response_code }  || 204;
    my $ua              = LWP::UserAgent->new();

    ### we are testing 301/302, do not follow the redirect, but inspect the
    ### result instead! (default is 7, so definitely turn off!)
    $ua->max_redirect(0);

    ### As we're using undef, 0 and 1 for DNT, we have to have a pretty print
    ### version of DNT, or we get lots of warnings:
    my $pp_dnt_set = defined $dnt_set ? $dnt_set : '<undef>';

    ### what cookie to send; by default, use the vanilla one
    my $cookie          = $Map{ $endpoint }->{ use_cookie } || $DCookie;

    diag "\n\n *** New Request ***\n\t DNT: $pp_dnt_set\n\t Cookie: $send_cookie\n\n"
        if $Debug;

    ### build the request
    my @req = ($url, @$send_headers);
    push @req, (Cookie => $cookie  ) if $send_cookie;
    ### doesn't send it if set to undef, but send explicitly for 0 and 1
    if( defined $dnt_set ) {
        push @req, (DNT => $dnt_set );
    }

    ### Diagnostic header so we can correlate requests:
    push @req, ( "X-Test-Flags" => "url=$endpoint, dnt=$pp_dnt_set, cookie=$send_cookie" );

    diag "Sending: @req" if $Debug;

    my $res     = $ua->get( @req );
    diag $res->as_string if $Debug;

    ok( $res,                   "Got /$endpoint - dnt:$pp_dnt_set cookie:$send_cookie" );
    is( $res->code, $rv,        "   HTTP Response = $rv" );

     ####################
     ### header tests
     ####################
     while( my( $key, $aref ) = each %$header_tests ) {
         ### If we have dnt set to <undef>, we want it to test the same values as DNT=0
         my $test = $aref->[ $dnt_set || 0 ]->[ $send_cookie ];
         my $val  = $res->header( $key );
         my $diag = "    Response header $key matches ". ( $test || '<undef>' );

         UNIVERSAL::isa( $test, "Regexp" )
             ? like( $val, $test, $diag )
             : is(   $val, $test, $diag );
     }

     ####################
     ### cookie tests
     ####################

     my %cookie = _simple_cookie_parse( $res->header( $set_cookie ) );

     while( my( $key, $aref ) = each %$cookie_tests ) {
         ### If we have dnt set to <undef>, we want it to test the same values as DNT=0
         my $test   = $aref->[ $dnt_set || 0 ]->[ $send_cookie ];
         my $val    = $cookie{ $key };
         my $pp_val = $val || '<undef>';
         my $diag   = "    Response cookie key $key ($pp_val) matches ".
                        ( $test || '<undef>' );

         UNIVERSAL::isa( $test, "Regexp" ) ? like( $val, $test, $diag )          :
         UNIVERSAL::isa( $test, "CODE"   ) ? $test->( $key, $val )               :
         is( $val, $test, $diag );
     }
}

### there are more sophisticated parsers needed for difference
### cookie modes, but since we know the exact format, it's easier
sub _simple_cookie_parse {
    my $str = shift or return;
    my %rv  = ();

    diag "Returned cookie: $str" if $Debug;

    for my $kv ( split( /;\s*/, $str ) ) {
        my($k,$v) = split( /=/, $kv );

        $rv{$k} = $v;
    }

    return %rv;
}

