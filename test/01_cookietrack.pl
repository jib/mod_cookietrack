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

GetOptions(
    'base=s'            => \$Base,
    'debug'             => \$Debug,
    'cookielength=s'    => \$CookieLen,
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

my $BName   = $DName;
my $BValue  = 'eyJ1dWlkIjp7IiB1IjoiZDUxODYxYTg1YTkxNDIxZGJmOTAyOGU2NTJmZjNjMGIifX0.Cah9hg.oGKRZnM95pjqaUe9t-EQl7qMzdI';
my $BCookie = "__cfduid=d89800a4bc1ee9f7b227287a7d24157a01435568869; cX_S=ikfeb85v98hdn043; cX_P=ikfeb85wbcgpa5pr; session=eyJ1dWlkIjp7IiB1IjoiZDUxODYxYTg1YTkxNDIxZGJmOTAyOGU2NTJmZjNjMGIifX0.Cah9hg.oGKRZnM95pjqaUe9t-EQl7qMzdI; s_pers=%20s_nr%3D1457967298476-Repeat%7C1465743298476%3B%20bc%3D1%7C1458053698479%3B; s_sess=%20s_cc%3Dtrue%3B%20s_sq%3D%3B; fsr.a=1457967298564; fsr.s=%7B%22v2%22%3A-2%2C%22v1%22%3A1%2C%22rid%22%3A%22de07bd3-79144505-4f08-1f01-8054f%22%2C%22ru%22%3A%22http%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttp%253A%252F%252Fdev.dianomi.com%252Fpartner%252Fnasdaq%252FiframeDemo%252FnasdaqDemo.epl%26sa%3DD%26sntz%3D1%26usg%3DAFQjCNGw64T_PskWaMQdEtLzzYrWoWNMPw%22%2C%22r%22%3A%22www.google.com%22%2C%22st%22%3A%22http%3A%2F%2Fdev.dianomi.com%2Fpartner%2Fnasdaq%2FiframeDemo%2FnasdaqDemo.epl%22%2C%22to%22%3A3%2C%22c%22%3A%22http%3A%2F%2Fdev.dianomi.com%2Fpartner%2Fnasdaq%2FiframeDemo%2FnasdaqDemo.epl%22%2C%22pv%22%3A1%2C%22lc%22%3A%7B%22d0%22%3A%7B%22v%22%3A1%2C%22s%22%3Afalse%7D%7D%2C%22cd%22%3A0%7D; BIGipServerPOOL-212.100.237.224-443=650294026.20736.0000; djangoSessionId=ab997d3773cef1b2399ed0af4b8c58d6; __utma=86428557.1169378542.1435570010.1463066992.1463560681.56; __utmc=86428557; __utmz=86428557.1463560681.56.34.utmcsr=dianomioffers.co.uk|utmccn=(referral)|utmcmd=referral|utmcct=/; " . $DName .'='. $BValue . "; mod_auth_openidc_session=e2dbe9dc-caed-4e0f-9e63-114c0fee473b";

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
    bug => {
        use_cookie          => $BCookie,
        headers             => {},
        cookies => {        # COOKIE NO     YES
            $DName          => [ [ $CookieRe, $BValue ], # DNT OFF
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

