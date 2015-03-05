#!perl

use strict;
use warnings;

use FindBin;
use IPC::Cmd 'can_run';
use Getopt::Long;

my $debug   = 0;
my $install = 0;
my $apxs    = 'apxs2';
my @flags   = do { no warnings; qw[-a -c -Wl,-Wall -Wl,-lm]; };
my $my_lib  = 'mod_cookietrack.c';
my @inc;
my $lib;
my @link;

GetOptions(
    debug       => \$debug,
    "apxs=s"    => \$apxs,
    "flags=s@"  => \@flags,
    "lib=s"     => \$lib,
    "inc=s@"    => \@inc,
    "link=s@"   => \@link,
    install     => \$install,
) or die usage();

unless( can_run( $apxs ) ) {
    die "Could not find '$apxs' in your path.\n\n" .
        "On Ubuntu/Debian, try 'sudo apt-get install apache2-dev'\n\n";
}

### from apxs man page:
### * -Wl,-lX to link against X
### * -Wc,-DX to tell gcc to -D(efine) X
### * -I to include other dirs

my @cmd = ( $apxs, @flags );

### By default we don't install, but with this flag we do.
push @cmd, '-i' if $install;

### extra include dirs
push @cmd, map { "-I $_" } $FindBin::Bin, @inc;

### libraries to link against
push @cmd, map { "-Wl,-l$_" } @link;

### enable debug?
push @cmd, "-Wc,-DDEBUG" if $debug;

### a potential .c/.o file that holds the custom uid code
if( $lib ) {
    my $header = $lib;
    $header =~ s/\.[soc]$//;
    $header .= '.h';

    ### generate this header file manually, because #include
    ### does not support macro expansion.
    open my $fh, ">", "mod_cookietrack_external_uid.h" or die $!;
    print $fh "#include <$header>\n";
    close $fh;

    ### the header to include in the mod_cookietrack.c, in
    ### case we need the value
    push @cmd, "-Wc,-DLIBRARY=$header";

}

### our module
push @cmd, $my_lib;

### and include the lib in the command -- order matters
push @cmd, $lib if $lib;


warn "\n\nAbout to run:\n\t@cmd\n\n";

system( @cmd ) and die $?;

sub usage {
    my $me = $FindBin::Script;

    return qq[
  $me [--debug] [--lib=foo.c | --lib=foo.o] [--inc /some/dir,..] [--link some_lib]

    \n];
}

