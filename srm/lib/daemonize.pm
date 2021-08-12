

# DAEMONIZE provides a simple 'init' routine which converts a running perl script
# into a unix (POSIX) daemon. This is a achieved by forking a child process, and
# killing the parent. the child process is then dettached from the terminal, and
# forked again. The grandchild is the DAEMON - all file descriptors are closed, and
# the STD triumverate are redirected to /dev/null

# this package is based on CPAN Proc::Daemon

# usage: DAEMONIZE::init();
# $SIG{HUP}=\&catch_hup;
# $SIG{TERM}=\&catch_term;
# our $isHupped=0;
# our $isTermed=0;



# sub catch_hup
#{
#       our $isHupped=1;
#}

# sub catch_term
#{
#        our $isTermed=1;
#}


package DAEMONIZE;

use strict;
use POSIX;

##      Fork(): Try to fork if at all possible.  Function will croak
##      if unable to fork.
##
sub Fork {
    my($pid);
    FORK: {
        if (defined($pid = fork)) {
            return $pid;
        } elsif ($! =~ /No more process/) {
            sleep 5;
            redo FORK;
        } else {
            die "Can't fork: $!";
        }
    }
}

sub Init {

    my($pid, $sess_id, $i);

    ## Fork and exit parent
    if ($pid = Fork) { exit 0; }

    ## Detach ourselves from the terminal
    
    
    die "Cannot detach from controlling terminal"
        unless $sess_id = POSIX::setsid();

    ## Prevent possibility of acquiring a controling terminal
    
        if ($pid = Fork) { exit 0; }
    
	## Change working directory
    chdir "/";

    ## Clear file creation mask
    ## umask 0;

    ## Close open file descriptors
    ## foreach $i (0 .. OpenMax) { POSIX::close($i); }

	print "(my PID is $$) ...\n\n";
    main::add_to_log("status", "entering daemon mode (pid = $$)");
    ## Reopen stderr, stdout, stdin to /dev/null
    open(STDIN,  "+>/dev/null");
    open(STDOUT, "+>&STDIN");
    open(STDERR, "+>&STDIN");

    return $sess_id;
}

1;
