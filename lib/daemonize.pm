
# the serverM intrusion detection and protection system
# (one of) main library files
# D. Scholefield 2004, 2005, 2006 (www.port80.com)
# Version 2.80 (Linux/Mac OS X/BSD)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

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

    main::add_to_log("status", "entering daemon mode (pid = $$)");
    ## Reopen stderr, stdout, stdin to /dev/null
    open(STDIN,  "+>/dev/null");
    open(STDOUT, "+>&STDIN");
    open(STDERR, "+>&STDIN");

    return $sess_id;
}

1;
