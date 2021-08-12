
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

# remote logging package for sending (possibly encrypted) UDP messages
# containing serverM log entries

# version 0.9
# Author: D Scholefield. 2006

use strict;

package rlog;
use IO::Socket::INET;
use Crypt::CBC;

my $cipher;

sub init {
	my $key = shift;

	$cipher=Crypt::CBC->new(-key => "$key", -cipher => 'Blowfish');
	
}

sub send {
	
	my ($ip, $port, $key, $msg) = @_;
	# note that $key is required, but may be an empty string
	
	$msg = $cipher->encrypt($msg) if ($key ne '');
	
	my $MySocket=new IO::Socket::INET->new(PeerPort=>$port,
        Proto=>'udp',
	    PeerAddr=>$ip);
	
	$MySocket->send($msg);
	# UDP is 'fire and forget' so that's it!
}

1;

