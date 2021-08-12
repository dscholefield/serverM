
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


package tie_control;

use strict;
use DB_File;


# the routine returns a 2-element list with the $db connection
# as the first element (undefined if an error occurred) and
# the second element a return code
# 0 = everything ok, file was present
# 1 = couldn't open file, created one ok
# 2 - couldn't open file, database not present
# 3 - couldn't open file, unknown error

# note - %checksum_db is a global hash declared in the watcher service

sub create_tie
{
	my $location = shift;
	
	 eval {tie(%main::checksum_db, "DB_File", $location);};
	 if ($@)
		{
		die "Can't create tie ($@)\n";
		
		return 0;
		}
		else
		{
			print "checksum tie created\n";
			
			return 1;
		}
}

sub destroy_tie
{
	untie(%main::checksum_db);
}


sub add_checksum
{
	my ($server, $file, $content, $acl) = @_;
	my $insert_key = $server.'^'.$file;
	my $insert_value = $content.'^'.$acl;
	

	eval{$main::checksum_db{$insert_key} = $insert_value;};
	if ($@)
	{
		return "Error occured during checksum insert ($@)";
	}
	else
	{
		print "Checksum $content, acls $acl added for file $file\n";
		return "ok";
	}
}

sub delete_checksum
{
	my ($db, $server, $file) = @_;
	my $insert_key = $server.'^'.$file;
	
	eval{delete $main::checksum_db{$insert_key};};
	if ($@)
	{
		return "Error occured during checksum delete ($@)";
	}
	else
	{
		return "ok";
	}
}


	
1;
