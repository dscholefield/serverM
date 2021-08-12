
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

use strict;
use Time::Local;

package toolkit;
		
sub execute_alarm
{
	# executes whatever command is provided
	# and returns the result to the caller
	# as a list
	my $cmd = shift;
	my $name = shift;
	
	my $nowait=0;
	my $old_command = $cmd;
	
	if ($cmd =~ /^\s*nowait\:/)
	{
		# by pre-pending a nowait: starter, it tells the system to execute
		# the command in a forked pipe
		$nowait=1;
		$cmd =~ s/^\s*nowait\:\s*//;
	}
	
	my ($txt, $hr, $min, $sec) = split(/:/, convert_timestamp());
	my ($dnm, $dn, $mo, $yr) = split(/ /, $txt);
	
	my $ssm = seconds_since_midnight();
	my ($stxt, $shr, $smin, $ssec) = split(/:/, convert_timestamp_in($ssm));
	
	my $squashed = $txt.$hr.$min.$sec;
	$squashed =~ s/ //g;
	
	$cmd =~ s/\%rn/$name/g;
	$cmd =~ s/\%ss/$sec/g;
	$cmd =~ s/\%smd/$ssec/g;
	$cmd =~ s/\%mn/$min/g;
	$cmd =~ s/\%smn/$smin/g;
	$cmd =~ s/\%hr/$hr/g;
	$cmd =~ s/\%shr/$shr/g;
	$cmd =~ s/\%df/$squashed/g;
	
	$cmd =~ s/\%dnm/$dnm/g;
	$cmd =~ s/\%dn/$dn/g;
	$cmd =~ s/\%mo/$mo/g;
	$cmd =~ s/\%yr/$yr/g;
	$cmd =~ s/\%cc/$main::check_cycle_count/g;
	$cmd =~ s/\%sv/$main::machine/g;
	
	
	$cmd =~ s/\%dt/$txt $hr:$min:$sec/g;
	
	my @results=();
	if ($nowait)
	{
		my $child_pid;
		if (!defined($child_pid = fork()))
		{
			push @results, "could not fork process for execute in rule $name";
		}
		else
		{
			if (!$child_pid)
			{
				# we're in the forked child so execute
				`$cmd`;
				exit;
			}
		}
	}
	else
	{
		@results = `$cmd`;
	}
	push @results, "encoded command: $old_command";
	push @results, "expanded command: $cmd";
	return @results;
}

sub convert_timestamp
{
   	my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime();
	$year+=1900;
	my $monName = (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$mon];
	my $dayName = (qw(Sun Mon Tue Wed Thu Fri Sat))[$wday];
	
	if ($sec<10) {$sec="0$sec";}
	if ($min<10) {$min="0$min";}
	if ($hour<10) {$hour="0$hour";}
	
	return "$dayName $mday $monName $year : $hour:$min:$sec";

}

sub convert_timestamp_in
{
	my $tm = shift;
   	my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($tm);
	$year+=1900;
	my $monName = (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$mon];
	my $dayName = (qw(Sun Mon Tue Wed Thu Fri Sat))[$wday];
	
	if ($sec<10) {$sec="0$sec";}
	if ($min<10) {$min="0$min";}
	if ($hour<10) {$hour="0$hour";}
	
	return "$dayName $mday $monName $year : $hour:$min:$sec";

}


sub lastMidnight
{
	
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
	# ok, let's get the first second of today
	$sec = 0; $min = 0; $hour = 0; # that's the previous midnight!
	my $midnight = Time::Local::timegm($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
	
	return $midnight;
}

sub seconds_since_midnight
{
	my $lm = lastMidnight();
	my $ssm = time() - $lm;
	
	return $ssm;
}

1;
