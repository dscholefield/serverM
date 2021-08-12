
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

package htmltoolkit;

use parse_rules;

sub get_log_stats {
	
	my $log_path = shift;
	my $line_limit = shift;
	
	my %results = ();
	my @all_lines = ();
	my @lines = ();
	my @errors = ();
	my @info = ();
	my @heartbeat = ();
	
	my $has_errors;
	
	$results{'error_message'}="can't find file";
	$results{'first_entry'} = "unknown";
	$results{'last_entry'} = "unknown";
	$results{'last_startup_time'} = "unknown";
	$results{'last_pause_time'} = "unknown";
	$results{'last_stop_time'} = "unknown";
	$results{'last_cont_time'} = "unknown";
	$results{'last_alarm_time'} = "unknown";
	$results{'last_error_time'} = "unknown";
	$results{'state'} = "unknown";
	$results{'last_check_cycle'}=0;
	
	$results{'has_errors'} = 0;
	
	my @alarms_since_restart= ();
	my @alarms_in24hours = ();
	
	my @errors_since_restart=();
	
	$results{'server_name'}="unkown";
	$results{'server_ip'}="unkown";
	
	my $success = open(InFile, "<$log_path/log.txt");
	return \%results if (!$success);
	
	$results{'error_message'}="";
	
	while(my $line = <InFile>)
	{
		push @all_lines, $line;
		push @lines, $line;
		shift @lines if ($#lines >= $line_limit);
		
		$line =~ m/^(.* : \d{2}:\d{2}:\d{2}) \((\d+)\) \[(\S+)\] (.*)/;
		my $this_time = $1;
		my $check_cycle = $2;
		my $this_type = $3;
		my $msg = $4;
		
		$results{'last_entry'} = $this_time;
		$results{'last_check_cycle'}=$check_cycle;
		
		$results{'first_entry'} = $this_time if ($results{'first_entry'} eq "unknown");
		
		if ($this_type =~ /Error/i)
		{
			push @errors, $line;
			push @errors_since_restart, $line;
			$results{'last_error_time'} = $this_time;
			$results{'has_errors'} = 1 if ($msg =~ /error in rules file\(s\)/);
		}
		
		if (($this_type =~ /Info/i) || ($this_type =~ /Status/i))
		{
			if (($msg =~ /^rules file parsed OK/) && ($results{'has_errors'}))
			{
				$results{'has_errors'} = 0;
			}
			if ($msg =~ /serverM system is starting/)
			{
				$results{'last_startup_time'} = $this_time;
				@alarms_since_restart = ();
				@errors_since_restart = ();
				$results{'state'} = "running";
			}
			if ($msg =~ /serverM system paused/)
			{
				$results{'last_pause_time'} = $this_time;
				$results{'state'} = "paused";
			}
			if ($msg =~ /serverM system continuing/)
			{
				$results{'last_cont_time'} = $this_time;
				$results{'state'}="running";
			}
			if ($msg =~ /serverM system has stopped/)
			{
				$results{'last_stop_time'} = $this_time;
				$results{'state'} = "stopped";
			}
		}
		
		if ($this_type =~ /Alarm/i)
			{
				$results{'last_alarm_time'} = $this_time;
				push @alarms, $line ;
				push @alarms_since_restart, $line;
			}
			
		
	}
	
	
	
	$results{'alarms_since_restart'} = \@alarms_since_restart;
	$results{'errors_since_restart'} = \@errors_since_restart;
	$results{'errors'} = \@errors;
	$results{'alarms'} = \@alarms;
	$results{'all_log'} = \@all_lines;
	$results{'log'} = \@lines;
	
	return \%results;
	
}

sub get_rule_details
{
	my $rule_path = shift;
	parse_rules::init();
	
	my ($error_result, $rfErrors, $LocalrfValues, $LocalrfOnceOnly, $LocalrfOnceUntilFail, $rfLocalOrder, $rfLocalIfAndConditions, $rfLocalIfOrConditions, $rfLocalEvery, $rfRules_files, $rfGlobal_ignores) = parse_rules::parse(3,0,$file);

	# now we have the rule structures, let's wrap them and ship them!
	my %results = ();
	$results{'errors'}=$rfErrors; 
	$results{'values'}=$LocalrfValues;
	$results{'onceonly'}=$LocalrfOnceOnly; 
	$results{'onceuntilfail'}=$LocalrfOnceUntilFail; 
	$results{'order'}=$rfLocalOrder;
	$results{'ifand'}=$rfLocalIfAndConditions; 
	$results{'ifor'}=$rfLocalIfOrConditions;
	$results{'every'}=$rfLocalEvery; 
	$results{'files'}=$rfRules_files; 
	$results{'ignores'}=$rfGlobal_ignores; 
}

1;
