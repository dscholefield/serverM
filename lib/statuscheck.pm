
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


package statuscheck;

our %alarm_record;
my @intrusion_sms = ();

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();

my %ignore_list;

my %allowed_rules;
my %already_triggered;
my @hasTriggered;

my $rfOnceOnly;
my $rfOnceUntilFail;;
my $rfTriggerCount;;
my @alarm_reports;
my $rfIfOr;
my $rfIfAnd;
my $rfEvery;
my $alarm_this_cycle;

our %status_output;
our $old_status;

# clear the command output hash
sub init
{
	# db_connection stores the filename to tie the DB hash to
	
	%status_output=();
	
}

sub terminate
{
	# nothing to be done for statuscheck!	
}

sub report_on_status
{

	my $passHash = shift;
	my $name = $passHash->{'name'};
	my $rfRules = $passHash->{'values'};		# the parsed rules set
	my $history_file = $passHash->{'path'};
	my $rfAllowed = $passHash->{'allowed_rules'};
	my $db = $passHash->{'db'};
	$rfOnceOnly = $passHash->{'once_only'};
	$rfOnceUntilFail = $passHash->{'once_until_fail'};
	$rfTriggerCount = $passHash->{'trigger'};
	$rfIfOr = $passHash->{'if_or'};
	$rfIfAnd = $passHash->{'if_and'};
	$rfEvery = $passHash->{'every'};
	$alarm_this_cycle = $passHash->{'alarm'};
	
	@alarm_reports=();
	%alarm_record = ();
	
	%allowed_rules = map {$_ => 1} @$rfAllowed;
	
	@intrusion_sms = ();
	
	@log = ();
	@alarm_log=();
	@report = ();
	@errors = ();
	 
	my %rules = %$rfRules;
	my %type = %{$rules{'type'}};
	my %value = %{$rules{'value'}};
	my %constraints = %{$rules{'constraints'}};
	my %alarm = %{$rules{'alarm'}};
	
	@hasTriggered = ();
	%already_triggered = ();

		my %alarmHash = %{$alarm{$name}};
		my $lt = convert_timestamp_specific_lt(time());
		

		if ($type{$name} eq "status")
		{
			# we need to chop off the leading and trailing double quotes from the command
			$value{$name} =~ s/^\"//;
			$value{$name} =~ s/\"$//;
			
			if ($main::check_cycle_count == 1)
			{
				# we're in the initial check cycle, so create the output
				# and record it for the next check cycle
				
				my $command = $value{$name};
				my @report=`$command`;
				if ($#report>1000)
				{
					@report=();
					push @log, "status command '$command' in $name created oversized output - ignoring rule";
					push @errors, "Status command '$command' in $name created oversized output - ignoring rule";
				}
				else
				{	$status_output{$name}=\@report; }	
			}
			else
			{
			# we have a pattern to check to see if a process is present
			
			my $is_found=0;
			my $command = $value{$name};
			my @report=`$command`;
			if ($#report>1000)
			{
				@report=();
				push @log, "status command '$command' in $name created oversized output - ignoring rule";
				push @errors, "status command '$command' in $name created oversized output - ignoring rule";
			}
			else
			{	
				if (! defined $status_output{$name})
				{
					# a new rule has been added, so we need to define a null output for
					# this rule
					$status_output{$name}=\@report;
					$old_status="none";
				}
				else
				{	
					if (join('',@report) ne join('',@{$status_output{$name}})) 
					{	$is_found=1; 
						$old_status=join("<br>", @{$status_output{$name}}[1..10]);
						$status_output{$name}=\@report if ($constraints{$name} ne 'baseline'); 
					}
				}
			}
				
			if ($is_found)						
			{
					
				if (!$already_triggered{$name}) {$already_triggered{$name}=1; push @hasTriggered, $name;}
				
				if ($allowed_rules{$name})
				{
					
					# ---------------------------------------------------------------------
					# build the sms alarm report, execute any commands, and log to any DSNs
					# also log to the standard log
					
					foreach my $sms_num (@{$alarmHash{'sms'}})
					{
						if (!$alarm_record{$sms_num})
						{ my @list=(); push @list,"status rule $name occurred"; $alarm_record{$sms_num} = \@list;}
						else
						{ push @{$alarm_record{$sms_num}}, "status rule $name occurred";}
					}
					
					if ($alarm_this_cycle)
					{
						
						foreach my $execute (@{$alarmHash{'execute'}})
						{
							my $oldexecute = $execute;
							$execute =~ s/^\"//;
							$execute =~ s/\"$//;
							my $report_string=join('#', @report);
							$execute =~ s/\%status/$report_string/g;
							my @results = toolkit::execute_alarm($execute, $name);
							push @log, "executed command $execute for rule $name";
										
							foreach my $res (@results)
							{
								push @log, "   result -> $res";
							}
							$execute = $oldexecute;
						}
					}
					
					push @alarm_log, "status rule $name occurred";
					
					#
					#
					# ---------------------------------------------------------------------
					
					if (!$rfTriggerCount->{$name})
					{
						$rfTriggerCount->{$name}=1;
					}
					else
					{
						$rfTriggerCount->{$name}++;  
					}
					
					if (@{$alarmHash{'email'}} != ())
					{
						# we need to build the entry in the email alarm data structure
						my %alarm_details1 = ();
						$alarm_details1{'name'}=$name;
						$alarm_details1{'type'}="status";
						$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
						$alarm_details1{'details'}="Status of command has changed";
						$alarm_details1{'details'}.='<br>Command = '.$command;
						$alarm_details1{'details'}.='<br>Old=<br>'.$old_status;
						$alarm_details1{'details'}.='<p>New=<br>'.join("<br>", @{$status_output{$name}}[1..10]);
						$alarm_details1{'data'}="none";
								
						if ($rfOnceUntilFail->{$name})
						{
							$alarm_details1{'meta'}="Once until fail";
						}
						else
						{
							if ($rfOnceOnly->{$name})
							{
									$alarm_details1{'meta'}="Once only";
							}
							else
							{
									$alarm_details1{'meta'}="none";
							}
						}
						
						
						$alarm_details1{'count'}= $rfTriggerCount->{$name};
						
						$alarm_details1{'alarm'}="email";
						
						
						# ----------------------------------------
						# Build the alarm records for email alarms
						#
					
						foreach my $email_address (@{$alarmHash{'email'}})
						{
							if (!$alarm_record{$email_address})
							{ my @list = (); push @list, \%alarm_details1;
								$alarm_record{$email_address} = \@list;}
							else
							{ push @{$alarm_record{$email_address}}, \%alarm_details1;
								}
						}
						
						#
						# ----------------------------------------
					}
			} 
				
			} # end 'service not found' loop
		}
		}
		
	return(\@intrusion_sms, \@alarm_log, \@log, \@report, \@errors, \@hasTriggered, \%alarm_record, $rfTriggerCount);
			

}

sub convert_timestamp_specific_lt
{
	my $fromTime = shift;
   	my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($fromTime);
	$year+=1900;
	my $monName = (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$mon];
	my $dayName = (qw(Sun Mon Tue Wed Thu Fri Sat))[$wday];
	
	if ($sec<10) {$sec="0$sec";}
	if ($min<10) {$min="0$min";}
	if ($hour<10) {$hour="0$hour";}
	
	return "$dayName $mday $monName $year : $hour:$min:$sec";

}

sub add_to_log
{
	my $message = shift;
	open(DailyReport, ">>c:/qmonII_dev/log/log.txt");
	my $ltime="now";
	
	print DailyReport "$ltime $message\n";
	close(DailyReport);
}


1;
