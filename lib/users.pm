
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
use toolkit;

package users;

my @intrusion_sms = ();

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();

our %alarm_record;

sub do_users
{


	
	my $passHash = shift;
	
	my $name = $passHash->{'name'};
	my $rfValues = $passHash->{'values'};		# the parsed rules set
	my $in_path = $passHash->{'path'};
	my $rfAllowed = $passHash->{'allowed_rules'};
	my $rfOnceOnly = $passHash->{'once_only'};
	my $rfOnceUntilFail = $passHash->{'once_until_fail'};
	my $rfTriggerCount = $passHash->{'trigger'};
	my $rfIfOr = $passHash->{'if_or'};
	my $rfIfAnd = $passHash->{'if_and'};
	my $rfEvery = $passHash->{'every'};
	my $alarm_this_cycle = $passHash->{'alarm'};
	
	
	# add_to_log("debug:: in true check");
	my %allowed_rule = map {$_ => 1} @$rfAllowed;
	
	@intrusion_sms = ();
	
	@log = ();
	@alarm_log = ();
	@report = ();
	@errors = ();
	
	my @hasTriggered=();
	my @alarm_reports = ();
	my %alarm_record = ();
	
	my %type = %{$rfValues->{'type'}};
	my %value = %{$rfValues->{'value'}};
	my %constraints = %{$rfValues->{'constraints'}};
	my $value = $value{$name};
	
    
	my $times = $constraints{$name};
    
    my $startTime = -1; my $endTime = -1;
  
	($startTime, $endTime) = split(/:/, $times);
	if ($startTime != -1) {$startTime = $startTime * 60;}
	if ($endTime != -1) {$endTime = $endTime * 60;}
	
	if ($endTime == 0) {$endTime = 86400;}
	
	# the alarm value is now a ref to a hash containing
	# keys 'email' 'sms' and 'execute' with
	# values refs to lists of paramters
	
	my $alarm = $rfValues->{'alarm'};

	my $tm = convert_timestamp();
	

		if ($type{$name} =~ /^users$/i)
		{
		
			# now to check is the rule has been triggered
			# we will parse the 'value' string
			
	
			my $not=0;
			if ($value =~ /^s*not/i)
			{
				$not=1;
				$value =~ s/^\s*not//i;
			}
			
			my $type = "any-type";
			if ($value =~ /.*(interactive|system|any-type)\s*$/i)
			{
				$type = $1;
				$value =~ s/$1\s*$//;
				$type =~ tr/[A-Z]/[a-z]/;
			}
			
			# value now just has the user list so strip any white spaces
			
			$value =~ s/^\s*//;
			$value =~ s/\s*$//;
			
			# now we have user list, not modifier, and type, we can check
			
			my @current_users = `who`;
			my %online = ();
			foreach my $line (@current_users)
			{
				if ($line =~ /^([^\s]+)\s*.*$/)
				{ $online{$1}=1;}
			}
			
			
			my @check_users = split(/,/,$value);
			
			
			push @hasTriggered, $name;
			if (!$rfTriggerCount->{$name})
						{
							$rfTriggerCount->{$name}=1;
						}
						else
						{
							$rfTriggerCount->{$name}++;  
						}
						
			# add_to_log("debug:: command lib found command rule $name");
		
		if ($allowed_rule{$name})
			{
			
				# ---------------------------------------------------------------------
				# CHECK RULE FOR ALARM TRIGGERING HERE
				# ---------------------------------------------------------------------
				
				# assume rule alarm is not triggered
				my $rule_triggered = 0;
				
				# we need to check for the time parameters
				
				my @alarm_user;
				foreach my $user_to_check (@check_users)
				{
					$user_to_check =~ s/^'//;
					$user_to_check =~ s/'$//;
					
					foreach my $now_online (keys %online)
					{
						if (($now_online eq $user_to_check) || ($user_to_check eq "any"))
						{ $rule_triggered = 1;
							push @alarm_user, $now_online;
						}
					}
				}
				
				$rule_triggered = ($rule_triggered ^ $not);
				
				my $ssm = toolkit::seconds_since_midnight();
				
				if (($startTime != -1) 
					&& (($ssm < $startTime) || ($ssm > $endTime))
					)
				{ $rule_triggered = 0; }
				
				if ($rule_triggered)
				{
					
				# we need to get the alarms
				my %alarmHash = %{$alarm->{$name}};
				
				# ---------------------------------------------------------------------
				# build the sms alarm report, execute any commands, and log to any DSNs
				# also log to the standard log
				
				foreach my $sms_num (@{$alarmHash{'sms'}})
				{
					if (!$alarm_record{$sms_num})
					{ my @list=(); push @list,"users rule $name occurred"; $alarm_record{$sms_num} = \@list;}
					else
					{ push @{$alarm_record{$sms_num}}, "users rule $name occurred";}
				}
				
				if ($alarm_this_cycle)
				{
					foreach my $execute (@{$alarmHash{'execute'}})
					{
						my $old_execute = $execute;
						$execute =~ s/^\"//;
						$execute =~ s/\"$//;
						my @results = toolkit::execute_alarm($execute, $name);
						push @log, "executed command $execute for rule $name";
									
						foreach my $res (@results)
						{
							push @log, "   result -> $res";
						}
						$execute = $old_execute;
					}
				}
				
				push @alarm_log, "users rule $name occurred";
				
				#
				#
				# ---------------------------------------------------------------------
				
				if (@{$alarmHash{'email'}} != ())
				{
					my %alarm_details1 = ();
					$alarm_details1{'name'}=$name;
					$alarm_details1{'type'}="True";
					$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
					$alarm_details1{'details'}="users: ".join(' ', @alarm_user);
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
			}
			
		}
	
	
	# add_to_log("debug::returning from truecheck");
	return(\@intrusion_sms,  \@alarm_log, \@log, \@report, \@errors, \@hasTriggered, \%alarm_record, $rfTriggerCount);
			

}

sub do_final_exe
{
	# executes whatever command is provided
	# and returns the result to the caller
	# as a list
	my $cmd = shift;
	#$cmd =~ s/^\"//;
	#$cmd =~ s/\"$//;
	
	my $name = shift;
	
	my $old_command = $cmd;
	
	my ($txt, $hr, $min, $sec) = split(/:/, convert_timestamp());
	my ($dnm, $dn, $mo, $yr) = split(/ /, $txt);
	
	my $ssm = toolkit::seconds_since_midnight();
	my ($stxt, $shr, $smin, $ssec) = split(/:/, toolkit::convert_timestamp_in($ssm));
	
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
	
	
	my @results = `$cmd`;
	
	push @results, "encoded command: $old_command";
	push @results, "expanded command: $cmd";
	push @results, $?;
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
	my $ltime=convert_timestamp();
	
	print DailyReport "$ltime $message\n";
	close(DailyReport);
}


1;
