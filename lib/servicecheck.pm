
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


package servicecheck;

our %alarm_record;
my @intrusion_sms = ();

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();

my %current_services;
my %service_status;
my %old_services;
my %new_services;
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
my $alarm_this_cycle;
my $rfEvery;

# the initialisation routine reads the current rules file and
# stores the contents in a global array for later reference
# it needs the current filename for reference
sub init
{
	# db_connection stores the filename to tie the DB hash to
	
	my $location = shift;
	
	my $success = create_tie($location);
	
	if (!$success)
	{
		return(0, "Can't open db for reading checksums");
		
	}
	return(1, "ok");
	
}

sub terminate
{
	my $location = shift;
	%old_services=%current_services;
	destroy_tie();
	
}

sub report_on_services
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
	
	my $rfGlobalIgnores = $passHash->{'global_ignores'};
	
	my $rfIgnores = $rfRules->{'ignores'};
	my @ignores = @{$rfIgnores->{$name}->{'service'}};
	push @ignores, @{$rfGlobalIgnores->{'service'}};
	
	@alarm_reports=();
	%alarm_record = ();
	
	%allowed_rules = map {$_ => 1} @$rfAllowed;
	
	%current_services=();
	%service_status=();
	
	%new_services=();

	@intrusion_sms = ();
	
	@log = ();
	@alarm_log = ();
	@report = ();
	@errors = ();
	 
	my %rules = %$rfRules;
	my %type = %{$rules{'type'}};
	my %value = %{$rules{'value'}};
	my %constraints = %{$rules{'constraints'}};
	my %alarm = %{$rules{'alarm'}};
	%ignore_list = map {$_ => 1} @ignores;
	@hasTriggered = ();
	%already_triggered = ();
	
	read_services();
	
	
		my %alarmHash = %{$alarm{$name}};
		my $lt = convert_timestamp_specific_lt(time());
		
		if (($type{$name} eq "new service") && ($constraints{$name} =~ /lookfor:(.*)/i))
		{
			my $is_present= $1;
			# add_to_log("debug:: found lookfor rule for $is_present");
			
			
			
				# we have a pattern to check to see if a process is present
				my $is_found=0;
				foreach my $desc (keys %current_services)
				{
					$is_found = 1 if ($desc =~ /$is_present/i);
				}
				
				if (!$is_found)
				{
					# add_to_log("debug:: haven't found found lookfor  for $is_present");
					
					if (!$already_triggered{$name}) {$already_triggered{$name}=1; push @hasTriggered, $name;}
					
					if ($allowed_rules{$name})
					{
					# the service isn't there, we need to alarm
						
						
						# ---------------------------------------------------------------------
						# build the sms alarm report, execute any commands, and log to any DSNs
						# also log to the standard log
						
						foreach my $sms_num (@{$alarmHash{'sms'}})
						{
							if (!$alarm_record{$sms_num})
							{ my @list=(); push @list,"service check $name occurred"; $alarm_record{$sms_num} = \@list;}
							else
							{ push @{$alarm_record{$sms_num}}, "service check rule $name occurred";}
						}
						
						if ($alarm_this_cycle)
						{
							foreach my $execute (@{$alarmHash{'execute'}})
							{
								my $oldexecute = $execute;
								$execute =~ s/^\"//;
								$execute =~ s/\"$//;
								$execute =~ s/\%sn/$is_present/g;
								my @results = toolkit::execute_alarm($execute, $name);
								push @log, "executed command $execute for rule $name";
											
								foreach my $res (@results)
								{
									push @log, "   result -> $res";
								}
								$execute = $oldexecute;
							}
						}
						
						push @alarm_log, "new Service rule $name occurred";
						
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
							$alarm_details1{'type'}="lookfor service";
							$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
							$alarm_details1{'details'}="service has not been found: '$is_present'";
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
	
	
	make_new_services();
	
	
	if ((%new_services != ()) && ($main::check_cycle != 1))
	{
			if (($type{$name} eq "new service") && ($constraints{$name} eq "none"))
			{
				if (!$already_triggered{$name}) {$already_triggered{$name}=1; push @hasTriggered, $name;}
				if (!$rfTriggerCount->{$name})
						{
							$rfTriggerCount->{$name}=1;
						}
						else
						{
							$rfTriggerCount->{$name}++;  
						}
				foreach my $desc (keys %new_services)
				{
					if ($allowed_rules{$name})
					{
						# ---------------------------------------------------------------------
						# build the sms alarm report, execute any commands, and log to any DSNs
						# also log to the standard log
						
						foreach my $sms_num (@{$alarmHash{'sms'}})
						{
							if (!$alarm_record{$sms_num})
							{ my @list=(); push @list,"new Service rule $name occurred"; $alarm_record{$sms_num} = \@list;}
							else
							{ push @{$alarm_record{$sms_num}}, "sew Service rule $name occurred";}
						}
						
						if ($alarm_this_cycle)
						{
							foreach my $execute (@{$alarmHash{'execute'}})
							{
								my $oldexecute = $execute;
								$execute =~ s/^\"//;
								$execute =~ s/\"$//;
								$execute =~s /\%sn/$desc/g;
								
								my @results = toolkit::execute_alarm($execute, $name);
								push @log, "executed command $execute for rule $name";
											
								foreach my $res (@results)
								{
									push @log, "   result -> $res";
								}
								$execute = $oldexecute;
							}
						}
						
						push @alarm_log, "new Service rule $name occurred";
						
						#
						#
						# ---------------------------------------------------------------------
						
						if (@{$alarmHash{'email'}} != ())
						{
							# we need to build the entry in the email alarm data structure
							my %alarm_details1 = ();
							$alarm_details1{'name'}=$name;
							$alarm_details1{'type'}="New service";
							$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
							$alarm_details1{'details'}="New service has been found '$desc'";
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
		
	}
	
	
	update_history($db);
	
	return(\@intrusion_sms, \@alarm_log, \@log, \@report, \@errors, \@hasTriggered, \%alarm_record, $rfTriggerCount);
			

}

sub make_new_services
{
	foreach my $desc (keys %current_services)
	{
		my $to_be_ignored=0;
		foreach my $pattern (keys %ignore_list)
		{
			$to_be_ignored=1 if ($desc =~ /$pattern/i);
		}
		# push @log, "Ignoring service $desc" if ($to_be_ignored);
		$new_services{$desc}=1 if ((!$old_services{$desc}) && (!$to_be_ignored))
	}
}

sub read_services
{
	# $current_services has process names as keys to hash
	# on exit
	my $pattern='^\s*[0-9]+\s+[^\s]+\s+[^\s]+\s+[0-9]+\:[0-9]+\s+(.*)$';

	if ($main::config{'user-defs'}->{'MAC OS X'})
	{ $pattern='^\s*[0-9]+\s+[^\s]+\s+[^\s]+\s+[0-9]+\:[0-9]+\.[0-9]+\s+(.*)$';}
	
	my @report = `ps axw`;
	foreach my $line (@report)
	{
		if ($line =~ /$pattern/)
		{	my $srv=$1;
			$current_services{$srv}=1;
		}
	}
	
}



sub update_history
{
	
	
}

sub create_tie
{
	my $location = shift;
	
	 eval {tie(%old_services, "DB_File", $location);};
	 if ($@)
		{
		die "Can't create tie ($@)\n";
		return 0;
		}
		else
		{
			return 1;
		}
}

sub destroy_tie
{
	untie(%old_services);
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
