
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

package truecheck;

my @intrusion_sms = ();

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();

our %alarm_record;

sub do_all_trues
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
	
	# the alarm value is now a ref to a hash containing
	# keys 'email' 'sms' 'dsn' and 'execute' with
	# values refs to lists of paramters
	
	my $alarm = $rfValues->{'alarm'};

	my $tm = convert_timestamp();
	
		if ($type{$name} =~ /^true$/i)
		{
			push @hasTriggered, $name;
			if (!$rfTriggerCount->{$name})
						{
							$rfTriggerCount->{$name}=1;
						}
						else
						{
							$rfTriggerCount->{$name}++;  
						}
			# add_to_log("debug:: trucheck found true rule $name");
			if ($allowed_rule{$name})
			{
				# we need to get the alarms
				my %alarmHash = %{$alarm->{$name}};
				
				# ---------------------------------------------------------------------
				# build the sms alarm report, execute any commands, and log to any DSNs
				# also log to the standard log
				
				foreach my $sms_num (@{$alarmHash{'sms'}})
				{
					if (!$alarm_record{$sms_num})
					{ my @list=(); push @list,"True rule $name occurred"; $alarm_record{$sms_num} = \@list;}
					else
					{ push @{$alarm_record{$sms_num}}, "True rule $name occurred";}
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
				
				push @alarm_log, "true rule $name occurred";
				
				#
				#
				# ---------------------------------------------------------------------
				
				if (@{$alarmHash{'email'}} != ())
				{
					my %alarm_details1 = ();
					$alarm_details1{'name'}=$name;
					$alarm_details1{'type'}="True";
					$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
					$alarm_details1{'details'}="none";
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
	
	
	return(\@intrusion_sms, \@alarm_log, \@log, \@report, \@errors, \@hasTriggered, \%alarm_record, $rfTriggerCount);
			

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
