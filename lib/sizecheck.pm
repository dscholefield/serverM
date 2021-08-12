
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

package sizecheck;

our %alarm_record;
my @intrusion_sms = ();

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();

my $rfOnceOnly;
my $rfOnceUntilFail;;
my $rfTriggerCount;;
my @alarm_reports;
my $rfIfOr;
my $rfIfAnd;
my $rfEvery;
my $alarm_this_cycle;

sub report_on_filesize
{
	my $passHash = shift;
	my $name = $passHash->{'name'};
	my $rfRules = $passHash->{'values'};		# the parsed rules set
	my $historyfile = $passHash->{'path'};
	my $rfAllowed = $passHash->{'allowed_rules'};
	$rfOnceOnly = $passHash->{'once_only'};
	$rfOnceUntilFail = $passHash->{'once_until_fail'};
	$rfTriggerCount = $passHash->{'trigger'};
	$rfIfOr = $passHash->{'if_or'};
	$rfIfAnd = $passHash->{'if_and'};
	$rfEvery = $passHash->{'every'};
	$alarm_this_cycle = $passHash->{'alarm'};
	
	my $rfGlobalIgnores = $passHash->{'global_ignores'};
	
	my $rfIgnores = $rfRules->{'ignores'};
	my @ignores_tmp = @{$rfIgnores->{$name}->{'filesize'}};
	push @ignores_tmp, @{$rfGlobalIgnores->{'filesize'}};
	
	my @ignores = ();
	foreach my $fname (@ignores_tmp)
	{
		my $tmp_fname = $fname;
		$tmp_fname =~ s/\\/\//g;
		$tmp_fname = lc($tmp_fname);
		push @ignores, $tmp_fname;
		# push, "filesize ignoring file $tmp_fname";
	}
	
	my %ignore_files = map {$_ => 1} @ignores;
	
	my @alarm_reports = ();
	%alarm_record=();
	my %allowed_rule = map {$_ => 1} @$rfAllowed;
	my @hasTriggered=();
	my %already_triggered=();
	
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
	
	my $lt = convert_timestamp_specific_lt(time());
	
		if ($type{$name} eq "file size")
		{
			my $filename = $value{$name};
			# we need to allow 'globbing' of files
			# so we will expand here
			
			if ($filename =~ / /) 
			{
				$filename = "\"$filename\"";
			}
			
			my @globlist = glob($filename);

			my $filesize = $constraints{$name};
			
			FILE: foreach my $gfile (@globlist)
			{
				$gfile =~ s/^\"//;
				$gfile =~ s/\"$//;
				$gfile =~ s/\\/\//g;
				
				next FILE if ($ignore_files{lc($gfile)});
				
				my $readSize = -s $gfile;
			
				
				
					$readSize = $readSize/1024;
				
					# we need to record which rule has been triggered
					if (($readSize > $filesize) && (!$already_triggered{$name})) 
					{push @hasTriggered, $name; $already_triggered{$name}=1;}
					if (!$rfTriggerCount->{$name})
						{
							$rfTriggerCount->{$name}=1;
						}
						else
						{
							$rfTriggerCount->{$name}++;  
						}
					# we will only check the rule and send an alarm if the
					# rule is currently enabled
					if ($allowed_rule{$name})
					{
					
						if ($readSize > $filesize)
						{
							my %alarmHash = %{$alarm{$name}};
							
							# ---------------------------------------------------------------------
							# build the sms alarm report, execute any commands, and log to any DSNs
							# also log to the standard log
							
							foreach my $sms_num (@{$alarmHash{'sms'}})
							{
								if (!$alarm_record{$sms_num})
								{ my @list=(); push @list,"size check $name occurred"; $alarm_record{$sms_num} = \@list;}
								else
								{ push @{$alarm_record{$sms_num}}, "size check $name occurred";}
							}
							
							if ($alarm_this_cycle)
							{
								foreach my $execute (@{$alarmHash{'execute'}})
								{
									my $oldexecute = $execute;
									$execute =~ s/^\"//;
									$execute =~ s/\"$//;
									my $pfile = $gfile;
									$pfile =~ s/\//\\/g;
									$execute =~ s/\%fn/$pfile/g;
									
									
									my @results = toolkit::execute_alarm($execute, $name);
									push @log, "executed command $execute for rule $name";
												
									foreach my $res (@results)
									{
										push @log, "   result -> $res";
									}
									$execute = $oldexecute;
									
								}
							}
							
							push @alarm_log, "size check $name occurred";
							
							#
							#
							# ---------------------------------------------------------------------
							
							if (@{$alarmHash{'email'}} != ())
							{ 
									# we need to build the entry in the email alarm data structure
									my %alarm_details1 = ();
									$alarm_details1{'name'}=$name;
									$alarm_details1{'type'}="File Size";
									$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
									$alarm_details1{'details'}="File $gfile size has passed limit";
									$alarm_details1{'data'}="Size is now $readSize Kb (limit $filesize Kb)";
											
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

1;
