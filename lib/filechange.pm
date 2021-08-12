
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
use Digest::MD5;
use toolkit;
use Data::Dumper;
use File::Find;
use File::Basename;
use DB_File;
package filechange;

my @intrusion_sms = ();
our %alarm_record;
our %error_throttle=();
our $fatal_throttle=0;

my %checksum_db;

my @log = ();
my @alarm_log = ();
my @report = ();
my @errors = ();
my @toadd=();
my @todelete=();

our $depth;
our $dirlist;

my %expanded_tree;
my @longList=();
my $all_constraints;
my $all_alarms;
my $all_values;

my %allowed_rules;
	my %alreadyTriggered;
	my @hasTriggered;
	
my %warn_email=();
my %warn_sms=();

my %fileDate = ();
my %fileChecksum = ();
my %fileAcl = ();
my $rfOnceOnly;
my $rfOnceUntilFail;
my $rfIfOr;
my $rfIfAnd;
my $rfEvery;
my $rfTriggerCount;
my %rfInitialConditions;
my @alarm_reports;
my $alarm_this_cycle;


# the initialisation routine reads the current rules file and
# stores the contents in a global array for later reference
# it needs the current filename for reference
sub init
{
	# db_connection stores the filename to tie the DB hash to
	
	my $location = shift;
	
	my $success = create_tie($location);
	
	%fileDate = ();
	%fileChecksum = ();
	%fileAcl = ();

  	@toadd=();
	@todelete=();

	my $read_success = read_checksums($location);
	if (!$read_success)
	{
		return(0, "Can't open db for reading checksums");
		
	}
	return(1, "ok");
	
}

sub terminate
{
	my $location = shift;
	
	update_checksums($location);
	destroy_tie();
	
}

sub maintain
{
	# we are going to delete all the files that are not
	# mentioned in the rules with file change
	# parameters
	# this may take some time!

	my $rfRules = shift;
}

	
sub report_on_file_changes
{
	my $passHash = shift;
	my $name = $passHash->{'name'};
	my $rfRules = $passHash->{'values'};		# the parsed rules set
	my $checkfile = $passHash->{'path'};
	my $rfAllowed = $passHash->{'allowed_rules'};
	$rfOnceOnly = $passHash->{'once_only'};
	$rfOnceUntilFail = $passHash->{'once_until_fail'};
	$rfTriggerCount = $passHash->{'trigger'};
	$rfIfOr = $passHash->{'if_or'};
	$rfIfAnd = $passHash->{'if_and'};
	$rfEvery = $passHash->{'every'};
	my $rfGlobalIgnores = $passHash->{'global_ignores'};
	$alarm_this_cycle = $passHash->{'alarm'};
	
	my $rfIgnores = $rfRules->{'ignores'};
	my @ignores = @{$rfIgnores->{$name}->{'filechange'}};
	
	
	push @ignores, @{$rfGlobalIgnores->{'filechange'}};
	
	%allowed_rules = map {$_ => 1} @$rfAllowed;
	%alreadyTriggered =();
	@hasTriggered=();
	%expanded_tree = ();
	
	# add_to_log("debug::file change entered");
	 @intrusion_sms = ();
	
	 @log = ();
	 @alarm_log = ();
	 @report = ();
	 @errors = ();
	 	
	 @toadd=();
	 @todelete=();
	 
	 @longList=();
	
	 %alarm_record = ();
	 
	 %warn_email=();
	 %warn_sms=();
	
	 

	my %rules = %$rfRules;
	my %type = %{$rules{'type'}};
	my %value = %{$rules{'value'}};
	my %constraints = %{$rules{'constraints'}};
	my %alarm = %{$rules{'alarm'}};
	
	# we will keep a global copy of the first contratints and
	# alarm values
	
	$all_constraints = $constraints{$name};
	$all_alarms = $alarm{$name};
	$all_values = $value{$name};
	
	
			
	@alarm_reports=();
	
	check_sums($name, $checkfile, \%type, \%value, \%constraints, \%alarm, \@ignores);
	update_checksums();
	
						
	return(\@intrusion_sms, \@alarm_log, \@log, \@report, \@errors, \@hasTriggered, \%alarm_record, $rfTriggerCount);
}
	
	
sub check_sums
{
	my ($isType, $checksumfile, $rfType, $rfValue, $rfConstraints, $rfAlarm, $rfIgnores) = @_;
	
	my %checkType = %$rfType;
	my %checkValue = %$rfValue;
	my %checkConstraints = %$rfConstraints;
	my %checkAlarms = %$rfAlarm;
	my @ignores_tmp = @$rfIgnores;
	my $cons_recurse = 0;
	my $cons_depth = 0;
	
	my @ignores = ();
	foreach my $fname (@ignores_tmp)
	{
		my $tmp_fname = $fname;
		$tmp_fname =~ s/\\/\//g;
		$tmp_fname = lc($tmp_fname);
		push @ignores, $tmp_fname;
		# push @log, "filechange ignoring file $tmp_fname";
	}
	
	my %ignore_files = map {$_ => 1} @ignores;
	
	my @filenames = ();
	my %keepAlarm = ();
	my %keepConstraints = ();
	
	# ALARMS NOT HANDLED PROPERLY HERE!! *** BUG ****
	# we need to take each file 'description' and and glob it, mapping the globbed
	# list to the alarm type
	
		
	# we'll extract any recursion information
	if ($checkConstraints{$isType} =~ /recurse:(\d+)/)
	{
		$cons_depth = $1;
		$cons_recurse = 1;
	}
		
		
		# $checkValue{$isType} =~ tr/A-Z/a-z/;
		if ($checkType{$isType} =~ /^\s*file\s+change/i)
		{
			# we first need to expand any globbing!
			my @full_list = ();
			
			if ($checkValue{$isType} =~ / /)
			{	
				$checkValue{$isType} = "\"$checkValue{$isType}\"";
			}
			
			# we need to change '\' slashes to '/'
			$checkValue{$isType} =~ s/\\/\//g;
			# ------------ recurse down tree structure if 'recurse' set
			
			if ((! -d $checkValue{$isType}) && ($cons_recurse))
			{
				# we need to chop off the file and return
				# just the directory
				my $tochop = $checkValue{$isType};
				if ($tochop =~ s/(\/[^\/]+)$//)
				{
					my $fname = $1;
					my %tree = ();
					get_tree($tochop, $cons_depth, \%tree);
					foreach my $dir (keys %tree)
					{
						my $fullname = "$dir$fname";
						$expanded_tree{$fullname} = 1;
					}
				}
			}
			else
			{ $expanded_tree{$checkValue{$isType}} = 1; }
			
			# ------------------------
			
			
			foreach my $fn (keys %expanded_tree)
			{
				
				my @globlist = glob($fn);
				foreach my $gfile (@globlist) 
					{	$gfile =~ s/^\"//;
						$gfile =~ s/\"$//;
						
						if (!$ignore_files{lc($gfile)})
						{push @full_list, $gfile ;}						
					}
						
			}
			
			# now we need to expand the full-list to take account of
			# directories with files in them
			@longList = ();
			expand(@full_list);
			# now @longlist has everyfile after globbing and expansion of 
			# directories, we can map the alarm type onto each filename
			
			
			foreach my $fname (@longList)
			{
				if (!$keepAlarm{$fname})
				{
					$keepAlarm{$fname}= $checkAlarms{$isType};
				}
				else
				{
					$keepAlarm{$fname} .= $checkAlarms{$isType};
				}
				
				# we need to do the same for the constraints
				if (!$keepConstraints{$fname})
				{
					$keepConstraints{$fname}= $checkConstraints{$isType};
					
				}
				else
				{
					$keepConstraints{$fname} .= $checkConstraints{$isType};
				}
			}
			
			
			# and we need to add the file names to the master list
		
			do_check($isType, \@longList, \%keepAlarm, \%keepConstraints);
		}
	
	}
	
	sub do_check
	{
		my $name = shift;
		my $rfFiles = shift;
		my $rfKalarms = shift;
		my $rfKconstraints = shift;
		my %keepAlarm = %$rfKalarms;
		my %keepConstraints = %$rfKconstraints;
		my @filenames = @$rfFiles;
		
	
	foreach my $file (keys %fileChecksum)
		{
		if (($all_constraints =~ /deleted/i) && (! -e $file))
		{
			# a file has been removed and we must alarm if it part
			# of the test pattern for this rule
			# add_to_log("File $file does not exist!");
			
			if (testglob($file, $all_values))
			{		
					my $lt = convert_timestamp_specific_lt(time());
				
					if (!$alreadyTriggered{$name}) {push @hasTriggered, $name; $alreadyTriggered{$name}=1;}
					
					# we need to check for allowed rules only
					if ($allowed_rules{$name})
					{
						
						# main alarm block here!
						my %alarmHash = %$all_alarms;
						
						# ---------------------------------------------------------------------
						# build the sms alarm report, execute any commands, and log to any DSNs
						# also log to the standard log
						
						foreach my $sms_num (@{$alarmHash{'sms'}})
						{
							if (!$alarm_record{$sms_num})
							{ my @list=(); push @list,"file deleted rule $name occurred"; $alarm_record{$sms_num} = \@list;}
							else
							{ push @{$alarm_record{$sms_num}}, "file deleted rule $name occurred";}
						}
						
						
						if ($alarm_this_cycle)
						{
							foreach my $execute (@{$alarmHash{'execute'}})
							{
								$execute =~ s/^\"//;
								$execute =~ s/\"$//;
								my $pfile = $file;
								$pfile =~ s/\//\\/g;
								my $oldexecute = $execute;
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
						
						
						push @alarm_log, "file change rule $name occurred (file $file deleted)";
						
						#
						#
						# ---------------------------------------------------------------------
				
						
					# need to increase the trigger count for this rule!
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
						if (!$warn_email{$file})
						{
							# we need to build the entry in the email alarm data structure
							my %alarm_details1 = ();
							$alarm_details1{'name'}=$name;
							$alarm_details1{'type'}="File Change";
							$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
							$alarm_details1{'details'}="File $file has changed";
							$alarm_details1{'data'}="Change type: deleted";
									
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
							# add_to_log("Pushing $alarm_details1{'name'} onto alarm reports");
							
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
							
							# $warn_email{$file}=1; commented out otherwise no other checks will be made
						}
					}
				
					}
			
			}
		delete_checksum($file);
		}
	}	
		
	# add_to_log("debug::doing check");
	if (@filenames == ())
	{
		# push @log, "No files to check for file change";
		# push @report, "No files to check for file change";
		return;	
	}
	
	
	
	foreach my $file (@filenames)
	{
		# old win32 code to deal with no case sensitivity
		# $file =~ tr/A-Z/a-z/;
		
		
		# print "Checking MD5 for $file\n";
	
		
		my $dobj = Digest::MD5->new;
	
		my $success = open(InCFile, "<$file");
	
		
		if (!$success)
		{
			my $e_msg="can't open $file found for file change check";
			if (! $error_throttle{$e_msg})
			{
				push @errors, $e_msg;
				$error_throttle{$e_msg}=1;
			}
			
		}
		else
		{
			$dobj->addfile(*InCFile);

			my $digest = $dobj->hexdigest;
			close(InCFile);	
			
			my $acl_list = "";
			{
				my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($file);
				$acl_list = "$mode:$atime:$mtime:$ctime";
			}
			# now we have the actual digest, we can compare it
			# against the original
			# we only need to do something if this digest doesn't
			# match the one for the file in the checksum file
			if (!$fileChecksum{$file})
			{
				# we don't have a checksum for this file
				# so we will add it
				add_checksum($file);
				push @log, "adding checksum for new file $file";
				if (($keepConstraints{$file} =~ /new/i) && ($main::check_cycle_count != 1))
				{
					my $lt = convert_timestamp_specific_lt(time());
				
					if (!$alreadyTriggered{$name}) {push @hasTriggered, $name; $alreadyTriggered{$name}=1;}
					
					# we need to check for allowed rules only
					if ($allowed_rules{$name})
					{
						
						# main alarm block here!
						my %alarmHash = %$all_alarms;
						
						# ---------------------------------------------------------------------
						# build the sms alarm report, execute any commands, and log to any DSNs
						# also log to the standard log
						
						foreach my $sms_num (@{$alarmHash{'sms'}})
						{
							if (!$alarm_record{$sms_num})
							{ my @list=(); push @list,"file change (created) rule $name occurred"; $alarm_record{$sms_num} = \@list;}
							else
							{ push @{$alarm_record{$sms_num}}, "file change (created) rule $name occurred";}
						}
						
						
						
						if ($alarm_this_cycle)
						{
							foreach my $execute (@{$alarmHash{'execute'}})
							{
								
							
								$execute =~ s/^\"//;
								$execute =~ s/\"$//;
								my $pfile = $file;
								$pfile =~ s/\//\\/g;
								my $oldexecute = $execute;
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
					
						push @alarm_log, "file change rule $name occurred (file $file created)";
						
						#
						#
						# ---------------------------------------------------------------------
				
						
					# need to increase the trigger count for this rule!
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
						if (!$warn_email{$file})
						{
							# we need to build the entry in the email alarm data structure
							my %alarm_details1 = ();
							$alarm_details1{'name'}=$name;
							$alarm_details1{'type'}="File Change";
							$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
							$alarm_details1{'details'}="File $file has changed";
							$alarm_details1{'data'}="Change type: created";
									
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
							# add_to_log("Pushing $alarm_details1{'name'} onto alarm reports");
							
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
							
							# $warn_email{$file}=1; commented out otherwise no other checks will be made
						}
					}
				
					}
				}
			}
			else
			{
				# we can compare the two!
				my $digest_matched;
				my $acl_matched;
				my $is_not;
				my $is_content;
				my $is_acl;
				my $is_triggered = 0;
				my $trigger_reason = "";
				
				if ($all_constraints =~ /not/i) {$is_not = 1;} else {$is_not = 0;}
				if ($all_constraints =~ /content/i) {$is_content = 1;} else {$is_content = 0;}
				if ($all_constraints =~ /acl/i) {$is_acl = 1;} else {$is_acl = 0;}
				
				
				if ($fileChecksum{$file} eq $digest)
				{$digest_matched = 1;} else {$digest_matched = 0;}
				
				# we need to check if the acl check is a '-a' or not
				{
					
					
					if ($all_constraints =~ /acl-a/i)
					{
						my ($storedMode,$storedAtime,$storedMtime,$storedCtime) = split(/:/, $fileAcl{$file});
						my ($newMode,$newAtime,$newMtime,$newCtime) = split(/:/, $acl_list);
						if (($storedMode eq $newMode) && ($storedMtime eq $newMtime) && ($storedCtime eq $newCtime))
						{$acl_matched = 1;} else {$acl_matched = 0;}
					}
					else
					{
						if ($fileAcl{$file} eq $acl_list)
						{$acl_matched = 1;} else {$acl_matched = 0;}
					}
				}
				
				# now for the test to see if the rule has been triggered
				
				if ((($is_content) && ($is_acl)) && (!$digest_matched))
				{
					$is_triggered=1; $trigger_reason = "content changed";
				}
				
				if ((($is_content) && ($is_acl)) && (!$acl_matched))
				{
					$is_triggered=1; $trigger_reason .= "acl changed";
				}
				
				if (($is_content) && (!$is_acl) && (!$digest_matched))
				{
					$is_triggered=1; $trigger_reason .= "content changed";
				}
				
				if (($is_acl) && (!$is_content) && (!$acl_matched))
				{
					$is_triggered=1; $trigger_reason .= "acl changed";
				}
				
				if ($is_not) 
				{
					if ($is_triggered) {$is_triggered = 0;}
					else
					{$is_triggered = 1; $trigger_reason = $all_constraints;}
				}
				
				
				if ($is_triggered) 
				{
					# the file has been changed!
					my $lt = convert_timestamp_specific_lt(time());
					
					
					# add_to_log("debug::file change rule trigger $file $trigger_reason");
					if (!$alreadyTriggered{$name}) {push @hasTriggered, $name; $alreadyTriggered{$name}=1;}
					
					# we need to check for allowed rules only
					if ($allowed_rules{$name})
					{
						
						# main alarm block here!
						my %alarmHash = %$all_alarms;
						
						# ---------------------------------------------------------------------
						# build the sms alarm report, execute any commands, and log to any DSNs
						# also log to the standard log
						
						foreach my $sms_num (@{$alarmHash{'sms'}})
						{
							if (!$alarm_record{$sms_num})
							{ my @list=(); push @list,"file change rule $name occurred"; $alarm_record{$sms_num} = \@list;}
							else
							{ push @{$alarm_record{$sms_num}}, "file change rule $name occurred";}
						}
						
						
						
						if ($alarm_this_cycle)
						{
							foreach my $execute (@{$alarmHash{'execute'}})
							{
								$execute =~ s/^\"//;
								$execute =~ s/\"$//;
								my $pfile = $file;
								$pfile =~ s/\//\\/g;
								my $oldexecute = $execute;
								$execute =~ s/\%fn/$pfile/g;
								
								my @results = toolkit::execute_alarm($execute, $name);
								push @log, "Executed command $execute for rule $name";
											
								foreach my $res (@results)
								{
									push @log, "   result -> $res";
								}
								$execute = $oldexecute;
								
							}
						}
						
						
						
						push @alarm_log, "file change rule $name occurred (file $file $trigger_reason)";
						
						#
						#
						# ---------------------------------------------------------------------
				
						
					# need to increase the trigger count for this rule!
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
						if (!$warn_email{$file})
						{
							# we need to build the entry in the email alarm data structure
							my %alarm_details1 = ();
							$alarm_details1{'name'}=$name;
							$alarm_details1{'type'}="File Change";
							$alarm_details1{'date'}=convert_timestamp_specific_lt(time);
							$alarm_details1{'details'}="File $file has changed";
							$alarm_details1{'data'}="Change type: $trigger_reason";
									
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
							# add_to_log("Pushing $alarm_details1{'name'} onto alarm reports");
							
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
							
							$warn_email{$file}=1;
						}
					}
				
					}
					delete_checksum($file);
					add_checksum($file);
				}
			}
		}
	
	}
}
						
		
sub update_checksums
{
	my $db_connection = shift;
	foreach my $file (@todelete)
	
	{delete_checksum_do($db_connection, $file);}
	
	foreach my $file (@toadd)
	{if (!$fileChecksum{$file}) {
		# print "Adding checksum for $file to $checkfile\n"; 
		add_checksum_do($db_connection, $file);}
	}
}
	
	
sub add_checksum
{
	my $filename = shift;
	push @toadd, $filename;
	
}

sub delete_checksum
{
	my $filename = shift;
	push @todelete, $filename;
}
	
sub add_checksum_do
{
	my $db_connection = shift;
	my $filename = shift;
	
	my $dobj = Digest::MD5->new;
	
	my $success = open(InCFile, "<$filename");
	
	if (!$success)
	{
		push @errors, "can't open file $filename for MD5 check!";
		
		push @report, "can't open file $filename for MD5 check!";
		return;
	}
	
	$dobj->addfile(*InCFile);
	
	my $digest = $dobj->hexdigest;
	close(InCFile);
	
	
	
	# we need to get the acls for the file
	
	my $acl_list = "";
	{
		my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev, $size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
		$acl_list = "$mode:$atime:$mtime:$ctime";
	}
	
	my $machine = $main::pmachine;
	my $msg = add_checksum_tie($machine, $filename, $digest, $acl_list); 
	push @errors, $msg if ($msg ne "ok");
	
	# we'll add this to the hash to avoid duplicates
	
	$fileChecksum{$filename}=$digest;
	
}

sub delete_checksum_do
{
	my $db_connection = shift;
	my $filename = shift;
	
	my $machine = $main::pmachine;
	my $msg = delete_checksum_tie($db_connection, $machine, $filename);
	push @errors, $msg if ($msg ne "ok");
	
	undef $fileChecksum{$filename};
}

sub read_checksums
{
	# all checksums are in the hash 'checksum_db'
	
	foreach my $insert_key (keys %checksum_db)
	{
		my ($server, $file) = split(/\^/, $insert_key);
		my ($checksum, $acls) = split(/\^/, $checksum_db{$insert_key});
		
		$fileChecksum{$file} = $checksum;
		$fileAcl{$file} = $acls;
	}

	return 1;
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
	
# the xpand routine checks each filename in the
# given list to see if it is a directory
# and traverses downwards adding filenames to
# the list as it goes

sub expand
{
	my @filelist = @_;
	
	
	foreach my $file (@filelist)
	{
		# print "Now checking $file\n";
		if (-d $file)
		{
			# print "Expanding $file\n";
			opendir DIR, $file or return;
			my @contents = grep !/^\.\.?$/, readdir DIR;
			closedir DIR;
			my @new_contents=();
			foreach my $nfile (@contents)
			{
				push @new_contents, "$file/$nfile";
			}
			expand(@new_contents);
		}
		else
		{

			push @longList, $file;
		}
		
	
	}
	

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

sub glob2pat {
	my $globstr = shift;
	my %patmap = ('*' => '.*', '?' => '.', '[' => '[', ']' => ']');
	$globstr =~ s{(.)} {$patmap{$1} || "\Q$1" }ge;
	return $globstr;
}

sub testglob {
	my $filename = shift;
	my $globpat = shift;
	
	# get the final part of the filename
	my $pattern = "";
	my $dir = "";
	
	if ($globpat =~ /(.*)\/([^\/]+)$/)
	{
		$pattern = $2;
		$dir = $1;
	}
	
	# convert to shell pattern
	$pattern = glob2pat($pattern);
	
	# now we can insert subdirectory stuff into
	# the pattern regex
	$pattern = "$dir" . '\/' . $pattern . '$';
	
	if ($filename =~ /^$pattern$/i)
	{
		return 1;
	}
	else {return 0;}
}
	
sub get_tree
{
	my $root = shift;
	$depth = shift;
	$dirlist = shift;
	$root.='/' if ($root !~ /\/$/);
	File::Find::find(\&dofind, $root);
}

sub dofind {
   my $fpath=$File::Find::name;
   my @cdepth = split(/\//, $fpath);
   my $cdepth = $#cdepth; 
   if ($cdepth <= $depth)
   {
   	$dirlist->{$fpath}=1;
   	 # print "adding $fpath to list ($cdepth:$depth)\n";
   }
  
}	

sub create_tie
{
	my $location = shift;
	
	 eval {tie(%checksum_db, "DB_File", $location);};
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
	untie(%checksum_db);
}


sub add_checksum_tie
{
	my ($server, $file, $content, $acl) = @_;
	my $insert_key = $server.'^'.$file;
	my $insert_value = $content.'^'.$acl;
	

	eval{$checksum_db{$insert_key} = $insert_value;};
	if ($@)
	{
		return "error occured during checksum insert ($@)";
	}
	else
	{
		# print "Checksum $content, acls $acl added for file $file\n";
		return "ok";
	}
}

sub delete_checksum_tie
{
	my ($db, $server, $file) = @_;
	my $insert_key = $server.'^'.$file;
	
	eval{delete $checksum_db{$insert_key};};
	if ($@)
	{
		return "error occured during checksum delete ($@)";
	}
	else
	{
		return "ok";
	}
}

		
		
	
1;

	
	
	
