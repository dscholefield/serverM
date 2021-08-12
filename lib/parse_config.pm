

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

# parse_config module to read the text file containing the configuration details for
# the watcher daemon - the main parse routine will accept a path to the config file
# directory, and return a status message of 'ok', or an error message


package parse_config;

use strict;

# declare global variables containing configuration details

my $daily_report="on";
my $daily_report_time=540; 				# 0900hrs as measured in minutes from midnight
my $heartbeat="off";

my @daily_report_emails=("none", "none", "none");
my $alarm_emails="on";
my @alarm_emails=("none", "none", "none");
my $alarm_email_throttle="on";
my $alarm_sms="off";
my @alarm_sms=("none", "none", "none");
my $alarm_sms_throttle="on";

my $alarm_format = "text";
my $report_format = "text";

my $email_gateway="none";
my $sms_gateway="none";

my $status="on";
my $period="60";						# how many minutes between each run
my $administrator="none";
my $clear_on_pause="off";
my $smtp_reply="";
my $sms_to="";
my $syslog_level='4';
my $syslog_include='all';
my $syslog_severity=0;
my $rlog_level='4';
my $rlog_include='all';
my $rlog_severity=0;
my $rlog='';
my $log_location='';
my %user_defs=();
my $user_def='';

my @allErrors=();
my %valStruct=();

my $lineCount=0;

# the main parse routine will accept a debug level, and a check flag
# if the check flag is set to 1 then the input is checked but the
# data structure containing the results are not returned, otherwise
# the data structure is built, and a pointer returned
# if the debug status is set to 1 then all debug messages are printed to STDIO
# if the debug status is set to 2 then only error messages are printed to STDIO
# if the debug status is set to 3 then error messages only are printed and
# the parsing will continue
# in all cases the @allErrors list is built with the errors encountered
# the routine will return a list of results ($status, $rfErrors, $rfStruct)
# where status = 1 if everything was ok, otherwise 0
# and $rfErrors is a ref to an array of strings (possibly empty), each with an error message
# and rf struct is a ref to a complex data structure (possibly empty) with the values parsed

sub parse
{
	my $debug=shift;
	my $check=shift;
	my $in_path=shift;
	
	#start with the basic parse
	my $result = parse_sub($debug, $in_path);
	if (($result ne "ok") && (!$check))
	{ return (0, \@allErrors, \%valStruct); }
	else
	{
		
			# we need to build the values structure
			$valStruct{'daily-report'}=$daily_report;
			$valStruct{'daily-report-time'}=$daily_report_time;
			
			# we have to scrap array index1 because perl auto-vivifies the array!
			{my $scrap = shift @daily_report_emails;}
			$valStruct{'daily-report-emails'}=\@daily_report_emails;
			$valStruct{'alarm-emails-status'}=$alarm_emails;
			
			
			$valStruct{'alarm-emails-throttle'}=$alarm_email_throttle;
			
			
			$valStruct{'alarm-sms-status'}=$alarm_sms;
			$valStruct{'alarm-sms-throttle'}=$alarm_sms_throttle;
			$valStruct{'email-gateway'}=$email_gateway;
			$valStruct{'sms-gateway'}=$sms_gateway;
			$valStruct{'status'}=$status;
			$valStruct{'period'}=$period;
			$valStruct{'heartbeat'}=$heartbeat;
			$valStruct{'administrator'}=$administrator;
			$valStruct{'clear-on-pause'}=$clear_on_pause;
			$valStruct{'smtp-reply'}=$smtp_reply;
			$valStruct{'sms-to'}=$sms_to;
			$valStruct{'alarm-format'}=$alarm_format;
			$valStruct{'report-format'}=$report_format;
			$valStruct{'syslog-level'}=$syslog_level;
			$valStruct{'syslog-severity'}=$syslog_severity;
			$valStruct{'syslog-include'}=$syslog_include;
			$valStruct{'rlog-severity'}=$rlog_severity;
			$valStruct{'rlog-include'}=$rlog_include;
			$valStruct{'rlog'}=$rlog;
			$valStruct{'log-location'}=$log_location;
			$valStruct{'user-defs'}=\%user_defs;
			
		if ($result ne "ok")
		{ return(0, \@allErrors, \%valStruct);}
		else
		{ return(1, \@allErrors, \%valStruct);}
	}
}

sub parse_sub
{
	my $debug=shift;
	my $in_path=shift;
	my $parse_error="ok";
	
	chop $in_path if ($in_path =~ /\/$/);
	my $success = open(Config, "<$in_path/config.txt");
	
	if (!$success)
	{
		error_report($debug, "Can't find config file in directory $in_path!");
		return "Can't find config file in directory $in_path!";
	}

	LINE: while(<Config>)
	{
		$lineCount++;
		my $in_line = $_;
		chomp	$in_line;
		
		# ignore lines which are just comments
		next LINE if (($in_line =~ /^\s*#/) || ($in_line =~ /^\s*$/));

		# remove any comment from the end of the line
		$in_line =~ s/#.*$//;
		
		my ($field, $value) = split(/:/, $in_line);
		
		# clear up leading and trailing spaces
		$field =~ s/^\s*//;
		$value =~ s/^\s*//;
		$field =~ s/\s*$//;
		$value =~ s/\s*$//;
		
		# we can now deal with the '%path' variable in the value if required
		$value =~ s/\%path/$main::install_path/g;
		
		if ($field eq "daily-report")
		{
			$parse_error=check_values($debug, \$daily_report, $field, $value, "off", "on");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$daily_report'");
			next LINE;
		}
		
		if ($field eq "heartbeat")
		{
			$parse_error=check_values($debug, \$heartbeat, $field, $value, "off", "on");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$heartbeat'");
			next LINE;
		}
		
		if ($field eq "alarm-format")
		{
			$parse_error=check_values($debug, \$alarm_format, $field, $value, "html", "text");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$alarm_format'");
			next LINE;
		}
		
		if ($field eq "report-format")
		{
			$parse_error=check_values($debug, \$report_format, $field, $value, "html", "text");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$report_format'");
			next LINE;
		}
		
		
		if ($field eq "clear-on-pause")
		{
			$parse_error=check_values($debug, \$clear_on_pause, $field, $value, "off", "on");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$heartbeat'");
			next LINE;
		}
		
		
		if ($field eq "administrator")
		{
			$parse_error=check_values($debug, \$administrator, $field, $value, "none", "pat(.*\@.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$administrator'");
			next LINE;
		}
		
		if ($field eq "sms-to")
		{
			$parse_error=check_values($debug, \$sms_to, $field, $value, "none", "pat(.*\@.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$sms_to'");
			next LINE;
		}
		
		if ($field eq "smtp-reply")
		{
			$parse_error=check_values($debug, \$smtp_reply, $field, $value, "none", "pat(.*\@.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$smtp_reply'");
			next LINE;
		}
		
		if ($field eq "daily-report-time")
		{
			
			# convert 24 hours to minutes
			my $inMins = (($value - ($value % 100))*0.6) + ($value % 100);
			
			my @allowed_times=[1..1440];
			$parse_error=check_values($debug, \$daily_report_time, $field, $inMins, @allowed_times);
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$daily_report_time'");
			next LINE;
		}
		
		if ($field =~ /daily-report-email(\d)/)
		{
			my $ar_index = $1;
			$parse_error=check_values($debug, \$daily_report_emails[$ar_index], $field, $value, "none", "pat(.*\@.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set field $field to @daily_report_emails");
			next LINE;
		}
		
		if ($field eq "alarm-emails")
		{
			$parse_error=check_values($debug, \$alarm_emails, $field, $value, "off", "on");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$alarm_emails'");
			next LINE;
		}
		
		
		
		if ($field eq "alarm-email-throttle")
		{
			$parse_error=check_values($debug, \$alarm_email_throttle, $field, $value, "off", "on");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$alarm_email_throttle'");
			next LINE;
		}
		
		if ($field eq "alarm-sms")
		{
			$parse_error=check_values($debug, \$alarm_sms, $field, $value, "off", "on");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$alarm_sms'");
			next LINE;
		}
		
		
		
		if ($field eq "alarm-sms-throttle")
		{
			$parse_error=check_values($debug, \$alarm_sms_throttle, $field, $value, "off", "on");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$alarm_sms_throttle'");
			next LINE;
		}
		
		if ($field eq "sms-gateway")
		{
			$parse_error=check_values($debug, \$sms_gateway, $field, $value, "pat(.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$sms_gateway'");
			next LINE;
		}
		
		if ($field eq "email-gateway")
		{
			$parse_error=check_values($debug, \$email_gateway, $field, $value, "pat(.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$email_gateway'");
			next LINE;
		}

		if ($field eq "status")
		{
			$parse_error=check_values($debug, \$status, $field, $value, "off", "on");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$status''");
			next LINE;
		}
		
		if ($field eq "period")
		{
			my @allowed_times=[1..1440];
			$parse_error=check_values($debug, \$period, $field, $value, @allowed_times);
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$period'");
			next LINE;
		}
		
		if ($field eq "syslog-level")
		{
			$parse_error=check_values($debug, \$syslog_level, $field, $value, "pat([0-9]+)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$syslog_level'");
			next LINE;
		}
		
		if ($field eq "syslog-include")
		{
			$parse_error=check_values($debug, \$syslog_include, $field, $value, "pat(((?:all)|(?:alarm)|(?:info)|(?:status)|(?:error))+)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$syslog_include'");
			next LINE;
		}
		
		if ($field eq "syslog-severity")
		{
			$parse_error=check_values($debug, \$syslog_severity, $field, $value, "pat([0-9]+)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$syslog_severity'");
			next LINE;
		}
		
		
		if ($field eq "rlog-include")
		{
			$parse_error=check_values($debug, \$rlog_include, $field, $value, "pat(((?:all)|(?:alarm)|(?:info)|(?:status)|(?:error))+)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$rlog_include'");
			next LINE;
		}
		
		if ($field eq "rlog-severity")
		{
			$parse_error=check_values($debug, \$rlog_severity, $field, $value, "pat([0-9]+)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$rlog_severity'");
			next LINE;
		}
		
		if ($field eq "rlog")
		{
			$parse_error=check_values($debug, \$rlog, $field, $value, "pat(.*)");
			if ($parse_error eq "ok")
			{
				# this is unusual, but it is very important that these values are correct, so we will
				# parse them even further
				my ($ip, $port, $key) = split(/\,/, $value);
				if ($ip eq '') 
				{ 	# we need a remote host to resolve to
					error_report($debug, "rlog value has no IP or hostname to send messages to");
					return "rlog value has no IP or hostname to send messages to";
				}
				if (($port !~ /^\s*[0-9]{1,5}\s*$/) || ($port<0) || ($port>65535)) 
				{ 	# we need a real port number
					error_report($debug, "rlog value has no valid port to send messages to");
					return "rlog value has no valid port to send messages to";
				}
			}
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$rlog'");
			next LINE;
		}
		
		if ($field eq "log-location")
		{
			$parse_error=check_values($debug, \$log_location, $field, $value, "pat(.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$log_location'");
			next LINE;
		}
		
		if ($field eq "user-def")
		{
			$parse_error=check_values($debug, \$user_def, $field, $value, "pat(.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$user_def'");
			$user_def=~s/^\s+//; $user_def=~s/\s+$//;
			$user_defs{$user_def}=1;
			next LINE;
		}
				
		error_report($debug, "Don't understand input field '$field'");
		$parse_error = "Don't understand input field '$field'";
		return $parse_error;
	}

	close(Config);
	return $parse_error;
}

# check_values expects a reference to a variable, the field name, the value given, and a following list
# of permissable values. If the value given is in the list then that variable is set to the
# value, and the result of 'ok' is given, else an error message is returned. Alternatively, the final
# parameter may be an array ref which the check_values routine will expand to the desired list.
# The list of permitted values may also contain regular expressions of the form 'pat(regex)'

sub check_values
{
	my $debug=shift;
	my $rfVar = shift;
	my $field = shift;
	my $value = shift;
	my @permitted;
	
	if (ref($_[0]))
	{
		my $rfPer = $_[0];
		@permitted = @$rfPer;
	}
	else {@permitted = @_;}
	
	if (is_in($value, @permitted))
	{
		$$rfVar=$value;
		return "ok";
	}
	else
	{
		if ($#permitted < 10)
		{
			my $valList=join(",", @permitted);
			error_report($debug, "value $value not in list ($valList) for field $field (default used)");
		}
		else
		{	
			error_report($debug, "value $value not in permitted list for field $field (default used)");
		}
		return "'$value' is not a permissible value for field '$field' (default used)";
	}

	
}

sub is_in
{
	my $value = shift;
	my @check_list=@_;
	
	foreach my $nxtElement (@check_list)
	{
		if ($nxtElement =~ /pat\((.*)\)/)
		{
			my $pat=$1;
			return 1 if ($value =~ /$pat/);
		}
		else {return 1 if ($value eq $nxtElement)};
	}
	return 0;
}

sub error_report
{
	my $debug=shift;
	my $error=shift;
	
	print "$error\n" if ($debug >0);
	push @allErrors, "(Line $lineCount) $error";
}

sub debug
{
	my $debug=shift;
	my $message=shift;
	print "DEBUG: $message\n" if ($debug==1);
}

return 1;

