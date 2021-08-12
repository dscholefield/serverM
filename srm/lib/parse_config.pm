# srm config parsing library
# (c)2006 port80 limited. All rights reserved.
# version 0.9 D. Scholefield

# parse_config module to read the text file containing the configuration details for
# the srm daemon


package parse_config;

use strict;

# declare global variables containing configuration details


my @rlog=();
my $log_location='';
my $db_ip;
my $db_user;
my $db_pass;
my $screen;
my $rlog_tmp;
my $key;

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
			$valStruct{'db-ip'}=$db_ip;
			$valStruct{'db-user'}=$db_user;
			$valStruct{'db-pass'}=$db_pass;
			$valStruct{'rlog'}=\@rlog;
			$valStruct{'log-location'}=$log_location;
			$valStruct{'screen'}=$screen;
			$valStruct{'key'}=$key;
			
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
	my $success = open(Config, "<$in_path");
	
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

		# remove and comment from the end of the line
		$in_line =~ s/#.*$//;
		
		my ($field, $value) = split(/:/, $in_line);
		
		# clear up leading and trailing spaces
		$field =~ s/^\s*//;
		$value =~ s/^\s*//;
		$field =~ s/\s*$//;
		$value =~ s/\s*$//;
		
		# we can now deal with the '%path' variable in the value if required
		$value =~ s/\%path/$main::install_path/g;
		
		
		
		if ($field eq "screen")
		{
			$parse_error=check_values($debug, \$screen, $field, $value, "off", "on");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$screen'");
			next LINE;
		}
		
		if ($field eq "db-ip")
		{
			$parse_error=check_values($debug, \$db_ip, $field, $value, "pat(.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$db_ip'");
			next LINE;
		}
		
		if ($field eq "db-user")
		{
			$parse_error=check_values($debug, \$db_user, $field, $value, "pat(.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$db_user'");
			next LINE;
		}
		
		if ($field eq "key")
		{
			$parse_error=check_values($debug, \$key, $field, $value, "pat(.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$key'");
			next LINE;
		}
		
		if ($field eq "db-pass")
		{
			$parse_error=check_values($debug, \$db_pass, $field, $value, "pat(.*)");
			return $parse_error if ($parse_error ne "ok");
			debug($debug, "Set $field to '$db_pass'");
			next LINE;
		}
		
		if ($field eq "rlog")
		{
			$parse_error=check_values($debug, \$rlog_tmp, $field, $value, "pat(.*)");
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
			debug($debug, "Set $field to '$rlog_tmp'");
			push @rlog, $rlog_tmp;
			next LINE;
		}
		
		if ($field eq "log-location")
		{
			$parse_error=check_values($debug, \$log_location, $field, $value, "pat(.*)");
			return $parse_error if (($parse_error ne "ok") && ($debug != 3));
			debug($debug, "Set $field to '$log_location'");
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

