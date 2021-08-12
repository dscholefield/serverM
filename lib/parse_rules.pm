

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

# parse_rules expects a text file with a set of qMonII rules, one per
# line, and will parse those rules according to a strict syntax


# data structures to hold rule results
# each rule has to have a unique name (or could be number) which is used
# as the key into a set of hashes containing the values, contraints, and
# alarm actions. 

# types map the rule name onto  'process', 'file_change', 'file_size', and 'capacity'

# def parse rules
# - group names are a-zA-Z0-9_:;\.- only


# CHANGES FOR V2.106
# included { and } for scoping ignores and defs
# included 'global' keyword for ignores and defs
# global ignores are global wherever they appear
# global defs must be defined before they are referenced

use strict;

# we need a routine to 'de-clone' hashes with refs as elements
use Storable;

package parse_rules;
use Data::Dumper;

our $debug;
our $check;
our $groupname_pattern = '[0-9a-zA-Z\_\:\;\.\-]';

my %type=();
my %value=();
my %constraints=();
my %alarm=();
my %ignore=();
my %syslog_severity=();

my %error_report=();

my $in_scope = 0;
my $in_ifdef_scope = 0;
my $scope_name = "";
my $conditional_scope=1;

my $rfAlarmStruct;
my %alarm_email_names = ();
my %alarm_sms_names = ();
my %alarm_execute_names = ();
my %alarm_string_names = ();

my %inscope_email_names = ();
my %inscope_sms_names = ();
my %inscope_execute_names = ();
my %inscope_ignores = ();
my %inscope_names = ();
my %inscope_string_names = ();

my %global_ignores = ();
my %local_ignores = ();

my %email_globals = ();
my %sms_globals = ();
my %execute_globals = ();
my %string_globals = ();

my %if_and_condition = ();
my %if_or_condition = ();
my %every_condition = ();
my %everyat_condition = ();
my %cycle_condition = ();
my %initial_condition=();
my %throttle_condition = ();
my %attime = ();
my %onday = ();
my $rfConfig={};

my @order_list = ();

my %valStruct=();
my @allErrors=();

my $lineCount;

# we can catch strange rule numbers during the parsing

my $max_event=6553500;
my $min_event=1;

my %once_only=();
my %once_until_fail=();

my %include_files = ();

our $global_infile;

sub init {
	%alarm_email_names = ();
	%alarm_sms_names = ();
	%alarm_execute_names = ();
	%alarm_string_names = ();
	
	%inscope_email_names = ();
	%inscope_sms_names = ();
	%inscope_execute_names = ();
	%inscope_ignores = ();

	%email_globals = ();
	%sms_globals = ();
	%execute_globals = ();

	%global_ignores = ();
	
	$global_ignores{'filechange'} = [];
	$global_ignores{'filesize'} = [];
	$global_ignores{'command'} = [];
	$global_ignores{'service'} = [];
	$global_ignores{'status'} = [];
	$rfConfig={};
	$in_scope=0;
	$in_ifdef_scope=0;
	$conditional_scope=1;
	$scope_name = "";
	%inscope_names=();
	
	# error_report hash maps rule names to
	# their error messages
	%error_report = ();
	
	%attime = ();
	%onday = ();

}

	
sub parse
{
  %type=();
  %value=();
  %constraints=();
  %alarm=();
  %ignore=();

	@order_list = ();
	@allErrors = ();
	%valStruct=();
	%once_only= ();
	%once_until_fail=();
	%if_and_condition = ();
	%if_or_condition = ();
	%every_condition = ();
	%cycle_condition = ();
	%initial_condition = ();
	%include_files = ();
	%throttle_condition = ();
	
	$rfAlarmStruct=();
	
	$debug=shift;
	$check=shift;
	my $in_file=shift;
	
	$rfConfig = shift if ($_[0]);
	
	my $parse_rules_error = 0;
	my $result="ok";
	
		$include_files{$in_file} = -M $in_file;
		$result = parse_sub($debug, $in_file);
		#clear_locals($in_file);
		#%local_ignores = ();
		
		if ($result ne "ok")
		{
			$parse_rules_error = 1;
		}
		
	
		if ($check == 0)
		{
			# add_to_log("finished rules.txt, now for library");
			# we can now parse the 'extra' library rules
			# we need the glob pattern first
			my $full_path = $in_file;
			$full_path =~ s/[^\/]*$/ruleslib\/\*\.txt/;
			$full_path =~ s/\\/\//g;
			
			if ($full_path =~ / /)
				{	
					$full_path = "\"$full_path\"";
				}
				
				
			my @globlist = glob($full_path);
			# add_to_log("globbing file $full_path");
			
			
			
			foreach my $gfile (@globlist) 
			{	
				
					$gfile =~ s/^\"//;
					$gfile =~ s/\"$//;
					$include_files{$gfile} = -M $gfile;
					#force end of scope
					$in_scope=2;
					$result = parse_sub($debug, $gfile);
					#clear_locals($gfile);
					#%local_ignores = ();
					
					# scope termination is automatic for end of files
					# so we will check here, we can ignore pending
					# scope closes (value==2) as they were technically
					# closed at end of final line
					
					if ($in_scope == 1)
					{
						# scope wasn't ended at end of file
						$result = "Signature scope not ended before end of file";
						my $parse_error = "($global_infile:EOF) Signature scope not ended before end of file";
						error_report($debug, $parse_error, "");
					}
					
					if ($conditional_scope == 0)
					{
						# conditional scope wasn't ended at end of file
						$result = "conditional scope not ended before end of file";
						my $parse_error = "($global_infile:EOF) conditional scope not ended before end of file";
						error_report($debug, $parse_error, "");
					}
						
					if ($result ne "ok")
					{
						$parse_rules_error=1;
					}
				
				
			}
		}
		$valStruct{'type'}=\%type;
		$valStruct{'value'}=\%value;
		$valStruct{'constraints'}=\%constraints;
		$valStruct{'alarm'}=\%alarm;
		$valStruct{'ignores'}=\%ignore;
		$valStruct{'severity'}=\%syslog_severity;
		
		
		if ($parse_rules_error == 0)
		{
			if (@allErrors == ())
			{
				return (1, \@allErrors, \%valStruct, \%once_only, \%once_until_fail, \@order_list, \%if_and_condition, \%if_or_condition, \%every_condition, \%everyat_condition, \%include_files, \%global_ignores, \%error_report, \%attime, \%onday, \%throttle_condition, \%cycle_condition, \%initial_condition);
			}
			else
			{
				return (0, \@allErrors, \%valStruct, \%once_only, \%once_until_fail, \@order_list, \%if_and_condition, \%if_or_condition, \%every_condition, \%everyat_condition, \%include_files, \%global_ignores, \%error_report, \%attime, \%onday, \%throttle_condition, \%cycle_condition, \%initial_condition);
		
			}
		}
		else
		{
			return (0, \@allErrors, \%valStruct, \%once_only, \%once_until_fail, \@order_list, \%if_and_condition, \%if_or_condition, \%every_condition, \%everyat_condition, \%include_files, \%global_ignores, \%error_report, \%attime, \%onday, \%throttle_condition, \%cycle_condition, \%initial_condition);
		}
		
	
}


sub parse_sub
{
	my $debug=shift;
	my $in_file=shift;
	my $parse_error="ok";
	
	$global_infile=$in_file;
	$global_infile =~ s/\\/\//g;
	
	# we are going to reset the scope flag for
	# this file (signature scopes are specific
	# to individual files
	
	# the 'in scope' flag shows if we are
	# inside a local scope or not
	$in_scope = 0;
	$in_ifdef_scope=0;
	$conditional_scope=1;
	
			$scope_name = "";
			
			# clear the ignores list for this scope
			%inscope_ignores = ();
			$inscope_ignores{'filechange'} = [];
			$inscope_ignores{'commmand'} = [];
			$inscope_ignores{'filesize'} = [];
			$inscope_ignores{'service'} = [];
			$inscope_ignores{'status'} = [];
			
			# clear the 'def's for this scope
			scope_delete_from_defs();
	
	%inscope_names = ();
	%local_ignores = ();
	$local_ignores{'filechange'} = [];
	$local_ignores{'command'} = [];
	$local_ignores{'filesize'} = [];
	$local_ignores{'service'} = [];
	$local_ignores{'status'} = [];
	
	%inscope_ignores = ();
	$inscope_ignores{'filechange'} = [];
	$inscope_ignores{'command'} = [];
	$inscope_ignores{'filesize'} = [];
	$inscope_ignores{'service'} = [];
	$inscope_ignores{'status'} = [];
	
	$lineCount=0;
	chop $in_file if ($in_file =~ /\/$/);
	my $success = open(Config, "<$in_file");
	
	if (!$success)
	{
		error_report($debug, "Can't find rules file $in_file!", "");
		return "Can't find rules file $in_file!";
	}

	# we need to record the modification time for this file
	$include_files{$in_file} = -M $in_file;
	
	my $in_line;
	my $new_line=1;
	
	LINE: while(my $get_line = <Config>)
	{
				$in_line="" if ($new_line);
				
				$lineCount++;
				if ($get_line =~ /^(?:\s*)(.*)\-\-\s*$/)
				{
				 # we have a split line
				 my $got_line = $1;
				 chomp $got_line;
				 $got_line =~ s/\s+$//;
				 # re-insert a single space
				$got_line = "$got_line ";
				 if ($new_line) {$in_line=$got_line;} else {$in_line.=$got_line;}
				 
				 $new_line=0;
				 next LINE;
				}
				else
				{
					if ($get_line =~ /^(?:\s*)(.*)\-\s*$/)
					{
						
						 my $got_line = $1;
						 chomp $got_line;
						 $got_line =~ s/\s+$//;
						 if ($new_line) {$in_line=$got_line;} else {$in_line.=$got_line;}
						 
						 $new_line=0;
						 next LINE;
					}
					else
					{
						# it wasn't a split line
						chomp $get_line;
						$get_line =~ s/^(?:\s*)//;
						$in_line.= $get_line;
						$new_line=1;
					}
				}
				
		
		# print "Now have line $in_line\n";
		# if we are in a 'scope exit pending' state then we must
		# force the scope exit now
		if ($in_scope == 2)
		{
			$in_scope = 0;
			$scope_name = "";
			
			# clear the ignores list for this scope
			%inscope_ignores = ();
			$inscope_ignores{'filechange'} = [];
			$inscope_ignores{'command'} = [];
			$inscope_ignores{'filesize'} = [];
			$inscope_ignores{'service'} = [];
			$inscope_ignores{'status'} = [];
			
			# clear the 'def's for this scope
			scope_delete_from_defs();
			
		}
		
				
		# ignore lines which are just comments
		next LINE if (($in_line =~ /^\s*#/) || ($in_line =~ /^\s*$/));

		# remove and comment from the end of the line
		$in_line =~ s/#.*$//;

		# we need to check if we have an 'enddef' line
		if ($in_line =~ /^\s*enddef\s*$/)
		{
			if ($in_ifdef_scope==0)
			{
				# we're not in a scope!
				$parse_error="($global_infile:$lineCount) not in ifdef scope! Ignoring ifdef scope exit";
				error_report($debug, $parse_error, "");
				return $parse_error if ($debug != 3);
				next LINE;
			}
			else
			{
				$conditional_scope=1;
				$in_ifdef_scope=0;
				next LINE;
			}
		}
		next LINE if ($conditional_scope == 0);
		
		# we need to check if we have an 'ifdef' line
		if ($in_line =~ /\s*ifdef\s+(.*)/)
		{
			# it is an ifdef line, so we need to check the ifdef value
			my $whichdef=$1; $whichdef=~s/\s+$//;
			
			# first we see if we are outside an ifdef scope
			if ($in_ifdef_scope==0)
			{
				$in_ifdef_scope=1;
				# check to see if there is a config file definition to match
				if ($rfConfig->{'user-defs'}->{$whichdef})
				{
					# the user config exists
					next LINE;
				}
				else
				{
					# the user config does not exist
					$conditional_scope=0;
					next LINE;
				}
			}
			else
			{
				# can't nest ifdef scopes
				$parse_error="($global_infile:$lineCount) already in ifdef scope! Ignoring ifdef scope enter";
				error_report($debug, $parse_error, "");
				return $parse_error if ($debug != 3);
				next LINE;
			}
		}
		
			# before we get started on the rule, we can perform the 'initial'
			# substitutions
			{
				# substitute the root path for %path
				my $in_path = get_install_path();
				#my $unalter_path = $main::install_path;
				#if ($in_line !~ /^.*((global)\s+)?def:\s*execute(.*)$/i)
				{$in_line =~ s/\%path/$in_path/g; }
				#else
				#{$in_line =~ s/\%path/$unalter_path/g;}
			}
			
			# check to see if we are entering a new scope block
			if ($in_line =~ /^\s*\{\s*(.*)$/)
			{
				# ok, we have a request to enter a signature scope
				# we should check to see if this is legal now or
				# not. We also chop off the scope opener
				$in_line = $1;
				
				if ($in_scope)
				{
					# we are already inside a scope so we will error msg
					# but continue anyway
					$parse_error="($global_infile:$lineCount) Already in scope! Ignoring scope enter";
					error_report($debug, $parse_error, "");
					return $parse_error if ($debug != 3);
					next LINE;
				}
				else
				{
					$in_scope = 1;
					# SCOPE NAMES ARE NOT NOT OPTIONAL
					# check for a scope name
					$in_line =~ s/^\s+//;
					$in_line =~ s/\s+$//;
					
					if ($in_line eq "")
					{
						$parse_error="($global_infile:$lineCount) No scope name found!";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
					
					$scope_name = $in_line;
					if ($inscope_names{$scope_name})
					{
						$parse_error="($global_infile:$lineCount) Scope name already used in this file! Ignoring scope name";
						$scope_name = "";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
					else
					{
						$inscope_names{$scope_name} = 1 if ($scope_name);
					}
					
					next LINE;
				}
			}
			
			# check to see if we are exiting a scope block
			if ($in_line =~ /^(.*)\s*\}\s*$/)
			{
				# ok, we have a request to exit a signature scope
				# we should check to see if this is legal now
				# or not. Note also that we can't turn the scope
				# off until we have dealt with the line so we
				# will flag this.
				$in_line = $1;
				
				if (!$in_scope)
				{
					# we are already inside a scope so we will error msg
					# but continue anyway
					$parse_error="($global_infile:$lineCount) Can't exit scope - not in one! Ignoring scope exit";
					error_report($debug, $parse_error, "");
					return $parse_error if ($debug != 3);
				}
				else
				{
					# a value of two will force the scope to be exited at the end of
					# the parsing of this line
					$in_scope = 2;
				}
			}
			
			# we will pick up on lines with only a exit scope becuase
			# they will now be empty
			next LINE if ($in_line =~ /^\s*$/);
				
					
			# next we check to see if the line is a 'def' or a rule
			if ($in_line =~ /^\s*((global)\s+)?def:\s*(.*)$/i)
			{
				# we have a definition line
				my $def_line = $3;
				my $scope = "local";
				my $defline_msg;
				
				if ($2 eq 'global')
				{
					$defline_msg = process_defline($def_line, 'global');
				}
				else
				{
					$defline_msg = process_defline($def_line, 'local');
				}
				
				if ($defline_msg ne "ok")
				{
					$parse_error="($global_infile:$lineCount) Don't understand defintion $in_line ($defline_msg)";
					error_report($debug, $parse_error, "");
					
					return $parse_error if ($debug != 3);
				}
				next LINE;
			}
			
			# then to check for 'ignores'
			if ($in_line =~ /^\s*((global)\s+)?ignore:\s*(.*)$/i)
			{
				# we have a definition line
				my $def_line = $3;
				my $scope = "local";
				my $defline_msg;
				
				if ($2 eq 'global')
				{
					# print "$def_line is global\n";
					$defline_msg = process_ignoreline($def_line, 'global');
				}
				else
				{
					# print "$def_line is local\n";
					$defline_msg = process_ignoreline($def_line, 'local');
				}
				
				if ($defline_msg ne "ok")
				{
					$parse_error="($global_infile:$lineCount) Don't understand ignore definition $in_line ($defline_msg)";
					error_report($debug, $parse_error, "");
					
					return $parse_error if ($debug != 3);
				}
				next LINE;
			}
				
			# ok, now we can split the line up into the constituant parts
			{	my @countsplit = split(/::/, $in_line, 4);
				if ($#countsplit != 3) {
				$parse_error="($global_infile:$lineCount) Don't understand line $in_line (fewer than 4 parts to rule!)";
					error_report($debug, $parse_error, "");
					
					return $parse_error if ($debug != 3);
				}
			}	
			
			# ok, we can now substitute all strings in *any* part of the rulebase
			# we will look for all patterns of $_name_$ where 'name' is not ''
			# in the latter case we just replace the double $_ with one, and move on
			
			while($in_line =~ /\$\$([^\$]+)\$\$/i)
			{
				# we can replace each match with the correct name
				my $key = $1;
				my $value=get_string_value($key);
				if ($value eq '')
				{
					# this string isn't defined, error
					$parse_error="($global_infile:$lineCount) string $key not defined in $in_line";
					error_report($debug, $parse_error, "");
					return $parse_error if ($debug != 3);
				}
				else
				{$in_line =~ s/\$\$$key\$\$/$value/ ;}
			}
			
			$in_line =~ s/\$\$\$\$/\$\$/g;
			# that's removed the doubles as well
			
			my ($name, $value, $constraint, $alarm) = split(/::/, $in_line, 4);
			
			# we can now scrub off any whitespace from the start or end of the values
			$name =~ s/^\s+//; $value =~ s/^\s+//; $constraint =~ s/^\s+//; $alarm =~ s/^\s+//;
			$name =~ s/\s+$//; $value =~ s/\s+$//; $constraint =~ s/\s+$//; $alarm =~ s/\s+$//; 
			
			
			
			
			# we are going to look for rule pragmas, which start with
			# square brackets, there can be more than one pragma
			# so we need to keep checking
			# start by defining an empty 'if list'
			my @if_and_list=();
			my @if_or_list=();
			my $every_count = 0;
			my $every_type = '';
			my $cycle_count = 0;
			my $initial_count = 0;
			my $throttle_count = 0;
			my $throttle_span = "";
			my $onceonly = 0;
			my $onceuntilfail = 0;
			my @on_day_list= ();
			my @at_time_list = ();
			my $syslog_severity=0;
			
			
			while ($name =~ /^\s*\[([^\]]*)\]\s*(.*)/)
			{
				# there is a pragma
				my $pragma = $1; $name=$2;
				my $valid_pragma=0;
				if ($pragma =~ /^once only$/i)
				{ $valid_pragma=1;
					$onceonly = 1;
					}
				if ($pragma =~ /^once until fail$/i)
				{	$valid_pragma=1;
					$onceuntilfail = 1;
				}
				if ($pragma =~ /if-and\s+(.*)\s*/i)
				{
					my $list_to_split = $1;
					@if_and_list = iflist_split($list_to_split);
					
					$valid_pragma=1;
				}
				
				if ($pragma =~ /if-or\s+(.*)\s*/i)
				{
					my $list_to_split = $1;
					@if_or_list = iflist_split($list_to_split);
					
					$valid_pragma=1;
				}
				
				if ($pragma =~ /severity\s+([0-9]+)\s*/i)
				{
					$syslog_severity = $1;
					$valid_pragma=1;
				}
				
				if ($pragma =~ /on-day\s+(.*)\s*/i)
				{
					my $list_to_split=$1;
					@on_day_list = process_onday($list_to_split);
					$valid_pragma=1;
				}
				
				if ($pragma =~ /at-time\s+(.*)\s*/i)
				{
					my $list_to_split=$1;
					@at_time_list = process_attime($list_to_split);
					$valid_pragma=1;
				}
				
				if ($pragma =~ /every\s+(\d+)\s*([dhm])\s*/i)
				{
					$every_count = $1; $every_type = $2;
					if ($every_count > 0)
					{			
						$valid_pragma=1;
					}
					else
					{
						$parse_error="($global_infile:$lineCount) 'every' pragma is set to zero!";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
				}
				
				if ($pragma =~ /every\s+(\d+)\s*$/i)
				{
					$every_count = $1;
					if ($every_count > 0)
					{			
						$valid_pragma=1;
					}
					else
					{
						$parse_error="($global_infile:$lineCount) 'every' pragma is set to zero!";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
				}
				
				if ($pragma =~ /^initial\s*$/i)
				{
					$initial_count = 1;		
					$valid_pragma=1;
				}
				
				if ($pragma =~ /on-cycle\s+(\d+)\s*/i)
				{
					$cycle_count = $1;
					if ($cycle_count > 0)
					{			
						$valid_pragma=1;
					}
					else
					{
						$parse_error="($global_infile:$lineCount) 'on-cycle' pragma is set to zero!";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
				}
				
				if ($pragma =~ /throttle\s+(\d+)\s*\:\s*([mhds])\s*/i)
				{
					$throttle_count = $1;
					$throttle_span = $2;
					
					if (($throttle_count > 0) && ($throttle_span =~ /[mhds]/i))
					{		
						$throttle_span = lc($throttle_span);
						$throttle_count *= 60 if ($throttle_span eq "m");
						$throttle_count *= 3600 if ($throttle_span eq "h");
						$throttle_count *= 86400 if ($throttle_span eq "d");
						
						$valid_pragma=1;
					}
					else
					{
						$parse_error="($global_infile:$lineCount) 'throttle' pragma value is not understood!";
						error_report($debug, $parse_error, "");
						return $parse_error if ($debug != 3);
					}
				}
				
				if (!$valid_pragma)
				{
					$parse_error="($global_infile:$lineCount) Don't understand pragma $pragma";
					error_report($debug, $parse_error, "");
					return $parse_error if ($debug != 3);
					next LINE;
				}
				
			}
			
			if ($name !~ /[a-zA-Z0-9]+/)
			{
				$parse_error="($global_infile:$lineCount) Name for rule must have at least one alpha-numeric character";
				error_report($debug, $parse_error, "");
				return $parse_error if ($debug != 3);
			}
			
			# we are going to add the name of the file to
			# the start of the rule name
			# we will also add the current scope name if there
			# is one defined
			
			# we need to strip off the leading directory location
			# because we only have 251 chars to plat with in hash
			# key length!
			my $fname = $in_file;
			my $ftag = "";
			if ($fname =~ /^.*\/(ruleslib\/[^\/]+)\.txt$/)
			{
				# this is a ruleslib file
				$ftag = $1;
			}
			else
			{
				$ftag = "rules";
			}
			
			if ($scope_name ne "")
			{
				$ftag .= " \{$scope_name\}";
			}
			
			$name = "$ftag $name";
			
			if ($type{$name})
			{
				$parse_error="($global_infile:$lineCount) name for rule '$name' is duplicated";
				error_report($debug, $parse_error, "");
				return $parse_error if ($debug != 3);
			}
			
			# we can now add the alarm severity rating if there is one
			if ($syslog_severity != 0)
			{
				$syslog_severity{$name}=$syslog_severity;
			}
			
			my $alarm_parse_msg;
			($rfAlarmStruct, $alarm_parse_msg) = parse_alarm($alarm);
			
			if ($alarm_parse_msg ne "ok")
			{
				$parse_error="($global_infile:$lineCount) alarm type is not understood ($alarm_parse_msg)";
				error_report($debug, $parse_error, "");
				$error_report{$name} = $alarm_parse_msg;
				return $parse_error if ($debug != 3);
				next LINE;
			}
			
			
			# and now we can start the process of checking
			
			
			# if we are called by 'configure.pl' then debug will be
			# set to 9 and we can print to terminal
			if ($debug == 9)
			{
				print "Processing rule $name\n";
				print "\t-> value = '$value'\n";
				print "\t-> constraint = '$constraint'\n";
				print "\t-> alarm = '$alarm'\n";
			}
				
			# now we know we have a valid rule name, on with the rest of the parsing
			
			
			if ($onceonly && $onceuntilfail)
			{
				$parse_error="($global_infile:$lineCount) cannot have once-only and once-until-fail in same rule $name";
				error_report($debug, $parse_error, "");
				return $parse_error if ($debug != 3);
			}
			
			$once_only{$name} = 1 if ($onceonly);
			$once_until_fail{$name} = 1 if ($onceuntilfail);
			
			if (@if_and_list != ())
			{
				# we need to push the ftag onto the name list
				foreach my $name_count (0..$#if_and_list)
				{
					
					$if_and_list[$name_count] = "$ftag $if_and_list[$name_count]";
				}
				# we have an if pragma
				$if_and_condition{$name} = \@if_and_list;
			}
			
			if (@if_or_list != ())
			{
				foreach my $name_count (0..$#if_or_list)
				{
					$if_or_list[$name_count] = "$ftag $if_or_list[$name_count]";
				}
				# we have an if pragma
				$if_or_condition{$name} = \@if_or_list;
			}
			
			if (@on_day_list != ())
			{ $onday{$name} = \@on_day_list;}
			
			if (@at_time_list != ())
			{ $attime{$name} = \@at_time_list;}
			
			if ($every_count>0)
			{
				if ($every_type eq '')
				{$every_condition{$name} = $every_count;}
				else
				{	my $seconds = $every_count;
					$seconds = $seconds * 60 if ($every_type eq 'm');
					$seconds = $seconds * 3600 if ($every_type eq 'h');
					$seconds = $seconds * 86400 if ($every_type eq 'd');
					$everyat_condition{$name} = $seconds;
				}
			}
			
			if ($initial_count>0)
			{
				$initial_condition{$name} = 1;
			}
			
			if ($cycle_count>0)
			{
				$cycle_condition{$name} = $cycle_count;
			}
			
			if ($throttle_count > 0)
			{
				$throttle_condition{$name} = $throttle_count;
			}
			
			#print "Parsing rule $in_line\n";
			#dump_inscope_details();
			
			
			
			if ($value =~ /^command$/i)
			{
				$parse_error = parse_command($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			if ($value =~ /^true$/i)
			{
				$parse_error = parse_true($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			if ($value =~ /^new service$/i)
			{
				$parse_error = parse_new_service($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			if ($value =~ /^status\s+(.*)$/i)
			{
				$parse_error = parse_status($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			if ($value =~ /^file change\s*->.*$/i)
			{
				$parse_error = parse_file_change($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			if ($value =~ /^file size\s*->.*$/i)
			{
				$parse_error = parse_file_size($debug, $name, $value, $constraint, $rfAlarmStruct) ;
				if ($parse_error ne "ok")
				{
					$error_report{$name} = $parse_error;
					error_report($debug, $parse_error, $name);
					return $parse_error if ($debug != 3);
				}
				else {push @order_list, $name ;}
				next LINE;
			}
			
			$parse_error = "($global_infile:$lineCount) Don't understand rule $name of type '$value'";
			error_report($debug, "($global_infile:$lineCount) Don't understand rule $name of type '$value'", $name);
			return $parse_error if ($debug != 3);
			
		}
	
		close(Config);
		# we will force a scope end here
		$in_scope = 0;
			$scope_name = "";
			
			# clear the ignores list for this scope
			%inscope_ignores = ();
			$inscope_ignores{'filechange'} = [];
			$inscope_ignores{'command'} = [];
			$inscope_ignores{'filesize'} = [];
			$inscope_ignores{'service'} = [];
			$inscope_ignores{'status'} = [];
			
			# clear the 'def's for this scope
			scope_delete_from_defs();
			
		return $parse_error;
	}


		
		


sub parse_command
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	
	$type{$name}="command";
	$value{$name}=0;

	# all commands need to be in single quotes
	if ($constraint !~ /^\".*\"$/)
	{ return "($global_infile:$lineCount) don't understand command in $value (no surrounding quotes?)";}
	else {$constraints{$name} = $constraint;}
	
	
	$alarm{$name}=$alarm;
	my $rfLigs=Storable::dclone(\%local_ignores);
	my $rfScp = Storable::dclone(\%inscope_ignores);
	my $rfMerged = merge($rfLigs, $rfScp);
	$ignore{$name} = $rfMerged;
	debug($debug, "name = $name $type{$name} $value{$name} $constraints{$name} $alarm{$name}");
	return "ok";

}

sub parse_status
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	my $filename;
	$constraints{$name} = "";
	
	if ($value =~ /status\s+(.*)/)
	{
		my $command=$1;
		
		if ($in_scope)
		{
			$command = '{'.$scope_name.'}'." $command";
		}
				
		if(!$alarm_execute_names{$command})
		{
			return "($global_infile:$lineCount) don't understand command '$command' in $value";
		}
		else
		{
			$value{$name}=$alarm_execute_names{$command};
			my @commands=@{$value{$name}};
			if ($#commands>0)
			{
				return "($global_infile:$lineCount) can only execute one command for status rule, '$command' has multiple commands in $value";
			}
			else
			{
				$value{$name}=$commands[0];
			}
		}
	}
	else
	{
		return "($global_infile:$lineCount) don't understand status command in $value";
	}
	
	if ($constraint =~ /^(?:none)|(?:baseline)$/)
	{
		$constraints{$name} = 'baseline' if ($constraint =~ /^baseline$/);
	}
		
	$type{$name}="status";
	$alarm{$name}=$alarm;
	
	return "ok";
}
	
sub parse_file_change
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	my $filename;
	$constraints{$name} = "";
	
	if ($value =~ /file change\s*->\s*(.+)/)
	{
		$filename=$1;
		$filename =~ s/\\/\//g;
	}
	else
	{
		return "($global_infile:$lineCount) don't understand filename in $value";
	}
		
	# we allow two constraints 'content' and 'acl'
	# and an optional 'not', giving us the possibilities
	# not acl, not content, content, acl, content acl, and not content acl
	

	if ($constraint =~ /not/i)
	{
			$constraints{$name} = "not ";
	}
	
	if ($constraint =~ /acl/i)
	{
			if ($constraint =~ /acl-a/i)
			{
				$constraints{$name} .= "acl-a ";
			}
			else
			{
				$constraints{$name} .= "acl ";
			}
	}
	
	if ($constraint =~ /new/i)
	{
			$constraints{$name} .= "new ";
	}
	
	if ($constraint =~ /deleted/i)
	{
			$constraints{$name} .= "deleted ";
	}
	
	if ($constraint =~ /content/i)
	{
			$constraints{$name} .= "content ";
	}
	
	if ($constraint =~ /recurse:\s*(\d+)/i)
	{
			$constraints{$name} .= "recurse:$1 ";
	}
	
	if ($constraints{$name} eq "")
	{
		return "($global_infile:$lineCount) don't understand file change constraint in $name ($constraint)";
	}
	
	my $checkcons = $constraint;
	$checkcons =~ s/not\s*//g;
	$checkcons =~ s/acl-a\s*//g;
	$checkcons =~ s/acl\s*//g;
	$checkcons =~ s/new\s*//g;
	$checkcons =~ s/deleted\s*//g;
	$checkcons =~ s/content\s*//g;
	$checkcons =~ s/recurse:\s*\d+//g;
	$checkcons =~ s/^\s*//;
	$checkcons =~ s/\s*$//;
	if ($checkcons =~ /[^\s]+/)
	{return "($global_infile:$lineCount) don't understand constraint in $name ($checkcons)";
		}
		
	
	
	$type{$name}="file change";
	$value{$name}=$filename;
	$alarm{$name}=$alarm;
	my $rfLigs=Storable::dclone(\%local_ignores);
	my $rfScp = Storable::dclone(\%inscope_ignores);
	my $rfMerged = merge($rfLigs, $rfScp);
	$ignore{$name} = $rfMerged;
	debug($debug, "name = $name $type{$name} $value{$name} $constraints{$name} $alarm{$name}");
	return "ok";
}

sub parse_file_size
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	my $filename;
	
	if ($value =~ /file size\s*->\s*(.+)/)
	{
		$filename=$1;
		$filename =~ s/\\/\//g;
		
	}
	else
	{
		return "($global_infile:$lineCount) don't understand filename in $value";
	}
	
	my $filesize;
	if ($constraint =~ />\s*(\d+)k?/)
	{
		$filesize	= $1;
	}
	else
	{
		return "($global_infile:$lineCount) don't understand file size in $constraint";
	}
	
	$type{$name}="file size";
	$value{$name}=$filename;
	$constraints{$name}=$filesize;
	$alarm{$name}=$alarm;
	my $rfLigs=Storable::dclone(\%local_ignores);
	my $rfScp = Storable::dclone(\%inscope_ignores);
	my $rfMerged = merge($rfLigs, $rfScp);
	$ignore{$name} = $rfMerged;
	debug($debug, "name = $name $type{$name} $value{$name} $constraints{$name} $alarm{$name}");
	return "ok";

}

sub parse_new_service
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	
	$type{$name}="new service";
	$value{$name}=0;
	if ($constraint !~ /(?:\s*ignore\:.*[A-Za-z]|\s*look\s*for\:.*[A-Za-z]|\s*none\s*)/i)
	{ return "($global_infile:$lineCount) don't understand new service constraint ($constraint) in $constraint";}
	my $checkcons = $constraint;
	
	$checkcons =~ s/\s*look\s*for\:.*[A-Za-z]\s*//g;
	$checkcons =~ s/\s*ignore\:.*[A-Za-z]\s*//g;
	$checkcons =~ s/none\s*//g;
	if ($checkcons =~ /[^\s]+/)
	{return "($global_infile:$lineCount) don't understand new service constraint ($checkcons) in $constraint";}
		
	$constraints{$name}=$constraint;
	$alarm{$name}=$alarm;
	my $rfLigs=Storable::dclone(\%local_ignores);
	my $rfScp = Storable::dclone(\%inscope_ignores);
	my $rfMerged = merge($rfLigs, $rfScp);
	$ignore{$name} = $rfMerged;
	debug($debug, "name = $name $type{$name} $value{$name} $constraints{$name} $alarm{$name}");
	return "ok";

}


sub parse_true
{
	my ($debug, $name, $value, $constraint, $alarm) = @_;
	my $partition;

	
	
	if ($constraint !~ /none/)
	{
		return "($global_infile:$lineCount) can't understand the TRUE rule constraint in $constraint";
	}
	
	
	$type{$name}="true";
	$value{$name}="none";
	$constraints{$name}="none";
	$alarm{$name}=$alarm;
	my $rfLigs=Storable::dclone(\%local_ignores);
	my $rfScp = Storable::dclone(\%inscope_ignores);
	my $rfMerged = merge($rfLigs, $rfScp);
	$ignore{$name} = $rfMerged;
	debug($debug, "name = $name $type{$name} $value{$name} $constraints{$name} $alarm{$name}");
	
	
	return "ok";
	
	
}

sub iflist_split
{
	my $to_split = shift;
	my @ret_list = ();
	my @to_split = split(/:/,$to_split);
	
	
	foreach my $name (@to_split)
	{
		$name =~ s/^\s*//;
		$name =~ s/\s*$//;
		push @ret_list, $name;
	}
	
	return @ret_list;
}
	
sub process_onday
{
	my $list = shift;
	my @results = ();
	
	my @days = split(/,| /, $list);
	foreach	my $day (@days)
	{
		$day =~ s/^\s+//;
		$day =~ s/\s+$//;
		$day = substr($day, 0, 3) if (($day !~ /^weekday$/i) && ($day !~ /^daily$/i));
		if ($day =~ /^daily$|^sun$|^mon$|^tue$|^wed$|^thu$|^fri$|^sat$|^sunday$|^monday$|^tuesday$|^wednesday$|^thursday$|^friday$|^saturday$/i)
		{
			$day =~ lc($day);
			push @results, $day;
		}
		if ($day =~ /^weekday$/i)
		{
			push @results, qw(mon tue wed thu fri);
		}
	}
	
	
	return @results;
}	

sub process_attime
{
	my $list = shift;
	my @results = ();
	
	my @times = split(/,/, $list);
	foreach	my $ntime (@times)
	{
		$ntime =~ s/^\s+//;
		$ntime =~ s/\s+$//;
		my ($start_time, $end_time) = split(/:/, $ntime);
		$start_time = (($start_time - ($start_time % 100))*0.6) + ($start_time % 100);
	  $end_time = (($end_time - ($end_time % 100))*0.6) + ($end_time % 100);
		if (
				($start_time >= 0) && ($start_time <= 1440)
				&&
				($end_time >=0) && ($end_time <= 1440)
			)
		{ push @results, "$start_time:$end_time";}
	}
	
	return @results;
}
		
sub error_report
{
	my $debug=shift;
	my $error=shift;
	my $name=shift; # we will undef any parsing on this name now!
	
	# print "ERROR: $error\n" if ($debug >0);
	push @allErrors, "$error";
	
	if ($name ne "")
	{
		delete $type{$name};
		delete $constraints{$name};
		delete $value{$name};
		delete $alarm{$name};
		delete $once_until_fail{$name};
		delete $once_only{$name};
		delete $every_condition{$name};
		delete $cycle_condition{$name};
		delete $if_and_condition{$name};
		delete $if_or_condition{$name};
		
	}
}

sub debug
{
	my $debug=shift;
	my $message=shift;
	print "DEBUG: $message\n" if ($debug==1);
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

sub parse_alarm
{
	my $alarm_string = shift;
	my %return_alarms = [];
	$return_alarms{'email'} = [];
	$return_alarms{'sms'} = [];
	$return_alarms{'execute'} = [];
	
	
	my $return_msg = "ok";
	
	# start by cleaning up the input
	$alarm_string =~ s/\s{2,}/ /g; # all whitespace>1 will be replace by a space
	my @all_alarms = split(/,/, $alarm_string);
	
	ALARM: foreach my $new_alarm (@all_alarms)
	{
		if ($new_alarm =~ /^\s*email\s*\((.*)\)\s*$/i)
		{
			# print "Processing email alarm of '$new_alarm'\n" if ($debug);
			my $key = $1;
			$key=~s/^\s+//; $key=~s/\s+$//;
			if ($key =~ /^\[([^\]]+)\]$/)
			{
				# a value from the master config is needed
				my $refKey=$1;
				if ($rfConfig->{$refKey})
				{ push @{$return_alarms{'email'}}, $rfConfig->{$refKey};}
				else
				{ return (\%return_alarms, "can't find master config parameter '$refKey'");}
			}
			
			else
			{	
			if ($key =~ /\@/)
			{
				push @{$return_alarms{'email'}}, $key;
			}
			else
			{
				# print "Looking for key '$key'\n"  if ($debug);
				if ($in_scope ne "")
				{
					my $scope_groupname = '{'.$scope_name.'}'." $key";
				
					if ($alarm_email_names{$scope_groupname})
					{
						push @{$return_alarms{'email'}}, @{$alarm_email_names{$scope_groupname}};
						# print "Adding '@{$alarm_email_names{$key}}' to alarm group if ($debug)";
						next ALARM;
					}
				}
					
						if ($alarm_email_names{$key})
						{
						push @{$return_alarms{'email'}}, @{$alarm_email_names{$key}};
						# print "Adding '@{$alarm_email_names{$key}}' to alarm group if ($debug)";
						next ALARM;
						}
						else
						{
							return (\%return_alarms, "can't find email group '$key'");
						}
					}
				}
				next ALARM;
				# FINISHED HERE
			}
			
		
		
		if ($new_alarm =~ /^\s*execute\s*\((.*)\)\s*$/i)
		{
			my $key = $1;
			if ($in_scope ne "")
				{
					my $scope_groupname = '{'.$scope_name.'}'." $key";
					if ($alarm_execute_names{$scope_groupname})
					{
						push @{$return_alarms{'execute'}}, @{$alarm_execute_names{$scope_groupname}};
						next ALARM;
					}
				}
					
						if ($alarm_execute_names{$key})
						{
							push @{$return_alarms{'execute'}}, @{$alarm_execute_names{$key}};
						}
						else
						{
						return (\%return_alarms, "can't find execute command '$key'");
						}
					next ALARM;
		}	
		
		if ($new_alarm =~ /^\s*sms\s*\((.*)\)\s*$/i)
		{
			# print "Processing sms alarm of '$new_alarm'\n" if ($debug);
			my $key = $1;
			
			
			if ($key =~ /^[0-9\+ ]+$/)
			{
				my $num = $key;
				
				$num =~ s/ //g;
				
				push @{$return_alarms{'sms'}}, $num;
			}
			else
			{
				if ($in_scope ne "")
				{
					my $scope_groupname = '{'.$scope_name.'}'." $key";
					if ($alarm_sms_names{$scope_groupname})
					{
						push @{$return_alarms{'sms'}}, @{$alarm_sms_names{$scope_groupname}};
						next ALARM;
					}
				}
				# print "looking for '$key' is sms names\n" if ($debug);
				if ($alarm_sms_names{$key})
				{
					push @{$return_alarms{'sms'}}, @{$alarm_sms_names{$key}};
				}
				else
				{
					# print "didn't find sms name \n";
					return (\%return_alarms, "can't find sms group '$key'") if ($debug);
				}
			}
			next ALARM;
		}	
		
		
		
		if ($new_alarm !~ /^\s*none\s*$/i)
		{
			return (\%return_alarms, "don't understand $new_alarm");
		}
	}
	return (\%return_alarms, "ok");
}

sub process_defline
{
	my $defline = shift;
	my $scope = shift;
	
	my $return_msg = "ok";
	my $parsed_ok = 0;
	my @these_values = ();
	
	# print "Processing $defline\n" if ($debug);
	
	if ($defline =~ /^\s*email\s*($groupname_pattern+)\s*\(([^\)]+)\)\s*$/i)
	{
		# this is an email definition
		my $groupname = $1;
		my $found_emails = $2;
		$groupname =~ s/^\s+//;
		$groupname =~s/\s+$//;
		
		$groupname = '{'.$scope_name.'}'." $groupname" if ($scope_name ne "");
		
		if ($alarm_email_names{$groupname})
		{
			return "email group name $groupname already exists";
		}
		
		# print "$defline is an email group def for group = '$groupname' and emails='$found_emails'\n" if ($debug);
		foreach my $next_email (split(/,/,$found_emails))
		{
			$next_email =~ s/^\s+//;
			$next_email =~ s/\s+$//;
			
			if (($next_email !~ /\@/) && ($next_email !~ /\%administrator/))
			{
				return "email $next_email in $defline is not an email address";
			}
			else
			{
				push @these_values, $next_email;
			}
		}
		$alarm_email_names{$groupname} = \@these_values;
		
		# we need to remember those defs which are in signature scope
		$inscope_email_names{$groupname} = 1 if (($scope eq "local") && ($in_scope));
		
		$email_globals{$groupname} = 1 if ($scope eq "global");
		
		#print "I have defined emails for $groupname of:\n" if ($debug);
		foreach my $tmp (@{$alarm_email_names{$groupname}})
		{#print "\t'$tmp'\n" if ($debug);
			}
		
		return "ok";
	}
	
	if ($defline =~ /^\s*sms\s*($groupname_pattern+)\s*\(([^\)]+)\)\s*$/i)
	{
		# this is an sms definition
		my $groupname = $1;
		my $found_sms = $2;
		$groupname =~ s/^\s+//;
		$groupname =~s/\s+$//;
		$groupname = '{'.$scope_name.'}'." $groupname" if ($scope_name ne "");
		if ($alarm_sms_names{$groupname})
		{
			return "sms group name $groupname already exists";
		}
		
		# print "$defline is an sms group def for group = '$groupname' and sms='$found_sms'\n" if ($debug);
		foreach my $next_sms (split(/,/,$found_sms))
		{
			$next_sms =~ s/^\s+//;
			$next_sms =~ s/\s+$//;
			$next_sms =~ s/ //g;
			
			if ($next_sms !~ /^[0-9\+]+$/)
			{
				return "sms $next_sms in $defline is not an sms cell phone number" if ($debug);
			}
			else
			{
				push @these_values, $next_sms;
			}
		}
		$alarm_sms_names{$groupname} = \@these_values;
		$sms_globals{$groupname} = 1 if ($scope eq "global");
		
		# we need to remember those defs which are in signature scope
		$inscope_sms_names{$groupname} = 1 if (($scope eq "local") && ($in_scope));
		
		# print "I have defined sms for $groupname of:\n" if ($debug);
		foreach my $tmp (@{$alarm_sms_names{$groupname}})
		{# print "\t'$tmp'\n" if ($debug);
			}
		
		return "ok";
	}
	
	if ($defline =~ /^\s*execute\s*($groupname_pattern+)\s*\((.*)\)\s*$/i)
	{
		# this is an excute definition
		my $groupname = $1;
		my $found_execute = $2;
		# $found_execute =~ s/\//\\/g;
		
		$groupname =~ s/^\s+//;
		$groupname =~s/\s+$//;
		$groupname = '{'.$scope_name.'}'." $groupname" if ($scope_name ne "");
		if ($alarm_execute_names{$groupname})
		{
			return "execute command $groupname already exists";
		}
		
		# print "$defline is an execute command def for command = '$groupname' 
		# and execute='$found_execute'\n" if ($debug);
		
		push @these_values, $found_execute;
		
		$alarm_execute_names{$groupname} = \@these_values;
		$execute_globals{$groupname} = 1 if ($scope eq "global");
		# we need to remember those defs which are in signature scope
		$inscope_execute_names{$groupname} = 1 if (($scope eq "local") && ($in_scope));
		
		# print "I have defined execute for $groupname of:\n" if ($debug);
		foreach my $tmp (@{$alarm_execute_names{$groupname}})
		{# print "\t'$tmp'\n" if ($debug);
			}
		
		return "ok";
	}
	
	if ($defline =~ /^\s*string\s*($groupname_pattern+)\s*\((.*)\)\s*$/i)
	{
		# this is an excute definition
		my $groupname = $1;
		my $found_execute = $2;
		# $found_execute =~ s/\//\\/g;
		
		$groupname =~ s/^\s+//;
		$groupname =~s/\s+$//;
		$groupname = '{'.$scope_name.'}'." $groupname" if ($scope_name ne "");
		if ($alarm_string_names{$groupname})
		{
			return "string $groupname already exists";
		}
		
		# print "$defline is an execute command def for command = '$groupname' 
		# and execute='$found_execute'\n" if ($debug);
		
		$found_execute=~s/^\"//; $found_execute=~s/\"$//;
		
		$alarm_string_names{$groupname} = $found_execute;
		
		$string_globals{$groupname} = 1 if ($scope eq "global");
		# we need to remember those defs which are in signature scope
		$inscope_string_names{$groupname} = 1 if (($scope eq "local") && ($in_scope));
		
		# print "I have defined execute for $groupname of:\n" if ($debug);
		
		return "ok";
	}
	
}
	
sub get_install_path
{
	my $path = $main::install_path;
	$path =~ s/\\/\//g;
	return $path;
	
}

	
sub clear_locals
{
	my $filename = shift;
	
	clear_locals_by_ref(\%alarm_email_names, \%email_globals, $filename, "email");
	clear_locals_by_ref(\%alarm_sms_names, \%sms_globals, $filename,"sms");
	clear_locals_by_ref(\%alarm_execute_names, \%execute_globals, $filename, "execute");
	
}

sub clear_locals_by_ref
{
	my $rfName = shift;
	my $rfGlobals = shift;
	my $filename = shift;
	my $vartype = shift;
	
	foreach my $key (keys %$rfName)
	{
		if (!$rfGlobals->{$key})
		{
			delete $rfName->{$key};
			# print "$key in $filename for type $vartype is local - now deleting\n";
		}
		else
		{
			# print "$key in $filename for type $vartype is global - KEEPING\n";
		}
	}
	
	
}
	
sub process_ignoreline {
	my $line_in = shift;
	my $scope = shift;
	
	if ($line_in =~ /^\s*(.*)\s+\"(.*)\"\s*$/i)
	{
		
		my $ignore_type = $1;
		my $ignore_value = $2;
		$ignore_type =~ s/^\s+//;
		$ignore_value =~s/\s+$//;
		
		$ignore_type =~ tr/[A-Z]/[a-z]/;
		
		# print "Have ignore type of '$ignore_type' and ignore value of '$ignore_value' (scope=$scope)\n";
		
		if (
				($ignore_type ne "filechange")
				&&
				($ignore_type ne "filesize")
				&&
				($ignore_type ne "command")
				&&
				($ignore_type ne "service")
				)
		{
			return "don't understand ignore type '$ignore_type'";
		}
		
		
		push @{$global_ignores{$ignore_type}}, $ignore_value if ($scope eq "global");
		push @{$local_ignores{$ignore_type}}, $ignore_value if (($scope eq "local") && (!$in_scope));
		push @{$inscope_ignores{$ignore_type}}, $ignore_value if (($scope eq "local") && ($in_scope));
		
		
		
		#print "\nDUMPING LOCALS\n";
		#dump_locals(\%local_ignores);
		#print "\n\nDUMPING GLOBALS\n";
		#dump_locals(\%global_ignores);
		
		return "ok";
	}
	else
	{
		return "don't understand ignore definition '$line_in'";
	}
}
				
sub dump_locals
{
	return if ($check != 0);
	my $rfHash = shift;
	my %inhash = %$rfHash;
	
	my $rfFilechange=$inhash{'filechange'};
	my $rfFilesize=$inhash{'filesize'};
	my $rfUsers=$inhash{'users'};
	my $rfCommand=$inhash{'command'};
	my $rfService=$inhash{'service'};
	
	print "Filechanges:\n";
	foreach my $val (@$rfFilechange) {print "\t$val\n";}
	print "Filesize:\n";
	foreach my $val (@$rfFilesize) {print "\t$val\n";}
	print "Commands:\n";
	foreach my $val (@$rfCommand) {print "\t$val\n";}
	print "Service:\n";
	foreach my $val (@$rfService) {print "\t$val\n";}
	
	print "\n";
	
}	

# we need to be able to combine two ignore hashes
sub merge
{
	my $rfIgnores1 = shift;
	my $rfIgnores2 = shift;
	
	my %retHash = ();
	$retHash{'filechange'} = [];
	$retHash{'filesize'} = [];
	$retHash{'command'} = [];
	$retHash{'service'} = [];
	$retHash{'status'} = [];

	
	my @ignore_list = ();
	push @ignore_list, @{$rfIgnores1->{'filechange'}};
	push @ignore_list, @{$rfIgnores2->{'filechange'}};
	$retHash{'filechange'} = Storable::dclone(\@ignore_list);
	
	@ignore_list = ();
	push @ignore_list, @{$rfIgnores1->{'filesize'}};
	push @ignore_list, @{$rfIgnores2->{'filesize'}};
	$retHash{'filesize'} = Storable::dclone(\@ignore_list);
	
	@ignore_list = ();
	push @ignore_list, @{$rfIgnores1->{'command'}};
	push @ignore_list, @{$rfIgnores2->{'command'}};
	$retHash{'command'} = Storable::dclone(\@ignore_list);
	
	@ignore_list = ();
	push @ignore_list, @{$rfIgnores1->{'service'}};
	push @ignore_list, @{$rfIgnores2->{'service'}};
	$retHash{'service'} = Storable::dclone(\@ignore_list);
	
	@ignore_list = ();
	push @ignore_list, @{$rfIgnores1->{'status'}};
	push @ignore_list, @{$rfIgnores2->{'status'}};
	$retHash{'status'} = Storable::dclone(\@ignore_list);
	
	return \%retHash;
	
}

	
	
	
sub scope_delete_from_defs
{
	foreach my $key (keys %inscope_email_names)
	{
		delete $alarm_email_names{$key};
	}
	%inscope_email_names = ();
	
	foreach my $key (keys %inscope_sms_names)
	{
		delete $alarm_sms_names{$key};
	}
	%inscope_sms_names = ();
	
	foreach my $key (keys %inscope_execute_names)
	{
		delete $alarm_execute_names{$key};
	}
	%inscope_execute_names = ();
	
	
	
}

sub get_string_value
{
	my $string_name = shift;
	if ($scope_name ne '')
	{ $string_name = '{'.$scope_name.'}'." $string_name";}
	return $alarm_string_names{$string_name};
}	
		
sub dump_inscope_details
{
	return if ($check != 0);
	print "Defs in scope;\n";
	print "\tEmail\n";
	foreach my $groupname (keys %alarm_email_names)
	{
		print "\n\n$groupname, ";
		if ($email_globals{$groupname}) {print " [global]";} else {print " [local]";}
		if ($inscope_email_names{$groupname}) {print " [in sig scope]";}
		print "\n";
	}
	print "\tSMS\n";
	foreach my $groupname (keys %alarm_sms_names)
	{
		print "\n\n$groupname, ";
		if ($sms_globals{$groupname}) {print " [global]";} else {print " [local]";}
		if ($inscope_sms_names{$groupname}) {print " [in sig scope]";}
		print "\n";
	}
	print "\tExecute\n";
	foreach my $groupname (keys %alarm_execute_names)
	{
		print "\n\n$groupname, ";
		if ($execute_globals{$groupname}) {print " [global]";} else {print " [local]";}
		if ($inscope_execute_names{$groupname}) {print " [in sig scope]";}
		print "\n";
	}
	
	
	foreach my $ignore_type ('filesize', 'filechange', 'command', 'service')
	{
		
		my @globals = @{$global_ignores{$ignore_type}};
		my @locals = @{$local_ignores{$ignore_type}};
		my @sigs = @{$inscope_ignores{$ignore_type}};
		
		print "For type $ignore_type\n";
		
		print "\tIgnores in global scope;\n";
		print join("\n\t\t", @globals), "\n";
		
		print "\tIgnores in local scope;\n";
		print join("\n\t\t", @locals), "\n";
		
		print "\tIgnores in signature scope;\n";
		print join("\n\t\t", @sigs), "\n";
	}
		
}

	


1;

