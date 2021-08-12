
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

# the alarms package expects an alarm type ('text', 'html'), a list of
# hashes, each containing a tiggered alarm report, a list of recipients
# the server name, the sending IP SMTP relay server, and the reply address

use strict;
use Net::SMTP;
use MIME::Lite;


package sendalarms;

my @email_alarms;
my @recipients;
my $send_type;
my $smtp_relay;
my $reply_address;
my $server_name;
my $current_time;
my @html_lines;
my $alarm_type;
my $rfReports;
my $rfRecipients;
my $pale_green;
my $pspace;
my $sep;
my $rfStatus;
my $rfTrigger_count;
my $rfOnceOnly;
my $rfOnceUntilFail;
my $rfNotAllowed;
my $rfConfig;


my @rules_list;

my %first_link;

my $install_path;


# we will keep some information for repeated rule alarms
# becuase emails can get very large!
my %count_occurs;

sub send_alarms
{
	
	
	($alarm_type, $rfReports, $rfRecipients, $smtp_relay, $reply_address, $server_name) = @_;
	my @email_alarms_in = @$rfReports;
	@recipients = @$rfRecipients;
	
	# we will sort the email alarms by rule name
	@email_alarms = sort { $a->{name} cmp $b->{name} } @email_alarms_in;
	
	$current_time = convert_timestamp(time);
	@html_lines = ();
	$pale_green="#bbeebb";
	$pspace="===================================";
	$sep="----";
	
	%count_occurs = ();
	
	# add_to_log("Alarm type is $alarm_type");
	get_install_path();
	
	if ($alarm_type eq "html")
	{
		
	do_header();
	do_banner();
	do_summary();
	do_results();
	do_footer();
	foreach my $recipient (@recipients)
	{
		
		create_html_email($recipient) if ($recipient =~ /\@/);
	}
	}
	else
	{
	do_text_header();
	do_text_banner();
	do_text_summary();
	do_text_results();
	do_text_footer();
	foreach my $recipient (@recipients)
	{
		create_text_email($recipient)  if ($recipient =~ /\@/);
	}
	}
	
	return;
}

	
sub do_banner
{

push @html_lines,  "<p><br><p>";

push @html_lines,  '<p align="center"><center>';
	
	push @html_lines,  '<table border = "0" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="#ffffff" align="left"><img src="'."cid:danger.gif".'" align="left" hspace="3" vspace="3"><font face="Verdana" size="2" color="#000000">You are receiving this email because ';
	push @html_lines,  'the port80 serverM system is helping to protect your server <b>'.$server_name.'</b> from intrusion and unauthorised use. There has been ';
	push @html_lines,  'a recent intrusion detected... details follow.'; 
	push @html_lines,  '<br></td></tr></table>';
	
push @html_lines,  '<p align="center"><center>';
	
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="'.$pale_green.'" align="center"><font face="Verdana" size="+1" color="#000000">Intrusion report at  '.$current_time;
	
	push @html_lines,  '<br>';
	my $num_rules = $#email_alarms + 1;
	push @html_lines, $num_rules.' ';
	if ($num_rules > 1)
	{
		push @html_lines, 'rules have been triggered';
	}
	else
	{
		push @html_lines, 'rule has been triggered';
	}
	
	push @html_lines, '</td></tr></table>';
	
}

sub do_text_banner
{
push @html_lines, " ";
push @html_lines, "You are receiving this email because the port80 serverM system is helping to protect your server $server_name from intrusion and unauthorised use. There has been a recent intrusion attempt detected... details follow";
push @html_lines,  "$pspace";
push @html_lines, " ";
push @html_lines, "Intrusion report at  $current_time";


	my $num_rules = $#email_alarms + 1;
	
	if ($num_rules > 1)
	{
		push @html_lines, $num_rules.' rules have been triggered';
	}
	else
	{
		push @html_lines, $num_rules.' rule has been triggered';
	}
	
}

sub do_summary
{
	# we will print a list of those rules which have been triggered, and put a link
	# to the first one of each rule
	
	# count the occurrances of each rule first
	my %count_names = ();
	foreach my $alarmref (@email_alarms)
	{
		if (!$count_names{$alarmref->{name}})
		{
			$count_names{$alarmref->{name}}=1;	
		}
		else
		{
			$count_names{$alarmref->{name}}++;
		}
	}
	
	%first_link = ();
	my $linkCount = 1;
	
	push @html_lines,  '<p align="center"><center>';
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="2" width="90%">';	
	push @html_lines, '<tr>';
	
	push @html_lines, '<td bgcolor="#ccffcc" width="100%" colspan="4"><font face="Verdana" size="2">Triggered Rules Summary</font></td>';
	push @html_lines, '</tr>';
	
	foreach my $alarmref (@email_alarms)
	{
		if (!$first_link{$alarmref->{name}})
		{
			$first_link{$alarmref->{name}} = $linkCount;
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Name</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="51%"><font face="Verdana" size="1">';
			my $tag = "rule_$linkCount";
			push @html_lines, '<a href="#'.$tag.'">'.$alarmref->{name}."</a>";
			push @html_lines, '</font></td>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Occurred</font></td>';
	push @html_lines, '<td bgcolor="#ffffff" width="15%"><font face="Verdana" size="1">'.$count_names{$alarmref->{name}}.'</font></td>';
			push @html_lines, '</tr>';
			$linkCount++;
		}
	}
	push @html_lines, '</table>';		
}

sub do_text_summary
{
	# we will print a list of those rules which have been triggered, and put a link
	# to the first one of each rule
	
	# count the occurrances of each rule first
	my %count_names = ();
	my %first_link = ();
	
	foreach my $alarmref (@email_alarms)
	{
		if (!$count_names{$alarmref->{name}})
		{
			$count_names{$alarmref->{name}}=1;	
		}
		else
		{
			$count_names{$alarmref->{name}}++;
		}
	}
	
	push @html_lines,  "$pspace";
	push @html_lines, " ";
	push @html_lines, "Triggered Rules Summary";
	
	
	foreach my $alarmref (@email_alarms)
	{
		if (!$first_link{$alarmref->{name}})
		{
			$first_link{$alarmref->{name}} = 1;
			push @html_lines, "Name: $alarmref->{name}   Occurred: $count_names{$alarmref->{name}}";
		}
	}
		
}
	
sub do_results
{
	
foreach my $alarmref (@email_alarms)
{
	my $name = $alarmref->{'name'};
	my $type = $alarmref->{'type'};
	my $date = $alarmref->{'date'};
	my $details = $alarmref->{'details'};
	my $meta = $alarmref->{'meta'};
	my $count = $alarmref->{'count'};
	my $alarm = $alarmref->{'alarm'};
	my $data = $alarmref->{'data'};
	
	# we will put an anchor in if this is the first time this rule
	# appears in the report
	
	if (!$count_occurs{$name}) {$count_occurs{$name}=0;}
	
	if ($count_occurs{$name} < 5)
	{
		
		if ($first_link{$name})
		{
			if ($first_link{$name} > 0)
			{
				my $tag = "rule_".$first_link{$name};
				$first_link{$name}=0;
				push @html_lines, '<a name="'.$tag.'">';
			}
		}
				
		push @html_lines,  "<p><br><p>";
		push @html_lines,  '<p align="center"><center>';
		push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="2" width="90%">';	
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Name</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="3"  width="51%"><font face="Verdana" size="1">'.$name.'</font></td>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Count</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" width="15%"><font face="Verdana" size="1">'.$count.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Time</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="3"  width="51%"><font face="Verdana" size="1">'.$date.'</font></td>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Type</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" width="15%"><font face="Verdana" size="1">'.$type.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Rule details</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="5" width="83%"><font face="Verdana" size="1">'.$details.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Information</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="5" width="83%"><font face="Verdana" size="1">'.$data.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Alarm type</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="5" width="83%"><font face="Verdana" size="1">'.$alarm.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '<tr>';
		push @html_lines, '<td bgcolor="'.$pale_green.'" width="17%"><font face="Verdana" size="2">Constraints</font></td>';
		push @html_lines, '<td bgcolor="#ffffff" colspan="5" width="83%"><font face="Verdana" size="1">'.$meta.'</font></td>';
		push @html_lines, '</tr>';
		
		push @html_lines, '</table>';
		
		push @html_lines,  "<p><br><p>";
		$count_occurs{$name}+=1;
	}
	
}
}

sub do_text_results
{
	push @html_lines,  "$pspace";
	push @html_lines, " ";
		push @html_lines, "Rules Triggered";
		
	foreach my $alarmref (@email_alarms)
	{
		
			my $name = $alarmref->{'name'};
			my $type = $alarmref->{'type'};
			my $date = $alarmref->{'date'};
			my $details = $alarmref->{'details'};
			my $meta = $alarmref->{'meta'};
			my $count = $alarmref->{'count'};
			my $alarm = $alarmref->{'alarm'};
			my $data = $alarmref->{'data'};
			
			if (!$count_occurs{$name}) {$count_occurs{$name}=0;}
			
			if ($count_occurs{$name}< 5)
			{
		
			push @html_lines, " ";
			push @html_lines, "Name: $name";
			push @html_lines, "Count: $count";
			push @html_lines, "Time: $date";
			push @html_lines, "Type: $type";
			push @html_lines, "Rule specification: $details";
			push @html_lines, "Data: $data";
			push @html_lines, "Alarm: $alarm";
			push @html_lines, "Constraints: $meta";
			
			push @html_lines, " ";
			push @html_lines, "$sep";
			$count_occurs{$name} += 1;
		}
		
	}
}

sub do_header
{

# push @html_lines,  "Content-Type: text/html\n\n";

# push @html_lines,  '<html>
#push @html_lines, '<head>
# <title>port80.com : serverM Intrusion Detection Report</title>';

push @html_lines, '

<body bgcolor="#ffffff" MARGINWIDTH="0" MARGINHEIGHT="0" LEFTMARGIN="0" TOPMARGIN="0" RIGHTMARGIN="0" BOTTOMMARGIN="0" LINK="#339933">';
}

sub do_footer
{
	
push @html_lines,  "<p><br><p>";

push @html_lines,  '<p align="center"><center>';
	
	
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="'.$pale_green.'" align="center"><font face="Verdana" size="2" color="#000000">';
	push @html_lines, 'End of intrusion report<br>For more information on the serverM intrusion detection system see the
	 website at <a href="http://www.port80.com/serverM">www.port80.com/serverM</a>';
	
	push @html_lines,  '<br>';
	
	
	push @html_lines, '</td></tr></table>';
	push @html_lines,  "<p><br><p>";

push @html_lines,  '</body>';

}

sub do_text_header
{


}

sub do_text_footer
{
	
push @html_lines,  "$pspace";
		push @html_lines, "Further Information...";
		push @html_lines, " ";
	
	push @html_lines, 'End of intrusion report. For more information on the serverM intrusion detection system see the website at http://www.port80.com/serverM';
	push @html_lines, " ";
	push @html_lines, " ";

}


sub lastMidnight
{
	
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	# ok, let's get the first second of today
	$sec = 0; $min = 0; $hour = 0; # that's the previous midnight!
	my $midnight = timegm($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
	
	return $midnight;
}

sub convert_timestamp
{
    my $intime = shift;
	my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($intime);
	$year+=1900;
	my $monName = (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec))[$mon];
	my $dayName = (qw(Sun Mon Tue Wed Thu Fri Sat))[$wday];
	
	if ($sec<10) {$sec="0$sec";}
	if ($min<10) {$min="0$min";}
	if ($hour<10) {$hour="0$hour";}
	
	return "$dayName $mday $monName $year : $hour:$min:$sec";

}

sub create_html_email
{
my $to_address = shift;


my $subject = 'Intrusion detected by serverM on server '.$server_name;
# add_to_log("Info: sending email alarm to $to_address");

my $msg = MIME::Lite->new(
                 To      =>$to_address,
                 From 	 =>$reply_address,
                 Subject =>$subject,
                 Type    =>'multipart/related'
                 );
    $msg->attach(Type => 'text/html',
                 Data => \@html_lines
                 );
    $msg->attach(Type => 'image/gif',
                 Id   => 'danger.gif',
                 Path => "$install_path/docs/danger.gif",
                 );
   eval {MIME::Lite->send('smtp', $smtp_relay);	$msg->send() or die "Error sending message: $!\n"};
   if ($@)
   {
   	main::add_to_log("error","can't send html email alarm to $to_address ($@)",0);
   }
   else
   {
   	main::add_to_log("info","email alarm sent to $to_address",0);
   }

}

sub create_text_email
{
my $to_address = shift;

my @text_lines = ();
foreach my $line (@html_lines)
{
	push @text_lines, $line;
	push @text_lines, "\r\n";
}


my $subject = 'Intrusion detected by serverM on server '.$server_name;


my $msg = MIME::Lite->new(
                 To      =>$to_address,
                 From 	 =>$reply_address,
                 Subject =>$subject,
                 Type    =>'TEXT',
                 Data => \@text_lines
                 );
    
  eval{MIME::Lite->send('smtp', $smtp_relay);	$msg->send() or die "Error sending message: $!\n"};
  if ($@)
  {
  	main::add_to_log("error","can't send email alarm to $to_address ($@)",0);
  }
  else
  {
  	main::add_to_log("error","Info: email alarm sent to $to_address",0);
   }

}


		

# the send_daily_report routine will create and send the daily
# report based on the requested format.
# The routine expects to see certain data

# machine name (scalar)

# HASH with
# lastsms -> last sms alarm
# lastalarm -> last email alarm
# startup -> startup time
# count -> cycle count

# current config hash

# trigger counts HASH
# list of current once only set rules
# list of current once until fail set rules


sub send_daily_report
{

	($alarm_type, $rfStatus, $rfTrigger_count, $rfOnceOnly, $rfOnceUntilFail, $rfNotAllowed, $rfConfig, $rfRecipients, $smtp_relay, $reply_address, $server_name) = @_;
	@recipients = @$rfRecipients;
	
	 @rules_list = sort keys %$rfTrigger_count;
	
	$pale_green="#bbeebb";
	$current_time = convert_timestamp(time);
	
	get_install_path();
	
	if ($alarm_type eq "html")
	{
		make_html_report();
		foreach my $recipient (@recipients)
			{
				send_html_report($recipient)  if ($recipient =~ /\@/);
			}
		
	}
	else
	{
		make_text_report();
		foreach my $recipient (@recipients)
			{
				send_text_report($recipient) if ($recipient =~ /\@/);
			}
	}
	return;
	
}

sub make_html_report
{

@html_lines = ();


push @html_lines, '<body bgcolor="#ffffff" MARGINWIDTH="0" MARGINHEIGHT="0" LEFTMARGIN="0" TOPMARGIN="0" RIGHTMARGIN="0" BOTTOMMARGIN="0" LINK="#339933">';

push @html_lines,  "<p><br><p>";

push @html_lines,  '<p align="center"><center>';
	
	push @html_lines,  '<table border = "0" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="#ffffff" align="left"><img src="'."cid:report.gif".'" align="left" hspace="3" vspace="3"><font face="Verdana" size="2" color="#000000">You are receiving this email because ';
	push @html_lines,  'you are a nominated email account to receive the daily reports from the port80 serverM system, which is helping to protect your server <b>'.$server_name.'</b> from intrusion and unauthorised use.';
	push @html_lines,  '<br></td></tr></table>';
	push @html_lines, "\n";
	
push @html_lines,  '<p align="center"><center>';
	
	push @html_lines, "\n";
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="'.$pale_green.'" align="center"><font face="Verdana" size="+1" color="#000000">Daily report at  '.$current_time;
	
	push @html_lines,  '<br>';
	push @html_lines, '</td></tr></table>';
	push @html_lines, "\n";
	
	# main content goes here
	
	# first the status
	push @html_lines,  '<p align="center"><center>';
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="2" width="90%">';	
	push @html_lines, '<tr>';
	
	push @html_lines, '<td bgcolor="#ccffcc" width="100%" colspan="2"><font face="Verdana" size="2">System Status Summary</font></td>';
	push @html_lines, '</tr>';
	push @html_lines, "\n";
	

			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Startup time:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{startup}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Check cycles executed:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{count}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Last SMS alarm sent:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{lastsms}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Last Email alarm sent:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{lastemail}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Last config change:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{lastconfig}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
			
			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">Last rules change:</font></td>';
			push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfStatus->{lastrules}.'</font></td>';
			push @html_lines, '</tr>';
			push @html_lines, "\n";
	
	push @html_lines, '</table>';
	push @html_lines, "\n";
	
 push @html_lines,  "<p><br><p>";
 
 # now for the rules information
 
 push @html_lines,  '<p align="center"><center>';
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="2" width="90%">';	
	push @html_lines, '<tr>';
	
	push @html_lines, '<td bgcolor="#ccffcc" width="100%" colspan="3"><font face="Verdana" size="2">Rules Status</font></td>';
	push @html_lines, '</tr>';

			push @html_lines, '<tr>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="60%"><font face="Verdana" size="1">Rule Name</font></td>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="15%"><font face="Verdana" size="1">Triggered</font></td>';
			push @html_lines, '<td bgcolor="'.$pale_green.'" width="25%"><font face="Verdana" size="1">Status</font></td>';
			push @html_lines, '</tr>';

			foreach my $rulename (@rules_list)
			{
				my $tcount = $rfTrigger_count->{$rulename};
				my $status = "live";
				if (is_in($rulename, $rfNotAllowed))
				{
					if ($rfOnceOnly->{$rulename})
					{
						$status = "disabled - once only";
					}
					if ($rfOnceUntilFail->{$rulename})
					{
						$status = "disabled - once until fail (awaiting failure)";
					}
				}
				push @html_lines, '<tr>';
				push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rulename.'</font></td>'; push @html_lines, "\n";
				push @html_lines, '<td bgcolor="#ffffff" width="15%"><font face="Verdana" size="1">'.$tcount.'</font></td>'; push @html_lines, "\n";
				push @html_lines, '<td bgcolor="#ffffff" width="25%"><font face="Verdana" size="1">'.$status.'</font></td>'; push @html_lines, "\n";
				push @html_lines, '</tr>'; push @html_lines, "\n";push @html_lines, "\n";
				push @html_lines, "\n";
			}
			push @html_lines, '</table>';
			push @html_lines, "\n";
	
 push @html_lines,  "<p><br><p>";
 push @html_lines, "\n";			
# we will also give the current configuration settings

push @html_lines,  '<p align="center"><center>';
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="2" width="90%">';	
	push @html_lines, '<tr>';
	
	push @html_lines, '<td bgcolor="#ccffcc" width="100%" colspan="2"><font face="Verdana" size="2">Current Configuration</font></td>';
	push @html_lines, '</tr>';
	push @html_lines, "\n";
	
	# need to convert daily-report-time back to 24 hour clock!
	my $reptime = $rfConfig->{'daily-report-time'};
	
	my $hourStart = ($reptime - ($reptime % 60)) / 60;
	my $minStart = $reptime - $hourStart * 60;
	$minStart = "0$minStart" if ($minStart < 10);
	$hourStart = "0$hourStart" if ($hourStart < 10);
	$rfConfig->{'daily-report-time'}="$hourStart$minStart";
											
											
											
	foreach my $value (sort keys %$rfConfig)
	{
		if ($value eq "alarm-sms")
		{
			my $rfValList = $rfConfig->{$value};
			my @val_list = @$rfValList;
			my $val_count=0;
			foreach my $val (@val_list)
			{
				$val_count++;
				push @html_lines, '<tr>';
				push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">alarm sms number '.$val_count.':</font></td>'; push @html_lines, "\n";
				push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$val.'</font></td>'; push @html_lines, "\n";
				push @html_lines, '</tr>';
				push @html_lines, "\n";
			}
			
		}
		else
		{
			if ($value eq "alarm-emails")
			{
				my $rfValList = $rfConfig->{$value};
				my @val_list = @$rfValList;
				my $val_count=0;
				foreach my $val (@val_list)
				{
					$val_count++;
					push @html_lines, '<tr>';
					push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">alarm email address '.$val_count.':</font></td>';
					push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$val.'</font></td>';
					push @html_lines, '</tr>';
				}
			}
			else
			{
				if ($value eq "daily-report-emails")
				{
					my $rfValList = $rfConfig->{$value};
					my @val_list = @$rfValList;
					my $val_count=0;
					foreach my $val (@val_list)
					{
						$val_count++;
						push @html_lines, '<tr>';
						push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">report email address '.$val_count.':</font></td>';
						push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$val.'</font></td>';
						push @html_lines, '</tr>';
						push @html_lines, "\n";
					}
				}
				else
				{
					if ($value eq "rlog")
					{
						my $valstring = $rfConfig->{$value};
						my ($ip, $port, $key) = split(/\,/,$valstring);
							push @html_lines, '<tr>';
							push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">rlog:</font></td>';
							push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'."Server=$ip, UDP port=$port".'</font></td>';
							push @html_lines, '</tr>';
							push @html_lines, "\n";
						
					}
					else
					{
						if ($value eq "user-defs")
						{
							my $rfValList = $rfConfig->{$value};
							my %val_list = %$rfValList;
							foreach my $val (keys %val_list)
							{
								push @html_lines, '<tr>';
								push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">user-def:</font></td>';
								push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$val.'</font></td>';
								push @html_lines, '</tr>';
								push @html_lines, "\n";
							}
							
						}
						else
						{
							push @html_lines, '<tr>';
							push @html_lines, '<td bgcolor="'.$pale_green.'" width="40%"><font face="Verdana" size="1">'.$value.':</font></td>';
							push @html_lines, '<td bgcolor="#ffffff" width="60%"><font face="Verdana" size="1">'.$rfConfig->{$value}.'</font></td>';
							push @html_lines, '</tr>';
							push @html_lines, "\n";
						}
					}
				}
			}
		}
	}
	
					
	push @html_lines, '</table>';
	
	
 push @html_lines,  "<p><br><p>";
 
# now for the footer etc.
push @html_lines,  '<p align="center"><center>';
	
	
	push @html_lines,  '<table border = "1" cellpadding="0" cellspacing="0" width="90%">';
	push @html_lines,  '<tr><td bgcolor="'.$pale_green.'" align="center"><font face="Verdana" size="2" color="#000000">';
	push @html_lines, 'End of daily report<br>For more information on the serverM intrusion detection system see the
	 website at <a href="http://www.port80.com/serverM">www.port80.com/serverM</a>';
	
	push @html_lines,  '<br>';
	
	
	push @html_lines, '</td></tr></table>';
	push @html_lines,  "<p><br><p>";

push @html_lines,  '</body>';
}

sub send_html_report
{
my $to_address = shift;


my $subject = 'Daily report for serverM on server '.$server_name;


my $msg = MIME::Lite->new(
                 To      =>$to_address,
                 From 	 =>$reply_address,
                 Subject =>$subject,
                 Type    =>'multipart/related'
                 );
    $msg->attach(Type => 'text/html',
                 Data => \@html_lines
                 );
    $msg->attach(Type => 'image/gif',
                 Id   => 'report.gif',
                 Path => "$install_path/docs/report.gif",
                 );
   
                 
  eval { MIME::Lite->send('smtp', $smtp_relay);
	$msg->send()};
	
	if ($@)
	{
		main::add_to_log("error","can't send daily report email to $to_address",0);
	}
	else
	{
		main::add_to_log("info","daily report sent to $to_address",0);
	}
	
}


sub make_text_report
{

$pspace="===================================";
$sep="----";
	
@html_lines = ();




push @html_lines,  ' ';
	
	push @html_lines, 'You are receiving this email because you are a nominated email account to receive the daily reports from the port80 serverM system, which is helping to protect your server '.$server_name.' from intrusion and unauthorised use.';
	push @html_lines, ' ';
	
	push @html_lines, "$pspace";
	push @html_lines, " ";
	
	push @html_lines,  'Daily report at  '.$current_time;
	
	push @html_lines, "$pspace";
	push @html_lines, " ";
	
	push @html_lines,  'System Status Summary';
	
	
	push @html_lines, "Startup time: $rfStatus->{startup}";
	
			push @html_lines, "Check cycles executed: $rfStatus->{count}";
			
			push @html_lines, "Last SMS alarm sent: $rfStatus->{lastsms}";
			push @html_lines, "Last Email alarm sent: $rfStatus->{lastemail}";
			push @html_lines, "Last config change: $rfStatus->{lastconfig}";
			push @html_lines, "Last rules change: $rfStatus->{lastrules}";
			
 
 # now for the rules information
 
 	push @html_lines, "$pspace";
	push @html_lines, " ";
	
	push @html_lines,  'Rules Status';
	

			foreach my $rulename (@rules_list)
			{
				my $tcount = $rfTrigger_count->{$rulename};
				my $status = "live";
				if (is_in($rulename, $rfNotAllowed))
				{
					if ($rfOnceOnly->{$rulename})
					{
						$status = "disabled - once only";
					}
					if ($rfOnceUntilFail->{$rulename})
					{
						$status = "disabled - once until fail (awaiting failure)";
					}
				}
				push @html_lines, "Rule name: $rulename";
				push @html_lines, "Occurred: $tcount";
				push @html_lines, "Rule status: $status";
				
				
			}
			
			
# we will also give the current configuration settings

	push @html_lines, "$pspace";
	push @html_lines, " ";
	
	push @html_lines,  'Current Config';
	
	
	
	# need to convert daily-report-time back to 24 hour clock!
	my $reptime = $rfConfig->{'daily-report-time'};
	
	my $hourStart = ($reptime - ($reptime % 60)) / 60;
	my $minStart = $reptime - $hourStart * 60;
	$minStart = "0$minStart" if ($minStart < 10);
	$hourStart = "0$hourStart" if ($hourStart < 10);
	$rfConfig->{'daily-report-time'}="$hourStart$minStart";
											
											
											
	foreach my $value (sort keys %$rfConfig)
	{
		if ($value eq "alarm-sms")
		{
			my $rfValList = $rfConfig->{$value};
			my @val_list = @$rfValList;
			my $val_count=0;
			foreach my $val (@val_list)
			{
				$val_count++;
				push @html_lines, "alarm sms number $val_count: $val";
				
			}
			
		}
		else
		{
			if ($value eq "alarm-emails")
			{
				my $rfValList = $rfConfig->{$value};
				my @val_list = @$rfValList;
				my $val_count=0;
				foreach my $val (@val_list)
				{
					$val_count++;
					push @html_lines, "alarm email address $val_count: $val";
					
				}
			}
			else
			{
				if ($value eq "daily-report-emails")
				{
					my $rfValList = $rfConfig->{$value};
					my @val_list = @$rfValList;
					my $val_count=0;
					foreach my $val (@val_list)
					{
						$val_count++;
						push @html_lines, "report email address $val_count: $val";
						
					}
				}
				else
				{
					push @html_lines, "$value: $rfConfig->{$value}";
					
				}
			}
		}
	}
	
	push @html_lines, "$pspace";
	push @html_lines, " ";
	
	push @html_lines,  "End of daily report. For more information on the serverM intrusion detection system see the website at http://www.port80.com/serverM";
	
	push @html_lines, " ";
	

}
sub is_in
{
	my $element = shift;
	my $rfList = shift;
	
	my %to_hash = map {$_ => 1} @$rfList;
	if ($to_hash{$element}) {return 1;}
	return 0;
}

sub send_text_report
{
my $to_address = shift;

my @text_lines = ();
foreach my $line (@html_lines)
{
	push @text_lines, $line;
	push @text_lines, "\r\n";
}


my $subject = 'Daily report for serverM on server '.$server_name;


my $msg = MIME::Lite->new(
                 To      =>$to_address,
                 From 	 =>$reply_address,
                 Subject =>$subject,
                 Type    =>'TEXT',
                 Data => \@text_lines
                 );
    
   eval{MIME::Lite->send('smtp', $smtp_relay);$msg->send() or die "Error sending message: $!\n"};
   if ($@)
   {
   		main::add_to_log("error","can't send daily report to $to_address ($@)",0);
   }
   else
   {
   		main::add_to_log("info","daily report sent to $to_address",0);
   }
}

sub get_install_path
{
	$install_path = $main::install_path;
	
	
	
}
1;
