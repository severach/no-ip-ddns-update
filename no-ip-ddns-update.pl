#!/usr/bin/perl

# TODO: Info about daemon user
# TODO: Should we make the log parsable with cut?
# TODO: ipv6 when no-ip makes the API for it
# TODO: Non root timers
# TODO: 25 day --debug-all just like pfSense

# Copyright (c) 2017, Chris Severance
# Copyright (c) 2013, Cathal Garvey. http://cgarvey.ie/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
######

# This script will update a list of no-ip.com dynamic DNS accounts
# using the credentials specified in the config file
#
# An optional IP address can be specified, without which
# the script will attempt to determine the WAN IP address
# automatically.
#
# Call script with no arguments to see usage help, and
# supported arguments.

# NOTHING TO CHANGE HERE!

# Other user written (and no-ip written) clients make a bunch of mistakes.

# Written in bash. Proper client support is complex which is hard in bash.
# No user/daemon mode
# Does not enforce chmod 600 for config with password
# Transmit account password unencrypted across Internet
#   Apparently even the no-ip DUC does this. Perl has full SSL support.
# Abuses service by not checking DNS first.
#   Apparently no-ip doesn't mind but many other services
#   do mind, so let's do it right!
# Not compatible with multiple hosts or groups.
# Clients do not self disable on errors as required by no-ip.
# Do not offer an IP Change history.
# Not package compatible.

# The previous version by CG also had some mistakes

# Forgot "use warnings"
# Didn't use Getopt::Long which made enhanced functionality clumsy and difficult to implement.
# Too many globals, poor scoping, unnecessary forward references.

# Sample user crontab line. Add --daemon for root or nobody
# */10 * * * * /usr/bin/perl /usr/bin/no-ip-ddns-update.pl --command 'update' --quiet

use strict;
use warnings;

$| = 1;

use LWP::UserAgent;
use HTTP::Request::Common;
use POSIX 'strftime';
use URI::Escape;
#use File::Spec;
use Socket;
use Getopt::Long qw(:config bundling no_ignore_case no_auto_abbrev no_getopt_compat no_permute require_order);
use Time::Local;
use Data::Dumper;

my $opt_Command=""; # see usage(). Packagers will find updateconfig useful for install scripts.
my $opt_IP="";      # to be used in place of learned IP or config IP_ADDRESS
my $opt_Debug=0;    # {0..2} from none to lots of debug output.
my $opt_DebugAll=0; # 0 to send only ip changes. 1 to send entire list to intentionally get nochg results. 1 restores original functionality and may be considered abuse.
my $opt_DebugResp=""; # Set to one of the no-ip responses to fake all requests returns with that response. Update are not sent to no-ip. This is used to test the state machine vars file with codes that are hard to get without triggering abuse.
my $opt_Quiet=0;    # Supress confirmation messages.
my $opt_Version=0;  # Print version and exit.
my $opt_Daemon=0;   # config files in /etc,/var for user with no homedir or root. Should be run as user as this needs no root capability.
my $opt_Destdir=""; # Temporary path for packaging. Only applies to --daemon paths
my $opt_Help="";    # Temporary path for packaging. Only applies to --daemon paths

GetOptions(
"command|c=s" => \$opt_Command, # Deprecated ARGV[1]
"ip=s"        => \$opt_IP,      # Deprecated ARGV[2]
"debug=i"     => \$opt_Debug,
"debug-all"   => \$opt_DebugAll,
"debug-resp=s"=> \$opt_DebugResp,
"quiet"       => \$opt_Quiet,
"version"     => \$opt_Version,
"daemon"      => \$opt_Daemon,
"destdir=s"   => \$opt_Destdir,
"help"        => \$opt_Help,
) or die("Error in command line arguments\n");

my $VERSION = "2.0.0";
if ($opt_Version) {
  print $VERSION,"\n";
  exit(0);
}

# Compatibility with old command lines
if (scalar @ARGV) {
  if (scalar @ARGV == 1) {
    ($opt_Command)=(@ARGV);
    printf STDERR ("use new command line option --command %s \n",$opt_Command);
  } elsif (scalar @ARGV == 2) {
    ($opt_Command,$opt_IP)=(@ARGV);
    printf STDERR ("use new command line options --command %s --ip %s\n",$opt_Command,$opt_IP);
  } else {
    die("Purpose of ".scalar @ARGV." command line args is unknown\n");
  }
}

sub usage {
  return "" if ($opt_Quiet);
  return <<EOF;
No-ip.com DDNS update script. See https://github.com/cgarvey/no-ip-ddns-update

Usage: $0 -c <command>

  <command> is required, and one of:
    createconfig - Creates an initial sample configuration file with supporting
                   comments.
    updateconfig - Create new clean config from existing config.
    update       - Updates the No-IP account with IP address from command line
                   or configuration file (cmd line takes precedence).
    updateforce  - Issues two updates to No-IP (to force it to recognise a
                   change. First with dummy IP in config file. Second with
                   real IP from command line, or config file.

  --ip <ip address> is optional, and is the IP address to update the No-IP domain
               with. If not specified, the config file must have IP_ADDRESS
EOF
}

if ($opt_Help) {
  print &usage();
  exit(0);
}

# Returns 1 for valid IP, 0 for not a valid ip
sub is_valid_ip {
  my ($arg_ip) = (@_);

  return 0 if (not defined( $arg_ip ));
  return 0 if (length($arg_ip)==0);

  my @matches = $arg_ip =~ m/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  return 0 if (scalar @matches != 4);

  my $match;
  foreach $match (@matches) {
    return 0 unless($match >= 0 and $match <= 255);
    #return 0 unless ($match >= 0 and $match <= 255 and $match !~ m/^0\d{1,2}$/);
  }

  return 1;
}

# http://stackoverflow.com/questions/7726514/how-to-convert-text-date-to-timestamp
sub get_time {
  my ($arg_date)=(@_); # 2011-10-23 11:35:00
  my ($year,$mon,$mday,$hour,$min,$sec) = split(/[-\s:]+/, $arg_date);
  return timelocal($sec,$min,$hour,$mday,$mon-1,$year);
}

# https://en.wikipedia.org/wiki/Hostname
sub is_valid_hostname {
  my ($host)=(@_);
  return 0 if (length($host)==0);
  return 0 if (substr($host,0,1) eq "." or substr($host,-1,1) eq ".");
  return 0 if (&is_valid_ip($host)); # 192.168.0.1 is not a valid dyndns hostname
  my $hosttr;
  foreach $hosttr (split(/\./,$host)) {
    return 0 if (length($hosttr)==0 or length($hosttr)>63);
    return 0 if (substr($hosttr,0,1) eq '-' or substr($hosttr,-1,1) eq '-');
    $hosttr =~ tr/-A-Za-z0-9//d;
    return 0 if (length($hosttr));
  }
  return 1;
}
sub test_valid_hostname {
  my $errors=0;
  foreach ("",".foo","bar.","-foo.bar","foo.bar-","foo..bar","_foo.bar"," foo.bar","192.168.1.1") {
    if (&is_valid_hostname($_)) {
      $errors++;
      printf("%s should not be a valid hostname\n",$_);
    }
  }
  die("test_valid_hostname: $errors errors\n") if ($errors);
}
&test_valid_hostname() if ($opt_Debug >= 1);

if (length($opt_IP) and not is_valid_ip($opt_IP)) {
  die("ERROR: Invalid format in IP address --ip ".$opt_IP."\nUse xxx.xxx.xxx.xxx notation (e.g. 192.168.1.1)\n\n" );
}

my %g_debug_resp=(
  "good"    => 200, # returns with multiple results
  "nochg"   => 200, # returns with multiple results
  "nohost"  => 200, # returns with multiple results
  "badauth" => 401, # This result code has been verified
  "badagent"=> 401,
  "!donator"=> 401,
  "abuse"   => 401,
  "911"     => 401,
);
if (length($opt_DebugResp) and not $g_debug_resp{$opt_DebugResp} ) {
  die("ERROR: Invalid --debug-resp Try ".join(",",sort(keys(%g_debug_resp)))."\n" );
}

my $g_agent = new LWP::UserAgent;
$g_agent->agent( "No-ip.com Dynamic DNS Updater; https://github.com/cgarvey/no-ip-ddns-update; Ver " . $VERSION );

my $g_logdate;
my $g_fhist;
my $g_path_hist;
# Sets the time. Always returns 1 in case you want to use this in a conditional
# $1: 1 to open the log, 0 to just get the time
sub hist_open {
  my ($arg_open)=(@_);
  if ($arg_open and not $g_fhist) {
    open($g_fhist,">>",$g_path_hist) or die("$!");
  }
  $g_logdate=strftime( '%Y-%m-%d %H:%M:%S', localtime );
  return 1;
}

# This records errors reportable to the fail file that aren't recorded in the vars file.
# These errors are temporary and will hopefully clear on the next run before getting reported by monitoring.
my $g_fail_errors=0;

# $1: IP from $g_cfg
# Returns choice between $g_cfg IP, $opt_IP, and the learned IP
# Returns "" if no IP can be obtained
sub choose_ip {
  my ($arg_ip)=(@_);
  # If --ip present, this overrides any IP in config file.
  if ( $opt_IP and $arg_ip ne $opt_IP ) {
    printf STDERR ("choose_ip: Changing ip from cfg %s to --ip %s\n",$arg_ip,$opt_IP) if ($opt_Debug >= 1 and $arg_ip);
    printf STDERR ("choose_ip: Choose --ip %s\n",$opt_IP) if ($opt_Debug >= 1 and not $arg_ip);
    $arg_ip = $opt_IP;
  } else {
    printf STDERR ("choose_ip: Choose config IP %s\n",$arg_ip) if ($opt_Debug >= 1 and $arg_ip);
  }

  # If we don't have a valid IP here (config file or cmd line arg), get it from web service.
  if ( not $arg_ip ) {
    my $req = new HTTP::Request( "GET",  "http://ip1.dynupdate.no-ip.com/" );
    my $resp = $g_agent->request( $req );

    if ( $resp->code == 200 and &is_valid_ip( $resp->content ) ) {
      $arg_ip = $resp->content;
      printf STDERR ("choose_ip: Retrieved current IP %s\n",$arg_ip) if ($opt_Debug >= 1);
    }
  }
  if ( not $arg_ip and &hist_open(1)) {
    my $v=sprintf("%s choose_ip: Failed to get IP address from the internet (and none was provided in config file or command line args).\n",$g_logdate);
    print STDERR ($v);
    printf $g_fhist ($v);
    $g_fail_errors++;
  } else {
    printf STDERR ("choose_ip: Using IP %s\n",$arg_ip ) if ($opt_Debug >= 1);
  }
  return $arg_ip;
}

use constant {
  TYPE_STRING  =>1,
  TYPE_NUMBER  =>2,
  TYPE_BOOLEAN =>3,
  TYPE_IP      =>4,
  TYPE_TYPE    =>0x7F, # This type is not for use in the table below
  TYPE_OPTIONAL=>0x80,
};
my %g_cfg_type=(
  "HOSTNAME"  => +TYPE_STRING,
  "USERNAME"  => +TYPE_STRING,
  "PASSWORD"  => +TYPE_STRING,
  "IP_ADDRESS"=> +TYPE_IP|+TYPE_OPTIONAL,
  "FORCE_DUMMY_IP_ADDRESS"=> +TYPE_IP|+TYPE_OPTIONAL,
  "HISTORY"   => +TYPE_BOOLEAN,
  "DEADTIME"  => +TYPE_NUMBER,
);
#print Dumper(\%g_cfg_type);
my %g_cfg=(
  "HOSTNAME"  =>"",
  "USERNAME"  =>"",
  "PASSWORD"  =>"",
  "IP_ADDRESS"=>"",
  "FORCE_DUMMY_IP_ADDRESS"=>"",
  "HISTORY"   =>0,
  "DEADTIME"  =>10,
);

if ($opt_Debug >= 1 and join(",",sort(keys(%g_cfg))) ne join(",",sort(keys(%g_cfg_type))) ) {
  die("Mismatch between %g_cfg_type and %g_cfg\n");
}

my $g_vars_dirty=0; # we must minimize the use of die() so dirty vars can be updated
my %g_vars;
sub set_g_vars {
  %g_vars=(
    "DISABLED"  =>0,
    "LASTSET"   =>"",
    "LASTSETFORCE"=>"",
    "TEMPDISABLED"=>"",
    # We intentionally make variables using the basename of the following variables to make them easy to match
    #"DISABLED:hostname"=>0, # example for individual hostnames
    #"LASTSET:hostname"  => "8.8.8.8,127.0.0.1,2017-02-26 23:59:00", # example for last set IP
  );
}

# $1 new IP from choose_ip
# $2 list of hosts from config file
# $3 0 to update hosts not matching $1, 1 to update all not disabled
# returns $1 with disabled and already updated hosts removed. Leading (:) are cleaned from group names
# returns "" if no hosts are to be updated.
# Returned hosts include the current IP address after a colon. Returned groups do not.
# Example return: host1.no-ip.com:127.0.0.1,group1,host2.no-ip.com:127.0.0.1
sub hosts_to_update {
  my ($arg_newip,$arg_hosts,$arg_updateall)=(@_);
  my $hoststoupdate=0;
  my $groupstoupdate=0;
  my %toupdate; # Hosts (not groups) marked for update in pass 0. Learned IP is included in a separate key.
  my @toupdate; # List of hosts and groups constructed in pass 1.
  my $pass;     # Two passes so we can ensure that the constructed host string is in the same order as the original.
  for($pass=0; $pass<=1; $pass++) {
    my $hg;
    foreach $hg (split(/,/,$arg_hosts)) {
      if (substr($hg,0,1) eq '!') {
        printf STDERR ("hosts_to_update-%u: %s Host/Group disabled\n",$pass,$hg) if ($opt_Debug >= 1 and $pass == 0);
      } elsif (substr($hg,0,1) eq ':') {
        if ($pass == 0) {
          printf STDERR ("hosts_to_update-%u: %s Group will be updated if other hosts found to update\n",$pass,$hg) if ($opt_Debug >= 1);
          $groupstoupdate++;
        } elsif ($hoststoupdate) {
          printf STDERR ("hosts_to_update-%u: %s Group queued for update\n",$pass,$hg) if ($opt_Debug >= 1);
          push(@toupdate,substr($hg,1));
        }
      } elsif ($g_vars{'DISABLED:'.$hg}) {
        if ($opt_Debug >= 1) {
          printf STDERR ("hosts_to_update-%u: %s host is disabled. Read history and see config file to enable\n",$pass,$hg);
        } else {
          printf STDERR ("%s host is disabled. Read history and see config file to enable\n",$hg);
        }
      } else { # no-ip does not require us to do this. Other services like dyndns do. It's the right way and enables a lot of functionality so we'll do it.
        if ($pass == 0) {
          my $ipn=inet_aton($hg); # inet_aton does DNS lookup. We guarantee it will do this by excluding actual IP addresses from the host list.
          if (not $ipn and &hist_open(1)) {
            # Deleting a host from the no-ip control panel should not shut down DNS updates to the remaining valid hosts.
            # We don't need to disable this host because we can't get abuse from too many DNS requests. Adding it back to no-ip after someone complains will immediately enable it.
            my $v=sprintf("%s hosts_to_update-%u: %s error lookup!\n",$g_logdate,$pass,$hg);
            printf STDERR ($v);
            printf $g_fhist ($v);
            $g_fail_errors++;
          } else {
            my $iph=inet_ntoa($ipn);
            if ($iph eq $arg_newip and not $arg_updateall) {
              printf STDERR ("hosts_to_update-%u: %s no change %s\n",$pass,$hg,$iph) if ($opt_Debug >= 1);
            } else {
              if ($g_vars{"LASTSET:".$hg}) {
                my ($prevhostfr,$prevhostto,$prevtime)=split(/,/,$g_vars{"LASTSET:".$hg});
                if ($prevhostfr eq $iph and $prevhostto eq $arg_newip and (my $dead=int(abs(time()-get_time($prevtime))/60)) < $g_cfg{"DEADTIME"}) {
                  printf STDERR ("hosts_to_update-%u: %s waiting %u minutes deadtime for ip changes from %s to %s to propogate\n",$pass,$hg,$g_cfg{"DEADTIME"}-$dead,$iph,$arg_newip) if ($opt_Debug >= 1);
                  $hg="";
                }
              }
              if ($hg) {
                printf STDERR ("hosts_to_update-%u: %s ip changes from %s to %s\n",$pass,$hg,$iph,$arg_newip) if ($opt_Debug >= 1);
                printf STDERR ("%s ip changes from %s to %s\n",$hg,$iph,$arg_newip) if ($opt_Debug == 0 and not $opt_Quiet);
                $toupdate{$hg}=1;
                $toupdate{$hg."-IP"}=$iph;
                $hoststoupdate++;
              }
            }
          }
        } elsif ($toupdate{$hg}) { # pass 1
          printf STDERR ("hosts_to_update-%u: %s queued for update\n",$pass,$hg) if ($opt_Debug >= 1);
          push(@toupdate,$hg.":".$toupdate{$hg."-IP"});
        }
      }
    }
    if ($hoststoupdate == 0) {
      @toupdate=(); # just in case errors above happened after a few got pushed in
      if ($opt_Debug >= 1) {
        printf STDERR ("hosts_to_update-%u: No hosts to update. %u groups were skipped\n",$pass,$groupstoupdate)
      } elsif (not $opt_Quiet) {
        print STDERR ("No hosts to update.\n");
      }
      last;
    }
  }
  printf STDERR ("hosts_to_update: Updating %s\n",join(",",@toupdate)) if ($opt_Debug >= 1 and scalar @toupdate);
  return join(",",@toupdate); # host names are blocked from containing commas
}

# Returns ($updates,$disables)
# If $updates == 0 all updates failed and you shouldn't try any more.
# if $disables != 0 some hosts have been disabled in $g_vars. You must hosts_to_update() again so the next update (if any) does not try to update the rejected hosts again.
# May modify $g_vars_dirty and $g_vars
sub sendUpdate {
  my ($arg_update_ip,$arg_hosts,$arg_username,$arg_password) = (@_);

  # Separate IPs from $arg_hosts and rebuild
  my @hosts=(); # @hosts, @prevhostips, and @responses must be the same order and count so we can shift them in sync except when @responses has only one result on error.
  my @prevhostips=(); # Will contain blanks for groups
  {
    my @arg_hosts=split(",",$arg_hosts);
    my $host;
    my $h;
    my $i;
    foreach $host (@arg_hosts) {
      ($h,$i)=split(/:/,$host);
      $i="" if (not $i);
      push(@hosts,$h);
      push(@prevhostips,$i);
      printf STDERR ("sendUpdate: Filter host/group %s %s:%s\n",$host,$h,$i) if ($opt_Debug>=2);
    }
    $arg_hosts=join(",",@hosts);
  }

  &hist_open(0);
  $g_vars{($opt_Command eq "updateforce")?"LASTSETFORCE":"LASTSET"}=$g_logdate;
  my $url=sprintf("https://dynupdate.no-ip.com/nic/update?myip=%s,&hostname=%s",uri_escape( $arg_update_ip ),uri_escape( $arg_hosts ));
  my $respcode=-1;
  my $respcontent="";
  if ($opt_DebugResp) {
    printf STDERR ("sendUpdate-fake: %s\n",$url) if ($opt_Debug>=1);
    # Here we manufacture results that look exactly like real results
    # http://www.noip.com/integrate/response
    $respcode=$g_debug_resp{$opt_DebugResp};
    if ($opt_DebugResp eq "good" or $opt_DebugResp eq "nochg") {
      $respcontent=($opt_DebugResp." ".$arg_update_ip."\n") x scalar @hosts;
    } elsif ($opt_DebugResp eq "nohost") { # 200 and multiple responses for good,nochg,nohost have been verified. You still get 200 even if every host is 'nohost'.
      $respcontent=("nohost\n") x scalar split(",",$arg_hosts); # To get this one specify a host we can't possibly update like www.no-ip.com
    } else { # Single response and 401 for badauth has been verified. The other ones are hard to get so we guess that they are the same.
      $respcontent=$opt_DebugResp."\n";
      #$respcode=401; $respcontent="badauth\n";
      #$respcode=401; $respcontent="badagent\n";
      #$respcode=401; $respcontent="!donator\n";
      #$respcode=401; $respcontent="abuse\n";
      #$respcode=401; $respcontent="911\n";
    }
  } else {
    printf STDERR ("sendUpdate-real: %s\n",$url) if ($opt_Debug>=1);
    my $req = new HTTP::Request( "GET", $url );
    $req->authorization_basic($arg_username,$arg_password );
    my $resp = $g_agent->request( $req );
    $respcode = $resp->code;
    $respcontent = $resp->content;
  }
  my @responses=split(/[\r\n]+/,$respcontent); # They say newline but will it always be true? Let's nuke \r just in case. perl discards the trailing \n

  printf STDERR ("sendUpdate: Response code %u count %u\n%s\n",$respcode,scalar @responses,$respcontent) if ($opt_Debug >= 1);
  if ( $respcode == 200 ) {
    if (scalar @responses != scalar @hosts and &hist_open(1) ) {
      my $v=sprintf("%s sendUpdate: Server returned incorrect number of reponses. Sent %u hosts, received %u responses\nHOSTS=%s\nResponse=%s\n",$g_logdate,scalar @hosts,scalar @responses,$arg_hosts,$respcontent);
      printf STDERR ($v);
      printf $g_fhist ($v);
    }
  } else {
    if (scalar @responses != 1 and &hist_open(1) ) {
      my $v=sprintf("%s sendUpdate: Server returned incorrect number of reponses. Sent %u hosts, received %u responses\nHOSTS=%s\nResponse=%s\n",$g_logdate,scalar @hosts,scalar @responses,$arg_hosts,$respcontent);
      printf STDERR ($v);
      printf $g_fhist ($v);
    }
  }
  my $rv_updates=0;
  my $rv_disables=0;
  my $host;
  my $prevhostip;
  my $respres;
  my $respip;
  my $resp;
  foreach $resp (@responses) {
    $host=shift(@hosts); # Using these destroys them.
    $prevhostip=shift(@prevhostips);
    ($respres,$respip)=split(/ /,$resp); # nochg 127.0.0.1
    $respip="" if (not $respip);
    printf STDERR ("sendUpdate: Split host %s response %s to res=%s ip=%s\n",$host,$resp,$respres,$respip) if ($opt_Debug >= 2);
    if ( (not $respip and ($respres eq "good" or $respres eq "nochg")) or ($respip and not ($respres eq "good" or $respres eq "nochg")) ) {
      &hist_open(1);
      my $v=sprintf("%s sendUpdate: error Server response for %s unexpected spacing: '%u/%s'\n",$g_logdate,$host,$respcode,$resp);
      printf $g_fhist ($v);
      print STDERR $v;
      next;
    }
    if (not $g_debug_resp{$respres} and &hist_open(1) ) {
      my $v=sprintf("%s sendUpdate: error Server response for %s didn't contain known response result: '%u/%s'\n",$g_logdate,$host,$respcode,$resp);
      printf $g_fhist ($v);
      print STDERR $v;
      next;
    }
    if ($g_debug_resp{$respres} != $respcode and &hist_open(1) ) {
      my $v=sprintf("%s sendUpdate: error Server response for %s is '%u/%s', expected code %u\n",$g_logdate,$host,$respcode,$resp,$g_debug_resp{$respres});
      printf $g_fhist ($v);
      print STDERR $v;
      next;
    }
    if ($respres eq "good" and &hist_open(1)) { # sure be nice if they would authoritatively report the previous IP rather than making me save the most recent inet_aton()
      my $v=sprintf("%s sendUpdate: %s %s, DNS hostname update from %s successful.\n",$g_logdate,$resp,$host,$prevhostip);
      printf $g_fhist ($v) if ($g_cfg{"HISTORY"});
      print STDERR $v if ($opt_Debug >= 1);
      $rv_updates++;
      if ($g_vars{"LASTSET:".$host}) {
        my ($prevhostfr,$prevhostto,$prevtime)=split(/,/,$g_vars{"LASTSET:".$host});
        if ($prevhostto eq $respip and abs(time() - &get_time($prevtime))<3600 and &hist_open(1)) {
          $v=sprintf("%s sendUpdate: %s %s was %s, disabled. IP address changed again within the last hour. Perhaps it is being updated by another no-ip client on a far away network.\n",$g_logdate,$resp,$host,$prevhostip);
          printf $g_fhist ($v);
          print STDERR $v if ($opt_Debug >= 1);
          $g_vars{"DISABLED:".$host}=1;
          $g_vars_dirty=1;
        }
      }
      $g_vars{"LASTSET:".$host}=$prevhostip.",".$respip.",".$g_logdate;
      $g_vars_dirty=1;
    } elsif ($respres eq "nochg") {
      if (not $opt_DebugAll and &hist_open(1)) {
        my $v=sprintf("%s sendUpdate: %s %s, disabled. IP address is current, no update performed. Perhaps it is being updated by another no-ip client on this network.\n",$g_logdate,$resp,$host);
        printf $g_fhist ($v);
        print STDERR $v if ($opt_Debug >= 1);
        $g_vars{"DISABLED:".$host}=1;
        $g_vars_dirty=1;
      } elsif ($opt_Debug >= 1 and &hist_open(1)) {
        my $v=sprintf("%s sendUpdate: %s %s, forced! IP address is current, no update performed. Host should be disabled. Perhaps it is being updated by another no-ip client on this network\n",$g_logdate,$resp,$host);
        printf $g_fhist ($v); # Fill the log with crap if they decide to do this.
        print STDERR $v;
      }
      $rv_disables++;
    } elsif ($respres eq "nohost" and &hist_open(1)) {
      my $v=sprintf("%s sendUpdate: %s %s, disabled. Hostname supplied does not exist under specified account.\n",$g_logdate,$resp,$host);
      printf $g_fhist ($v);
      print STDERR $v if ($opt_Debug >= 1);
      $g_vars{"DISABLED:".$host}=1;
      $g_vars_dirty=1;
      $rv_disables++;
    } elsif ( $respres eq "badauth" or $respres eq "badagent" or $respres eq "!donator" or $respres eq "abuse" ) {
      &hist_open(1);
      my $v=sprintf("%s sendUpdate: %s, global disabled. Invalid username password combination.\n",$g_logdate,$resp);
      printf $g_fhist ($v);
      print STDERR $v if ($opt_Debug >= 1);
      $g_vars{"DISABLED"}=1;
      $g_vars_dirty=1;
      $rv_updates=0; # just in case
    } elsif ( $respres eq "911" and &hist_open(1)) {
      my $v=sprintf("%s sendUpdate: %s, no-ip database error, updates disabled for 30 minutes.\n",$g_logdate,$resp);
      printf $g_fhist ($v);
      print STDERR $v if ($opt_Debug >= 1);
      $g_vars{"TEMPDISABLED"}="30,".$g_logdate;
      $g_vars_dirty=1;
      $rv_updates=0; # just in case
    } else {
      &hist_open(1);
      my $v=sprintf("%s sendUpdate: %s, unknown response.\n",$g_logdate,$resp);
      printf $g_fhist ($v);
      print STDERR $v if ($opt_Debug >= 1);
    }
  }
  return ($rv_updates,$rv_disables);
}

# $1: the config file name
# $2: 1 to bypass non fatal errors and corrections so we can write an update file without munging user data
# returns number of errors, 0 if everything went ok.
# We also construct a complete list of enabled hosts for use elsewhere
my %g_cfg_enabled_hosts;

sub read_cfg {
  my ($arg_conf,$arg_chmod_conf,$arg_update) = (@_);
  # Read config file
  if ( -r( $arg_conf ) ) {
    my @sb = stat( $arg_conf );
    my $mode = $sb[2] & 0777;
    if ($mode != oct($arg_chmod_conf)) {
      my $v=sprintf("read_cfg: %s contains a password. File mode %s %s\n",$arg_conf,$arg_update?"will be corrected to":"must be",$arg_chmod_conf);
      print STDERR ($v);
      if (not $arg_update and &hist_open(1)) {
        $g_fail_errors++;
        return 1;
      }
    }
  }
  if (not open( CONF, $arg_conf )) {
    printf STDERR ("read_cfg: Could not open the configuration file %s\nRun `%s %s-c createconfig` to create a sample conf file for you to change.\n",$arg_conf,"$0",$opt_Daemon?"--daemon ":"");
    $g_fail_errors++;
    return 0;
  }
  printf STDERR ("read_cfg: Reading %s\n",$arg_conf) if ($opt_Debug >= 1);
  my $errors=0; # I want all config errors to show at once rather than fix them one by one
  my $softerrors=0;
  my $line;
  my %cfgseen; # Allows us to detect what is missing from the file.
  my $type;
  while( $line = <CONF> ) {
    $line =~ s/[\r\n]//; # chomp()
    if ( $line =~ m/^([A-Z][A-Z_]+)=(.*)$/ ) {
      if ($opt_Debug >= 1) {
        my $data=$2;
        if ($opt_Debug <= 1) { # redact personal info from lines that might be posted to the Internet.
          if ($1 eq "PASSWORD" or $1 eq "USERNAME") {
            $data = "*" x length($data);
          } elsif ($1 eq "HOSTNAME") {
            $data =~ tr/-A-Za-z0-9/*/;
          } elsif ($1 eq "IP_ADDRESS") {
            $data =~ tr/0-9/*/;
          }
        }
        printf STDERR ("read_cfg: %s=%s\n",$1,$data);
      }
      if ( not exists $g_cfg{$1} ) {
        $softerrors++;
        printf STDERR ("read_cfg: '%s' unknown setting in the configuration file.\n",$1);
      } else {
        $g_cfg{$1}=$2;
        $cfgseen{$1}=1;

        $type = $g_cfg_type{$1};
        if ( length($2) == 0 ) {
          if ( not ($type & TYPE_OPTIONAL) ) {
            printf STDERR ("read_cfg: '%s' can not be empty in the configuration file.\n",$1);
            $softerrors++;
          }
        } else {
          $type &= TYPE_TYPE;
          if ($type eq TYPE_NUMBER) {
            my $tr = $2;
            $tr =~ tr/0123456789//d;
            if ( length($tr) ) {
              printf STDERR ("read_cfg: '%s' must be a number in the configuration file.\n",$1);
              $softerrors++;
              $g_cfg{$1} = 0 if (not $arg_update);
            }
            $g_cfg{$1} += 0 if (not $arg_update);
          } elsif ($type eq TYPE_BOOLEAN) {
            if ( not ($2 eq "0" or $2 eq "1") ) {
              printf STDERR ("read_cfg: '%s' must be 0 or 1 in the configuration file.\n",$1);
              $softerrors++;
              $g_cfg{$1} = 0 if (not $arg_update);
            }
            $g_cfg{$1} += 0 if (not $arg_update);
          } elsif ($type eq TYPE_IP) {
            if ( not &is_valid_ip( $2 ) ) {
              printf STDERR ("read_cfg: '%s' does not appear to be a valid numeric IP (e.g. 192.168.1.1)\n",$1);
              $softerrors++;
              $g_cfg{$1} = "" if (not $arg_update);
            }
          }
        }
      }
    }
  }
  close( CONF );
  print Dumper(\%g_cfg) if ($opt_Debug >= 2);
  #if ( $g_cfg{'USERNAME'} !~ /.*\@.*/ ) { print STDERR ("read_cfg: 'USERNAME' does not appear to be a valid email address.\n\n" ); }
  my $host;
  foreach $host (split(/,/,$g_cfg{'HOSTNAME'})) {
    if (length($host)==0) {
      print STDERR ("read_cfg: 'HOSTNAME' in config contains blank host, aka two commas in a row.\n");
      $softerrors++;
    } else {
      $g_cfg_enabled_hosts{$host}=1 if (substr($host,0,1) ne "!" and substr($host,0,1) ne ":");
      $host=substr($host,1) if (substr($host,0,1) eq "!"); # We require the disabled hosts to be valid
      if (substr($host,0,1) ne ":" and not is_valid_hostname($host)) {
        printf STDERR ("read_cfg: 'HOSTNAME' %s is not valid.\n",$host );
        $softerrors++;
      }
    }
  }
  foreach(sort(keys(%g_cfg))) { # Y'all don't get away with nuthin!
    if (not $cfgseen{$_}) {
      $softerrors++;
      printf STDERR ("read_cfg: '%s' is missing in config.\n",$_);
    }
  }
  printf STDERR ("read_cfg: Errors=%u, Soft Errors=%u, Update=%u\n",$errors,$softerrors,$arg_update) if ($opt_Debug >= 2);
  if ($arg_update) {
    $softerrors=0;
  }
  print Dumper(\%g_cfg_enabled_hosts) if ($opt_Debug >= 2);
  $g_fail_errors += $errors+$softerrors;
  return $errors+$softerrors;
}

sub read_vars {
  my ($arg_vars) = (@_);
  # To not open the vars file is not an error.
  set_g_vars();
  my $fvars;
  if (not open($fvars,"<", $arg_vars )) {
    printf STDERR ("read_vars: Could not open the vars file %s\n",$arg_vars) if ($opt_Debug >= 1);
    $g_vars_dirty=1;
    return 0;
  }
  printf STDERR ("read_vars: Reading %s\n",$arg_vars) if ($opt_Debug >= 1);
  my $line;
  my (@line,$lnvarorig,$lnvar,$lnsub,$lnval);
  while( $line = <$fvars> ) {
    $line =~ s/[\r\n]//; # chomp()
    @line = $line =~ m/^([A-Z][^=]+)=(.*)$/ ; # hostnames have a lot more 
    if (@line) {
      ($lnvarorig,$lnval)=(@line);
      printf STDERR ("read_vars: %s=%s\n",$lnvarorig,$lnval) if ($opt_Debug >= 1);
      $lnvar=$lnvarorig;
      $lnsub="";
      @line = $lnvar =~ m/^([^:]+):([^:]+)$/;
      if (@line) {
        ($lnvar,$lnsub)=(@line);
      }
      if ( not exists $g_vars{$lnvar} ) { # We only check the basename of the variable here.
        printf STDERR ("read_vars: '%s' unknown setting in the vars file.\n",$lnvar);
        $g_vars_dirty=1;
      } elsif ( $lnsub and not exists $g_cfg_enabled_hosts{$lnsub} ) {
        printf STDERR ("read_vars: '%s' unknown setting in the vars file.\n",$lnvar) if ($opt_Debug >= 1);
        $g_vars_dirty=1;
      } else {
        $g_vars{$lnvarorig}=$lnval;
      }
    }
  }
  close( $fvars );
  print Dumper(\%g_vars) if ($opt_Debug >= 2);
}

# Subtract basedir from a dir, for packaging.
# $1: basedir
# $2: entire dir including basedir at beginning. The removal is based on length so you'll get odd results if entiredir does not start with basedir
#   Double slashes are removed. Triple slashes are not my problem.
# Returns entiredir with basedir removed. The returned dir always begins with a slash so this is only expected to work properly with absolute paths.
sub dir_sub {
  my ($arg_basedir,$arg_entiredir)=(@_);
  if ($arg_basedir) {
    $arg_basedir =~ s/\/\//\//g;
    $arg_entiredir =~ s/\/\//\//g;
    $arg_basedir =~ s/\/+$//g; # remove trailing slashes
    if (length($arg_basedir) < length($arg_entiredir)) {
      return substr($arg_entiredir,length($arg_basedir));
    }
  }
  return $arg_entiredir;
}
#print dir_sub("foo/bar","foo/bar/baz"),"\n"; print dir_sub("foo/bar/","foo/bar/baz"),"\n"; die();
#print dir_sub("/foo/bar","/foo/bar/baz"),"\n"; print dir_sub("/foo/bar/","/foo/bar/baz"),"\n"; die();

sub gen_conf {
  my ($arg_chmod_conf,$arg_vars_dsub,$arg_hist_dsub,$arg_fail_dsub)=(@_);
  # Can't have the time in the conf file or packages will think that every version is different.
  return <<EOF;
# Sample configuration file for no-ip-ddns-update.

# Update the parameters below to match your No-IP.com account credentials.
# Due to the password, this file must be chmod $arg_chmod_conf or it will not be used.

# required
# List of hostnames and groups to update. Group names are indicated by a leading colon (:).
# A HOSTNAME consisting of only groups will not be updated.
# No group gets updated unless at least one host needs updating.
# Hosts and groups can be disabled with a leading exclamation (!).
# HOSTNAME=host1.domain.com,:group1,host2.domain.com,!disabled.domain.com,!:disabled.group
HOSTNAME=$g_cfg{'HOSTNAME'}

# required
# Your email address that you used to register
# on No-ip.com (and the one you login with).
# Your username also works.
#USERNAME=myemailaddress\@some.domain
#USERNAME=myusername
USERNAME=$g_cfg{'USERNAME'}

# required
# the one you use to login to No-ip.com.
PASSWORD=$g_cfg{'PASSWORD'}

# optional
# This is left blank for dynamic DNS updates. For static DNS updates
# specify IP here or on the command line.
# The format must be standard IPv4 dotted notation. E.g. 192.168.1.1
#IP_ADDRESS=192.168.1.100
IP_ADDRESS=$g_cfg{'IP_ADDRESS'}

# optional
# if blank, command 'updateforce' is non functional and will cause log error
# command 'updateforce' updates the no-ip account with this address first
# before updating with the real IP address. This should only be used
# if you notice your DNS is being disabled by no-ip because your ISP keeps
# you on the same IP address for too long. You should set HISTORY=1 below
# to help determine if this is happening.
# To use this you should run 'updateforce' every month or however long
# you decide from the IP change HISTORY.
# Some non-routable IP address is recommended, like 127.0.0.1.
FORCE_DUMMY_IP_ADDRESS=$g_cfg{'FORCE_DUMMY_IP_ADDRESS'}

# Set to 1 to save IP changes to log $arg_hist_dsub
# Errors are always saved to the log.
HISTORY=$g_cfg{'HISTORY'}

# Increase from 10 minutes if you get disabled because DNS updates are not propogating fast enough.
DEADTIME=$g_cfg{'DEADTIME'}

# To see if your DNS updates are disabled, see $arg_vars_dsub

# Set your monitoring app to $arg_fail_dsub
# If the file is 0-length, all is good.
# Otherwise it contains a 1 line message to be reported by monitoring.
EOF
}

# $arg_conf:           configuration file
# $arg_conf_write:     enable writing of configuration file
# $arg_conf_overwrite: enable overwriting of configuration file, usually because everything has already been read in.
# $arg_vars:           vars file
# $arg_vars_write:     enable writing of configuration file
# $arg_hist:           history log file
#   history log file is always written if it doesn't exist
# $g_cfg: hash of g_vars to write with default values or recently read values
sub gen_files {
  my ($arg_conf,$arg_chmod_conf,$arg_conf_write,$arg_conf_overwrite,$arg_chmod_other,$arg_vars,$arg_vars_write,$arg_hist,$arg_fail,$arg_fail_write) = (@_);
  my $arg_conf_dsub=&dir_sub($opt_Destdir,$arg_conf);
  my $arg_vars_dsub=&dir_sub($opt_Destdir,$arg_vars);
  my $arg_hist_dsub=&dir_sub($opt_Destdir,$arg_hist);
  my $arg_fail_dsub=&dir_sub($opt_Destdir,$arg_fail);
  my $logtime=strftime( '%Y-%m-%d %H:%M:%S', localtime );
  if ($arg_conf_write) {
    if ( not $arg_conf_overwrite and -r( $arg_conf ) ) {
      printf STDERR ("WARNING: Config file already exists (%s)\nI refuse to overwrite it! Remove the file if you want to re-create it.\n",$arg_conf);
    } else {
      my $fconf;
      if (not open( $fconf, ">" . $arg_conf )) {
        printf STDERR ("gen_files: Failed to write (%s). Are folder permissions OK?\n\n",$arg_conf );
      } else {
        printf STDERR ("gen_files: Writing %s\n",$arg_conf ) if ($opt_Debug >= 1);
        print $fconf &gen_conf($arg_chmod_conf,$arg_vars_dsub,$arg_fail_dsub,$arg_hist_dsub);
        close( $fconf );
        chmod(oct($arg_chmod_conf),$arg_conf);
        printf STDERR ("Configuration file created %s\nPlease update it to suit your needs.\n\n",$arg_conf ) if (not $opt_Quiet);
      }
    }
  }

  my $disabledhosts=0;
  if ($arg_vars_write) {
    my $fvars;
    if (not open( $fvars, ">" . $arg_vars )) {
      printf STDERR ("gen_files: Failed to write (%s). Are folder permissions OK?\n\n",$arg_vars );
    } else {
      printf STDERR ("gen_files: Writing %s\n",$arg_vars ) if ($opt_Debug >= 1);
      print $fvars <<EOF;
# vars file for no-ip-ddns-update. Created $logtime

# Warning: Do not add or remove lines. This file is rebuilt and overwritten constantly.

# 0: DNS updates not listed below are enabled.
# 1: all DNS updates are disabled. For reason see $arg_hist_dsub
# This setting will not disable automatically.
# Fix the problem then set to 0 to enable.
DISABLED=$g_vars{'DISABLED'}

# Don't change this value.
# It is not used for anything.
#LASTSET=8.8.8.8,2017-02-26 23:59:00
LASTSET=$g_vars{'LASTSET'}

# Don't change this value.
# It is not used for anything.
#LASTSETFORCE=8.8.8.8,2017-02-26 23:59:00
LASTSETFORCE=$g_vars{'LASTSETFORCE'}

# We use this to block updates after receiving a '911' response
# Don't change this value.
# It automatically goes out of date in a short time.
#TEMPDISABLED=30,2017-02-26 23:59:00
TEMPDISABLED=$g_vars{'TEMPDISABLED'}

# For maximum uptime these lines disable individual hosts so we can let other hosts continue.
# For reason see $arg_hist_dsub
# This setting will not disable automatically.
# Fix the problem then set to 0 to enable.
#DISABLED:hostname=1
EOF

      my @hostkeys=sort(keys(%g_cfg_enabled_hosts));
      my $key;
      my $key1;
      foreach $key (@hostkeys) {
        $key1="DISABLED:".$key;
        printf $fvars ("%s=%s\n",$key1,$g_vars{$key1}?1:0);
        $disabledhosts++ if ($g_vars{$key1});
      }

      print $fvars <<EOF;

# We use these values to detect if some other client is battling us for control of the host name
# or if we need to wait longer before deciding.
# Don't change this value.
#                 from   ,to       ,time
#LASTSET:hostname=8.8.8.8,127.0.0.1,2017-02-26 23:59:00
EOF

      foreach $key (@hostkeys) {
        $key1="LASTSET:".$key;
        printf $fvars ("%s=%s\n",$key1,$g_vars{$key1}?$g_vars{$key1}:"");
      }
      close( $fvars );
      chmod(oct($arg_chmod_other),$arg_vars);
    }
  } else { # This must run to keep $arg_fail updated
    my $key;
    foreach $key (keys(%g_cfg_enabled_hosts)) {
      $$g_fail_errors++ if ($g_vars{"DISABLED:".$key});
    }
  }

  if ( not -r( $arg_hist ) ) {
    my $fhist;
    if (not open( $fhist, ">" . $arg_hist )) {
      printf STDERR ("gen_files: Failed to write (%s). Are folder permissions OK?\n\n",$arg_hist );
    } else {
      printf STDERR ("gen_files: Writing %s\n",$arg_hist ) if ($opt_Debug >= 1);
      # Can't have the time in the hist file or packages will think that every version is different.
      print $fhist <<EOF;
# hist file for no-ip-ddns-update.
# Logs errors that may cause DDNS updates to be disabled.
# To enable IP change history set HISTORY=1 in $arg_conf_dsub
EOF
      close( $fhist );
      chmod(oct($arg_chmod_other),$arg_hist);
    }
  }

  # Provide a blank file for no problems or a one line message if there's a problem.
  if (open( my $ffail, ">" , $arg_fail )) {
    my $msg="";
    $msg .= sprintf(", %u %s disabled",$disabledhosts,($disabledhosts==1)?"host is":"hosts are") if ($disabledhosts);
    $msg .= ", all DDNS updates are disabled" if ($g_vars{'DISABLED'});
    $msg .= ", ".$g_fail_errors." general errors" if ($g_fail_errors);
    print $ffail substr($msg,2),"\n" if (length($msg));
    close($ffail);
    chmod(oct($arg_chmod_other),$arg_fail);
  }
  return 0;
}

sub check_vars_disabled {
  if ($g_vars{'DISABLED'}) {
    print STDERR ("Globally disabled. See config file to enable\n");
    return 1;
  }
  if ($g_vars{'TEMPDISABLED'}) {
    my ($min,$dt)=split(/,/,$g_vars{'TEMPDISABLED'});
    my $minpass=int(abs(time()-&get_time($dt))/60);
    if ($minpass < $min) {
      printf STDERR ("Disabled for %u more minutes\n",$min - $minpass) if (not $opt_Quiet);
      return 1;
    }
    $g_vars{'TEMPDISABLED'}="";
    $g_vars_dirty=1;
  }
  return 0;
}

sub main_update {
  my ($arg_conf,$arg_chmod_conf,$arg_vars)=(@_);
  my $rv=1;
  if ( $opt_Command eq "update" ) {
    if (&read_cfg($arg_conf,$arg_chmod_conf,0) == 0 ) {
      &read_vars($arg_vars);
      if (not check_vars_disabled()) {
        my $ip=&choose_ip($g_cfg{'IP_ADDRESS'});
        if ($ip) {
          my $hosts=&hosts_to_update($ip,$g_cfg{'HOSTNAME'},$opt_DebugAll);
          if ($hosts) {
            my ($updates,$disables) = &sendUpdate( $ip,$hosts, $g_cfg{'USERNAME'}, $g_cfg{'PASSWORD'} );
            $rv=0 if ($updates);
          } else {
            $rv=0; # To not have any hosts to update is not an error
          }
        }
      }
    }
  } elsif( $opt_Command eq "updateforce" ) {
    if (&read_cfg($arg_conf,$arg_chmod_conf,0) == 0) {
      &read_vars($arg_vars);
      if (not check_vars_disabled()) {
        if ( not $g_cfg{'FORCE_DUMMY_IP_ADDRESS'} and &hist_open(1)) {
          my $v="main_update: updateforce requires valid dummy IP address in config file.\n";
          printf $g_fhist ($v);
          print STDERR ($v);
          $g_vars{"DISABLED"}=1;
          $g_vars_dirty=1;
          return 1;
        }
        my $ip=&choose_ip($g_cfg{'IP_ADDRESS'});
        if ($ip) {
          if ( $g_cfg{'FORCE_DUMMY_IP_ADDRESS'} eq $ip and &hist_open(1)) {
            my $v=sprintf("%s main_update: Global disabled. Dummy IP and update IP cannot be the same %s.\n",$g_logdate,$ip);
            printf $g_fhist ($v);
            print STDERR ($v);
            $g_vars{"DISABLED"}=1;
            $g_vars_dirty=1;
            return 1;
          }
          my $hosts=&hosts_to_update($ip,$g_cfg{'HOSTNAME'},1);
          if ($hosts) {
            print STDERR ("Dummy Update:\n" ) if ($opt_Debug >= 1);
            my ($updates,$disables) = &sendUpdate( $g_cfg{'FORCE_DUMMY_IP_ADDRESS'},$hosts,$g_cfg{'USERNAME'}, $g_cfg{'PASSWORD'} );
            if ( $updates ) {
              if ($disables) {
                $hosts=&hosts_to_update($ip,$g_cfg{'HOSTNAME'},1);
              }
              if ($hosts) {
                print STDERR ("Sleeping...") if ($opt_Debug >= 1);
                sleep( $opt_DebugResp?1:10 ); # No reason to wait if faking responses
                print STDERR (" done.\n" ) if ($opt_Debug >= 1);
                print STDERR ("Real Update:\n" ) if ($opt_Debug >= 1);
                ($updates,$disables) = &sendUpdate( $ip, $hosts, $g_cfg{'USERNAME'}, $g_cfg{'PASSWORD'} );
                $rv=0 if ($updates);
              } else {
                $rv=0;
              }
            }
          } else {
            $rv=0; # To not have any hosts to update is not an error
          }
        }
      }
    }
  } else {
    printf STDERR ("main: Unsupported command %s\n\n%s",$opt_Command,&usage() );
  }
  return $rv;
}

# Handy packaging function
# Pretty much the same as install -dm or mkdir -pm
# $1: base dir. Don't try to create any folders this or below.
#   This is length based so you'll get odd results if this isn't exactly what $2 starts with.
# $2: the path, relative or absolute. Paths are forced if they end in a slash.
#   Accidental double slashes are cleaned from $1 and $2. Triple slashes? Don't know, don't care!
# $3: the chmod for the last path. This is always set even if the dir already exists.
#     all paths in the middle are chmod 0755 or not chmod at all if they already exist
# $4: set to 1 if passing a file name and the filename on the end should not be created as a dir
sub mkdir_pm {
  my ($arg_basedir,$arg_path,$arg_chmodlast,$arg_droplast)=(@_);
  if ($arg_path) {
    $arg_basedir =~ s/\/\//\//g;
    $arg_path =~ s/\/\//\//g;
    my @parts=split(/\//,$arg_path,-1);
    pop(@parts) if ($arg_droplast);
    my $curpath=(substr($arg_path,0,1) eq "/")?"/":"";
    foreach (@parts) {
      if ($_) {
        $curpath .= $_;
        if ($curpath and length($curpath) > length($arg_basedir)) {
          if (mkdir($curpath,0755)) {
            printf "mkdir '%s'\n",$curpath if (not $opt_Quiet);
          } else {
            printf "mkdir '%s' $!\n",$curpath if (not $opt_Quiet);
          }
        }
        $curpath .= "/";
      }
    }
    if (chmod($arg_chmodlast,$curpath) or $opt_Debug >= 1) {
      printf("chmod 0%o '%s'\n",$arg_chmodlast,$curpath) if (not $opt_Quiet);
    } else {
      printf("chmod 0%o '%s' $!\n",$arg_chmodlast,$curpath) if (not $opt_Quiet);
    }
  }
}
#mkdir_pm("","foo0",0775,0); mkdir_pm("","foo1//bar/baz",0775,0); mkdir_pm("","foo2/bar/baz/",0775,1); mkdir_pm("","foo3/bar/baz/do_not_create_this_file",0775,1); mkdir_pm("/fooy/","/fooy/bar/baz",0775,0); mkdir_pm("/fooz/bar","/fooz/bar/baz/",0775,0); die();

sub noip_status {
  my ($arg_title,$arg_conf,$arg_chmod_conf,$arg_vars,$arg_fail,$arg_hist)=(@_);
  my $rv=0;
  my $size= -s($arg_conf);
  if ( not $size) {
    printf("%s config not present %s\n",$arg_title,$arg_conf);
  } elsif ( $size == length(&gen_conf($arg_chmod_conf,$arg_vars,$arg_fail,$arg_hist)) ) {
    printf("%s config not configured %s\n",$arg_title,$arg_conf);
  } else {
    printf("%s config configured %s\n",$arg_title,$arg_conf);
    &read_vars($arg_vars);
    printf("  Last run: %s\n",strftime("%Y-%m-%d %H:%M:%S",localtime((stat($arg_fail))[9])));
    printf("  Global status: %s\n",$g_vars{'DISABLED'}?"disabled":"enabled");
    printf("  Last IP change: %s\n",$g_vars{'LASTSET'});
    my $failsize=-s($arg_fail);
    if (not defined $failsize) {
      print("  Monitoring status: not present\n");
    } elsif ($failsize == 0) {
      print("  Monitoring status: all good\n");
    } else {
      my $ffail;
      if (open($ffail,"<",$arg_fail)) {
        printf("  Monitoring status: %s",<$ffail>); # The monitor fail file ends with a \n
        close($ffail);
      }
    }
    # We can't count the normal way because we may not have access to the config file. We must trust that vars is current.
    my $key;
    my $disabled=0;
    foreach $key (keys(%g_vars)) {
      if ($g_vars{$key} and $key =~ m/^DISABLED:/ ) {
        $disabled++;
      }
    }
    printf("  Disabled hosts: %u\n",$disabled);
    #print Dumper(\%g_vars);
    $rv++;
  }
  return $rv;
}

sub main {
  #my( $path_vol, $path_dir, $path_script ) = File::Spec->splitpath(__FILE__);
  #my( $path_conf ) = $path_dir . "no-ip-ddns-update.conf";
  # These can't be set by command line or a standard run wouldn't know where to find the files. Use sed.
  my $chmod_conf="0660";
  my $chmod_other="0664";
  my $path_conf;
  my $path_vars;
  my $path_fail;
  my $path_hist;
  my $rv=1;
  {
    my $etc="/etc";    # Used with --daemon
    $path_conf=$opt_Destdir.$etc."/no-ip-ddns-update/conf";
    $path_vars=$opt_Destdir.$etc."/no-ip-ddns-update/vars";
    $path_fail=$opt_Destdir.$etc."/no-ip-ddns-update/fail";
    $path_hist=$opt_Destdir.$etc."/no-ip-ddns-update/log";

    my $user = glob("~")."/.no-ip-ddns-update";
    my $user_path_conf=$user.".conf";
    my $user_path_vars=$user.".vars";
    my $user_path_fail=$user.".fail";
    my $user_path_hist=$user.".log";
    my $user_chmod_conf="0600";

    if ($opt_Destdir) {
      $opt_Daemon=1;
      my $varlog="/var/log";
      my $path_histsym=$opt_Destdir.$varlog."/no-ip-ddns-update.log"; # must have symlink. If the log gets deleted from /var/log we won't be able to create it again.
      &mkdir_pm($opt_Destdir,$path_conf   ,0775,1); # Package installers can chown root:root or chown root:nobody
      &mkdir_pm($opt_Destdir,$path_histsym,0755,1);
      symlink(&dir_sub($opt_Destdir,$path_hist),$path_histsym); # no chown()
    } elsif (not $opt_Command and &noip_status("System",$path_conf,$chmod_conf,$path_vars,$path_fail,$path_hist) + &noip_status("User",$user_path_conf,$user_chmod_conf,$user_path_vars,$user_path_fail,$user_path_hist)) {
      $rv=0;
    } elsif (not $opt_Daemon) {
      $path_conf=$user_path_conf;
      $path_vars=$user_path_vars;
      $path_fail=$user_path_fail;
      $path_hist=$user_path_hist;
      $chmod_conf=$user_chmod_conf;
      $chmod_other="0644";
    }
  }
  $g_path_hist=$path_hist;
  &set_g_vars();

  if (not $rv) {
  } elsif ( not $opt_Command ) {
    # All but the config errors are recorded in the log file.
    # When the report comes in that DNS has failed, people will naturally run the program.
    # If any errors are shown we supress usage to keep from cluttering the screen.
    if (&read_cfg($path_conf,$chmod_conf,0) == 0) {
      print &usage();
    }
    &gen_files($path_conf,$chmod_conf,0,0,$chmod_other,$path_vars,0,$path_hist,$path_fail);
    $rv=0;
  } elsif ( $opt_Command eq "createconfig" ) {
    $rv= &gen_files($path_conf,$chmod_conf,1,0,$chmod_other,$path_vars,1,$path_hist,$path_fail);
    if (not $opt_Destdir) { # Packagers don't need this crap!
      &read_cfg($path_conf,$chmod_conf,0);
      &gen_files($path_conf,$chmod_conf,0,0,$chmod_other,$path_vars,0,$path_hist,$path_fail);
    }
  } elsif( $opt_Command eq "updateconfig" ) {
    if (not &read_cfg($path_conf,$chmod_conf,1)) {
      &read_vars($path_vars); # This ensures that $path_fail is maintained correctly
      $rv= &gen_files($path_conf,$chmod_conf,1,1,$chmod_other,$path_vars,0,$path_hist,$path_fail);
    }
  } else {
    $rv=&main_update($path_conf,$chmod_conf,$path_vars);
    &gen_files($path_conf,$chmod_conf,0,0,$chmod_other,$path_vars,$g_vars_dirty,$path_hist,$path_fail);
  }
  return $rv;
}

exit(main());
