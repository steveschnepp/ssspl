#!/usr/bin/perl
#sss.pl v0.1.4 (03/05/10)

use warnings; use strict;

=head1 NAME

Simple SOCKS5 Server for Perl

=head1 DESCRIPTION

SSS is a Simple SOCKS Server written in perl that implements the SOCKS v5 protocol.

It will accept username/password authentication.

The script runs in the background as a daemon.

=head2 HISTORY

Originally I was looking for a simple SOCKS5 Server (with user/pass auth) that
would run as a non-root user on FreeBSD.

I checked the FreeBSD ports for various SOCKS5 solutions and tried them all, 
only to discover that each one had a reason why it would not work, or why I 
could not use it.

I figured this could be done in perl, but found that there was no well 
maintained perl based solutions.

I hacked together this solution (with help from public domain scripts) and 
cleaned it up, ready for release.

Its simple, a feature I intend to maintain, however there is scope for much more
potential, especially with user feedback.

You can read the full story here:
  http://www.hm2k.com/posts/freebsd-socks-proxy-for-mirc

=head2 INSTALL

  wget http://ssspl.svn.sourceforge.net/viewvc/ssspl/sss.pl
  chmod 755 sss.pl

OR

  http://ssspl.svn.sourceforge.net/viewvc/ssspl.tar.gz?view=tar
  tar zxvf ssspl.tar.gz
  chmod 755 ssspl/sss.pl

=head2 USAGE

You run the script using the following command:
	./sss.pl <local_host> <local_port> [auth_login(:auth_pass)]
Note: the auth_pass must be an md5 (hex) hash
	eg: ./sss.pl hostname.example.com 34567 test:ae2b1fca515949e5d54fb22b8ed95575

Once up and running you can use the server in mIRC using the following command:
	/firewall [-cmN[+|-]d] [on|off] <server> <port> <userid> <password>
For more information on this command issue: /help /firewall in mIRC.
	eg: /firewall -m5 on hostname.example.com 34567 test testing

=head1 PREREQUISITES

Operating System: Tested on FreeBSD 6.x and CentOS 4.x, should work on others.

Required modules: C<IO::Socket::INET>, C<Digest::MD5>.

=head1 CHANGES
v0.1.4  (03/05/10)  - Improved documentation and logging subs
v0.1.3  (24/11/09)  - Improved documentation and code
                    - PID is displayed during fork
                    - Added logging (for Katlyn`)
v0.1.2  (27/02/09)  - Fixed a bug (Thanks Andreas)
v0.1.1  (02/10/08)  - Improved documentation
v0.1    (12/09/08)  - Initial release.

=head1 TODO
* Restrict IP access to the listening port <Reeve>
* Need a log format, see: http://en.wikipedia.org/wiki/Common_Log_Format
* Mozilla Firefox support/GSSAPI authentication support <OutCast3k, kingvis>
** See: http://forums.mozillazine.org/viewtopic.php?f=38&t=847655
** Alternative: http://blogs.techrepublic.com.com/security/?p=421
* IPv6 support
* BIND method
* UDP ASSOCIATE method
* pid file <mrakus>
* perl threads instead of fork()? <mrakus>

=head2 FAQ
* Why is there multiple processes in my process list?
** Each new connection spawns a new process, so it is easier to manage.
* Why does $serverip in mIRC return 255.255.255.255?
** 255.255.255.255 is the default value of a non-resolved address (INADDR_NONE).
** mIRC does not need to resolve the IRC server address.
** See: http://tinyurl.com/yjs8kyf
* Why is DCC SEND or DCC CHAT is not working?
** It should work, contact me to diagnose further.
** See: http://www.mirc.com/help/help-dcc.txt
* How do I create an md5 hash?
** In mIRC do: //echo -a $md5(password)
** You can visit: http://pajhome.org.uk/crypt/md5/
** I also added a -getmd5 option which you can use
* Why doesnt this work with Mozilla Firefox?
** Because Mozilla wont add SOCKS5 username/password auth support
** Because Ive not added GSSAPI support yet (donations please)

=head2 NOTES
* http://en.wikipedia.org/wiki/SOCKS
* http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
* http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4A.protocol
* http://tools.ietf.org/html/rfc1928
* http://tools.ietf.org/html/rfc1929
* http://tools.ietf.org/html/rfc1961
* http://tools.ietf.org/html/rfc3089
* http://tools.ietf.org/html/draft-ietf-aft-mcast-fw-traversal-01
* http://tools.ietf.org/html/draft-ietf-aft-socks-chap-01
* http://tools.ietf.org/html/draft-ietf-aft-socks-eap-00
* http://tools.ietf.org/html/draft-ietf-aft-socks-ext-00
* http://tools.ietf.org/html/draft-ietf-aft-socks-gssapi-revisions-01
* http://tools.ietf.org/html/draft-ietf-aft-socks-maf-01
* http://tools.ietf.org/html/draft-ietf-aft-socks-multiple-traversal-00
* http://tools.ietf.org/html/draft-ietf-aft-socks-pro-v5-04
* http://tools.ietf.org/html/draft-ietf-aft-socks-v6-req-00
* http://tools.ietf.org/html/draft-ietf-aft-socks-ssl-00
* http://www.iana.org/assignments/socks-methods
* http://developer.mozilla.org/index.php?title=En/Integrated_Authentication

=head1 COPYRIGHT

Copyright (c) 2008-2010, <a href="http://www.hm2k.com/">HM2K</a>. All rights reserved.

Released as Open Source under the BSD License.

=head1 LICENSE

Redistribution and use in source and binary forms, with or without modification, are 
permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this list of 
   conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list
   of conditions and the following disclaimer in the documentation and/or other
   materials provided with the distribution.
 * Neither the name of the author nor the names of its contributors may be used to 
   endorse or promote products derived from this software without specific prior 
   written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=head1 CREDITS

Satanic Socks Server v0.8.031206-perl
datapipe.pl by CuTTer

Also, thanks to #perlhelp @ EFnet

=pod OSNAMES

any

=pod SCRIPT CATEGORIES

Networking

=cut

## Settings
our $daemon   = 1; #run as a daemon or not (0/1)
our $logging  = 0; #logging on or off (0/1)
our $logfile  = 'sss.log';

## Language
my $lang_daemon="Process (%s) has entered into background.\n";
my $lang_usage="Usage: $0 <local_host> <local_port> [auth_login(:auth_pass)]\n".
		"Note: the auth_pass must be an md5 (hex) hash\n".
		"eg: $0 localhost 34567 test:098f6bcd4621d373cade4e832627b4f6\n";
my $lang_bind="Could not bind to %s:%s\n";
my $lang_sockopen="Could not open a socket to %s:%s\n";
my $lang_file_open="Could not open log file.";

## Usage
if (!$ARGV[1]) { die $lang_usage; }

## Requirements
# Install using: perl -MCPAN -e'install %module'
use IO::Socket::INET;
use Digest::MD5 qw(md5_hex);

##-md5 option
if ($ARGV[0] eq '-getmd5') {
  shift;
  print md5_hex(shift);
  exit(0);
}

## Arguments
our $local_host = shift;
our $local_port = shift;
our $auth_login = shift;
our $auth_pass;

#Parse auth part
if ($auth_login && $auth_login =~ m/:/) {
	($auth_login,$auth_pass)=split(':', $auth_login);
}

#Open listening port
$SIG{'CHLD'} = 'IGNORE';
my $bind = socks_open(  Listen=>5,
                        LocalAddr=>$local_host.':'.$local_port,
                        ReuseAddr=>1) 
                        or die sprintf($lang_bind,$local_host,$local_port);

#Run as daemon
if ($daemon) {
  our $pid=fork();
  if ($pid) {
    printf($lang_daemon,$pid);
    close(); exit();
  }
}

# Start client
our $client;
while($client = $bind->accept()) {
	$client->autoflush();
	if (fork()){ socks_close($client); }
	else { socks_close($bind); new_client($client); exit(); }
}

# New client subroutine
sub new_client {
	my($t, $i, $buff, $ord, $success);
	my $client = shift;

	socks_sysread($client, $buff, 1);
	if (ord($buff) != 5) { return; } #must be SOCKS 5
	
	socks_sysread($client, $buff, 1);
	$t=ord($buff);
	unless(socks_sysread($client, $buff, $t) == $t) { return; }

	$success=0;
	for($i=0; $i < $t; $i++) {
	 $ord = ord(substr($buff, $i, 1));
	 if ($ord == 0 && !$auth_login) {
	   socks_syswrite($client, "\x05\x00", 2);
	   $success++;
	   last;
	 }
	 elsif ($ord == 1 && $auth_login) {
	   #GSSAPI auth support
	   #socks_syswrite($client, "\x05\x01", 2);
	   #$success++;
	   #last;
	 }
	 elsif ($ord == 2 && $auth_login) {
	   unless(do_login_auth($client)){ return; }
	   $success++;
	   last;
	 }
	}

	if ($success) {
	 $t = socks_sysread($client, $buff, 3);

	 if (substr($buff, 0, 1) eq "\x05") {
	   if (ord(substr($buff, 2, 1)) == 0) { # reserved
		 my($host, $raw_host) = socks_get_host($client);
		 if (!$host) { return; }
		 my($port, $raw_port) = socks_get_port($client);
		 if (!$port) { return; }
		 $ord = ord(substr($buff, 1, 1));
		 $buff = "\x05\x00\x00".$raw_host.$raw_port;
		 socks_syswrite($client, $buff, length($buff));
		 socks_do($ord, $client, $host, $port);
	   }
	 }
	}
	else { socks_syswrite($client, "\x05\xFF", 2); }

	socks_close($client);
}

# Do login authentication subroutine
sub do_login_auth {
	my($buff, $login, $pass);
	my $client = shift;

	socks_syswrite($client, "\x05\x02", 2);
	socks_sysread($client, $buff, 1);

	if (ord($buff) == 1) {
		socks_sysread($client, $buff, 1);
		socks_sysread($client, $login, ord($buff));
		socks_sysread($client, $buff, 1);
		socks_sysread($client, $pass, ord($buff));

		if ($auth_login && $auth_pass && $login eq $auth_login && md5_hex($pass) eq $auth_pass) {
			socks_syswrite($client, "\x01\x00", 2);
			return 1;
		}
		else { socks_syswrite($client, "\x01\x01", 2); }
	}

	socks_close($client);
	return 0;
}

# Get socks hostname subrouteine
sub socks_get_host {
	my $client = shift;
	my ($t, $ord, $raw_host);
	my $host = "";
	my @host;

	socks_sysread($client, $t, 1);
	$ord = ord($t);
	if ($ord == 1) {
  	socks_sysread($client, $raw_host, 4);
  	@host = $raw_host =~ /(.)/g;
  	$host = ord($host[0]).'.'.ord($host[1]).'.'.ord($host[2]).'.'.ord($host[3]);
	} elsif ($ord == 3) {
  	socks_sysread($client, $raw_host, 1);
  	socks_sysread($client, $host, ord($raw_host));
  	$raw_host .= $host;
	} elsif ($ord == 4) {
	 #ipv6
	}

	return ($host, $t.$raw_host);
}

#Get socks port subroutine
sub socks_get_port {
	my $client = shift;
	my ($raw_port, $port);
	socks_sysread($client, $raw_port, 2);
	$port = ord(substr($raw_port, 0, 1)) << 8 | ord(substr($raw_port, 1, 1));
	return ($port, $raw_port);
}

#Socks command
sub socks_do {
	my($t, $client, $host, $port) = @_;

	if ($t == 1) { socks_connect($client, $host, $port); }
	elsif ($t == 2) { socks_bind($client, $host, $port); }
	elsif ($t == 3) { socks_udp_associate($client, $host, $port); }
	else { return 0; }

	return 1;
}

#Connect socks client to target server
our $target;
sub socks_connect {
	my($client, $host, $port) = @_;
	my $target = socks_open(LocalHost => $local_host,
                          PeerAddr => $host.':'.$port,
                          Proto => 'tcp',
                          Type => SOCK_STREAM)
                          or die sprintf($lang_sockopen,$host,$port);

	unless($target) { return; }

	$target->autoflush();
	while($client || $target) {
  	my $rin = "";
  	vec($rin, fileno($client), 1) = 1 if $client;
  	vec($rin, fileno($target), 1) = 1 if $target;
  	my($rout, $eout);
  	select($rout = $rin, undef, $eout = $rin, 120);
  	if (!$rout  &&  !$eout) { return; }
  	my $cbuffer = "";
  	my $tbuffer = "";
  
  	if ($client && (vec($eout, fileno($client), 1) || vec($rout, fileno($client), 1))) {
  	 my $result = socks_sysread($client, $tbuffer, 1024);
  	 if (!defined($result) || !$result) { return; }
  	}
  
  	if ($target  &&  (vec($eout, fileno($target), 1)  || vec($rout, fileno($target), 1))) {
  	 my $result = socks_sysread($target, $cbuffer, 1024);
  	 if (!defined($result) || !$result) { return; }
  	}
  
  	while (my $len = length($tbuffer)) {
  	 my $res = socks_syswrite($target, $tbuffer, $len);
  	 if ($res > 0) { $tbuffer = substr($tbuffer, $res); } else { return; }
  	}
  
  	while (my $len = length($cbuffer)) {
  	 my $res = socks_syswrite($client, $cbuffer, $len);
  	 if ($res > 0) { $cbuffer = substr($cbuffer, $res); } else { return; }
  	}
	}
}

sub socks_bind {
	my($client, $host, $port) = @_;
	# not supported yet
}

sub socks_udp_associate {
	my($client, $host, $port) = @_;
	# not supported yet
}

## Logging functions
our $log;
sub socks_open {
  socks_log('|open>');
  return IO::Socket::INET->new(@_);
}
sub socks_close {
  my $sock = shift;
  socks_log('<close|');
  return $sock->close();
}
sub socks_sysread {
  my $result = sysread($_[0], $_[1], $_[2]);
  socks_log("<read|$_[1]");
  return $result;
}
sub socks_syswrite {
  socks_log("|write>$_[1]");
  return syswrite($_[0], $_[1], $_[2]);
}

sub socks_log {
  if (!$logging){ return; }
  open(LOG, ">>$logfile") or die $lang_file_open;;
  print LOG shift;
  print LOG "\n";
  close(LOG);
} 

#EOF