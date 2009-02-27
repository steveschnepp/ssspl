#!/usr/bin/perl
#sss.pl v0.1.2 (27/02/09)
use warnings; use strict;

=head1 NAME

Simple SOCKS Server for Perl

=head1 DESCRIPTION

SSS is a Simple SOCKS Server written in perl that implements the SOCKS v5 protocol.

It will accept username/password authentication.

The script runs in the background as a daemon.

=head2 Why it exists

Originally I was looking for a simple SOCKS5 Server (with user/pass auth) that would run 
as a non-root user on FreeBSD.

I checked FreeBSD's ports for various SOCKS5 solutions and tried them all, only to discover
that each one had a reason why it would not work, or why I could not use it.

I figured this could be done in perl, but found that there was no well maintained perl based solutions.

I hacked together this solution (with help from public domain scripts) and cleaned it up, ready for release.

Its simple, a feature I intend to maintain, however there is scope for much more potential,
especially with user feedback.

You can read the full story here: http://www.hm2k.com/posts/freebsd-socks-proxy-for-mirc

=head2 Usage

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
v0.1.2 (27/02/09) - Fixed a bug (Thanks Andreas)
v0.1.1 (02/10/08) - Improved documentation
v0.1 (12/09/08) - Initial release.

=head1 TODO
* In mIRC $serverip returns 255.255.255.255 <digital>
* Outgoing DCCs are borked (mIRC) <digital>
* IPv6 support
* BIND method
* UDP ASSOCIATE method
* GSSAPI authentication support - for use with firefox <OutCast3k>
* Restrict IP access to the listening port <Reeve>
* Logging <Katlyn`>

=head2 FAQ
* Why is there multiple processes in my process list?
** Each new connection spawns a new process. I decided to do this to make it easier to manage.

=head2 Notes
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

Copyright (c) 2008-2009, <a href="http://www.hm2k.com/">HM2K</a>. All rights reserved.

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

based on Satanic Socks Server v0.8.031206-perl and (in part) datapipe.pl by CuTTer

also, special thanks to #perlhelp @ EFnet as they have helped me in the past.

=pod OSNAMES

any

=pod SCRIPT CATEGORIES

Networking

=cut

use IO::Socket::INET;
use Digest::MD5 qw(md5_hex);

if (!$ARGV[1]) {
	die "Usage: <local_host> <local_port> [auth_login(:auth_pass)]\n".
		"Note: the auth_pass must be an md5 (hex) hash\n".
		"eg: localhost 34567 test 098f6bcd4621d373cade4e832627b4f6\n";
}

# internal settings
my $daemon=1; #run as a daemon or not (1/0)

our $local_host = shift;
our $local_port = shift;
our $auth_login = shift;
our $auth_pass;

if ($auth_login && $auth_login =~ m/:/) {
	($auth_login,$auth_pass)=split(':', $auth_login);
}

$SIG{'CHLD'} = 'IGNORE';
my $bind = IO::Socket::INET->new(Listen=>10, LocalAddr=>$local_host.':'.$local_port, ReuseAddr=>1) or die "Could not bind to $local_host:$local_port\n";

if ($daemon) {
	print "Now entering process into the background...\n";
	if (fork()) { close(); exit(); }
}

our $client;
while($client = $bind->accept()) {
	$client->autoflush();
	if(fork()){ $client->close(); }
	else { $bind->close(); new_client($client); exit(); }
}

sub new_client {
	my($t, $i, $buff, $ord, $success);
	my $client = $_[0];

	sysread($client, $buff, 1);
	if(ord($buff) != 5) { return; } #must be SOCKS 5
	
	sysread($client, $buff, 1);
	$t=ord($buff);
	unless(sysread($client, $buff, $t) == $t) { return; }

	$success=0;
	for($i=0; $i < $t; $i++) {
	 $ord = ord(substr($buff, $i, 1));
	 if($ord == 0 && !$auth_login) {
	   syswrite($client, "\x05\x00", 2);
	   $success++;
	   last;
	 }
	 elsif($ord == 1 && $auth_login) {
	   #GSSAPI auth support
	   #syswrite($client, "\x05\x01", 2);
	   #$success++;
	   #last;
	 }
	 elsif($ord == 2 && $auth_login) {
	   unless(do_login_auth($client)){ return; }
	   $success++;
	   last;
	 }
	}

	if ($success) {
	 $t = sysread($client, $buff, 3);

	 if(substr($buff, 0, 1) eq "\x05") {
	   if(ord(substr($buff, 2, 1)) == 0) { # reserved
		 my($host, $raw_host) = socks_get_host($client);
		 if(!$host) { return; }
		 my($port, $raw_port) = socks_get_port($client);
		 if(!$port) { return; }
		 $ord = ord(substr($buff, 1, 1));
		 $buff = "\x05\x00\x00".$raw_host.$raw_port;
		 syswrite($client, $buff, length($buff));
		 socks_do($ord, $client, $host, $port);
	   }
	 }
	}
	else { syswrite($client, "\x05\xFF", 2); }

	$client->close();
}

sub do_login_auth {
	my($buff, $login, $pass);
	my $client = $_[0];

	syswrite($client, "\x05\x02", 2);
	sysread($client, $buff, 1);

	if (ord($buff) == 1) {
		sysread($client, $buff, 1);
		sysread($client, $login, ord($buff));
		sysread($client, $buff, 1);
		sysread($client, $pass, ord($buff));

		if ($login eq $auth_login && md5_hex($pass) eq $auth_pass) {
			syswrite($client, "\x01\x00", 2);
			return 1;
		}
		else { syswrite($client, "\x01\x01", 2); }
	}

	$client->close();
	return 0;
}

sub socks_get_host {
	my $client = $_[0];
	my ($t, $ord, $raw_host);
	my $host = "";
	my @host;

	sysread($client, $t, 1);
	$ord = ord($t);
	if($ord == 1) {
	sysread($client, $raw_host, 4);
	@host = $raw_host =~ /(.)/g;
	$host = ord($host[0]).'.'.ord($host[1]).'.'.ord($host[2]).'.'.ord($host[3]);
	} elsif($ord == 3) {
	sysread($client, $raw_host, 1);
	sysread($client, $host, ord($raw_host));
	$raw_host .= $host;
	} elsif($ord == 4) {
	#ipv6
	}

	return ($host, $t.$raw_host);
}

sub socks_get_port {
	my $client = $_[0];
	my ($raw_port, $port);
	sysread($client, $raw_port, 2);
	$port = ord(substr($raw_port, 0, 1)) << 8 | ord(substr($raw_port, 1, 1));
	return ($port, $raw_port);
}

sub socks_do {
	my($t, $client, $host, $port) = @_;

	if($t == 1) { socks_connect($client, $host, $port); }
	elsif($t == 2) { socks_bind($client, $host, $port); }
	elsif($t == 3) { socks_udp_associate($client, $host, $port); }
	else { return 0; }

	return 1;
}

sub socks_connect {
	my($client, $host, $port) = @_;
	my $target = IO::Socket::INET->new(LocalHost => $local_host, PeerAddr => $host, PeerPort => $port, Proto => 'tcp', Type => SOCK_STREAM);

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
	 my $result = sysread($client, $tbuffer, 1024);
	 if (!defined($result) || !$result) { return; }
	}

	if ($target  &&  (vec($eout, fileno($target), 1)  || vec($rout, fileno($target), 1))) {
	 my $result = sysread($target, $cbuffer, 1024);
	 if (!defined($result) || !$result) { return; }
	 }

	while (my $len = length($tbuffer)) {
	 my $res = syswrite($target, $tbuffer, $len);
	 if ($res > 0) { $tbuffer = substr($tbuffer, $res); } else { return; }
	}

	while (my $len = length($cbuffer)) {
	 my $res = syswrite($client, $cbuffer, $len);
	 if ($res > 0) { $cbuffer = substr($cbuffer, $res); } else { return; }
	}
	}
}

sub socks_bind {
	my($client, $host, $port) = @_;
	# not supported
}

sub socks_udp_associate {
	my($client, $host, $port) = @_;
	# not supported
}

#EOF