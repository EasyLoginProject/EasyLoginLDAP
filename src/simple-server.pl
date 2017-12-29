#!/usr/bin/perl

use strict;
use warnings;

use IO::Select;
use IO::Socket;
use EasyLogin::LDAPServer;

print STDERR "Running new simple LDAP gateway\n";

my $sock = IO::Socket::INET->new(
	Listen => 5,
	Proto => 'tcp',
	Reuse => 1,
	LocalPort => 6389
);

print STDERR "Socket created\n";

my $sel = IO::Select->new($sock);
my %Handlers;
while (my @ready = $sel->can_read) {
	foreach my $fh (@ready) {
		if ($fh == $sock) {
			# let's create a new socket
			print STDERR "New incoming request accepted\n";
			my $psock = $sock->accept;
			$sel->add($psock);
			$Handlers{*$psock} = EasyLogin::LDAPServer->new($psock);
		} else {
			my $result = $Handlers{*$fh}->handle;
			if ($result) {
				print STDERR "Closing socket\n";
				# we have finished with the socket
				$sel->remove($fh);
				$fh->close;
				delete $Handlers{*$fh};
			}
		}
	}
}

1;

