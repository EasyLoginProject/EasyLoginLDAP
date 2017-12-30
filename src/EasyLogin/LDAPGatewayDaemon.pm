#!/usr/bin/perl

package EasyLogin::LDAPGatewayDaemon;

use strict;
use warnings;
use EasyLogin::LDAPGatewayHandler;
use Net::Daemon;
use base 'Net::Daemon';

sub Run {
	my $self = shift;
	
	$self->Log('notice', "New incoming request forwarded to new LDAPGatewayHandler");
	my $handler = EasyLogin::LDAPGatewayHandler->new($self);
	
	while (1) {
		my $finished = $handler->handle;
		if ($finished) {
			$self->Log('notice', "Work is done, closing socket");
			$self->{socket}->close;
			return;
		}
	}
}

1;