#!/usr/bin/perl

use EasyLogin::LDAPGatewayDaemon;

my $gateway = EasyLogin::LDAPGatewayDaemon->new({
	localport => 6389,
	logfile => 'STDERR',
	pidfile => 'none',
	mode => 'fork'
});

$gateway->Bind;

1;