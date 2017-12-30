package EasyLogin::LDAPServer;

use strict;
use warnings;

use Data::Dumper;
use Net::LDAP::Server;
use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_OPERATIONS_ERROR LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_SYNTAX LDAP_NO_SUCH_OBJECT LDAP_INVALID_CREDENTIALS LDAP_UNAVAILABLE LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Entry;
use JSON;
use REST::Client;
use base 'Net::LDAP::Server';

# Used to simplify generation of LDAP answers
# matchedDN and errorMessage are optional so we can simply skip them for now
sub ldapReturnStruct {
	my $ldapResultCode = shift;
	
	return {
	    'matchedDN' => '',
		'errorMessage' => '',
		'resultCode' => $ldapResultCode
	};
}

sub restPostAtPathWithJSONObject {
	my $path = shift;
	my $jsonBody = shift;
	
	my $client = REST::Client->new();
	
	### TODO: use configuration system (CloudFoundry supported?) to find the REST API
	my $request_url =  'http://127.0.0.1:8080/ldap/v1'.$path;

	### TODO: if available, add the auth token in authentication headers
	$client->POST($request_url, $jsonBody, { "Content-type" => 'application/json', "Accept" => 'application/json'}); 
	return $client;
}

# Constructor
sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	
	print STDERR "New instance of EasyLogin LDAP Server created\n";
	
	return $self;
}

# Used when user try to login
sub bind {	
	my $self = shift;
	my $reqData = shift;
	
	print STDERR "New binding request\n";
	
	if ($reqData->{'name'}) {
		my $jsonRequest = encode_json $reqData;
		
		my $restClientWithAnswer = restPostAtPathWithJSONObject("/auth", $jsonRequest);
		
		my $responseCode = $restClientWithAnswer->responseCode();

		if ($responseCode == 200) {
			### TODO: grab the auth token from responseHeader
			return ldapReturnStruct(LDAP_SUCCESS);
		} elsif ($responseCode == 401) {
			return ldapReturnStruct(LDAP_INVALID_CREDENTIALS);
		}
		
		return ldapReturnStruct(LDAP_OPERATIONS_ERROR);
	} else {
		return ldapReturnStruct(LDAP_INVALID_CREDENTIALS);
	}
	
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR);
}

### Called to perform an object lookup
sub search {	
	my $self = shift;
	my ($reqData, $fullRequest) = @_;

	print STDERR "New search request\n";

	my @entries;

	my $jsonRequest = encode_json $reqData;

	print STDERR "JSON Object for search request: $jsonRequest \n";

	my $restClientWithAnswer = restPostAtPathWithJSONObject("/search", $jsonRequest);

	my $responseCode = $restClientWithAnswer->responseCode();

	if ($responseCode == 200) {
		print STDERR "Got result from EasyLogin Server\n";

		print STDERR "JSON Object as search result: ".$restClientWithAnswer->responseContent()."\n";
		
		my $arrayOfRecords = decode_json $restClientWithAnswer->responseContent();
		
		foreach my $record (@$arrayOfRecords) {
			my $entry = Net::LDAP::Entry->new;
			$entry->dn($record->{dn});
			delete $record->{dn};

			if (exists $reqData->{"attributes"}) {
				foreach my $key (@{$reqData->{"attributes"}}) {
					foreach my $value ($record->{$key}) {
						$entry->add ($key => $value);
					}
				}
			} else {
				foreach my $key (keys $record) {
					foreach my $value ($record->{$key}) {
						$entry->add ($key => $value);
					}
				}
			}
			push @entries, $entry;
		}

		return ldapReturnStruct(LDAP_SUCCESS), @entries;
	} elsif ($responseCode == 401) {
		print STDERR "Search denied by EasyLogin Server\n";
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
	}

	print STDERR "Unexpected search error\n";
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

1;
