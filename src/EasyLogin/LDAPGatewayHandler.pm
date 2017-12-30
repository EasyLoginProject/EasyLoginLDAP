package EasyLogin::LDAPGatewayHandler;

use strict;
use warnings;

use Net::LDAP::Server;
use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_OPERATIONS_ERROR LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_SYNTAX LDAP_NO_SUCH_OBJECT LDAP_INVALID_CREDENTIALS LDAP_UNAVAILABLE LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Entry;
use JSON;
use REST::Client;
use Net::Daemon;

use base 'Net::LDAP::Server';
use fields qw(ldapGatewayDaemon);

# Constructor
sub new {
	my $class = shift;
	my $daemon = shift;

	my $self = $class->SUPER::new($daemon->{socket});

	$self->{'ldapGatewayDaemon'} = $daemon;

	$self->{'ldapGatewayDaemon'}->Log('notice', "New instance of LDAPGatewayHandler created");
	
	return $self;
}

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

sub restGetPath {
	my $path = shift;
	
	my $client = REST::Client->new();
	
	### TODO: use configuration system (CloudFoundry supported?) to find the REST API
	my $request_url =  'http://127.0.0.1:8080/ldap/v1'.$path;

	### TODO: if available, add the auth token in authentication headers
	$client->GET($request_url, { "Accept" => 'application/json'}); 
	return $client;
}

# Used when user try to login
sub bind {	
	my $self = shift;
	my $reqData = shift;
	
	$self->{'ldapGatewayDaemon'}->Log('notice', "Incoming LDAP BIND");
	
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

	my $baseObject = $reqData->{"baseObject"};

	if ($baseObject eq "dc=easylogin,dc=proxy") {
		if ($reqData->{"scope"} == 0) {
			return $self->searchForBaseContainer($reqData, $fullRequest)
		} elsif ($reqData->{"scope"} == 1) {
			return $self->searchFoFirstLevelContainers($reqData, $fullRequest)
		}
		
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
		
	} elsif (defined $baseObject and length $baseObject) {
		return $self->searchOnSubTree($reqData, $fullRequest)
	} else {
		return $self->searchRootDSE($reqData, $fullRequest)
	}
}

sub searchForBaseContainer {
	my $self = shift;
	my ($reqData, $fullRequest) = @_;

	$self->{'ldapGatewayDaemon'}->Log('notice', "Incoming Base Object request");

	my @entries;

	my $restClientWithAnswer = restGetPath("/basecontainer");

	my $responseCode = $restClientWithAnswer->responseCode();

	if ($responseCode == 200) {
		$self->{'ldapGatewayDaemon'}->Log('notice', "Base Object request got valid answer from REST API");

		$self->{'ldapGatewayDaemon'}->Log('debug', "JSON Object representing the Base Object: ".$restClientWithAnswer->responseContent());
		
		my $baseObject = decode_json $restClientWithAnswer->responseContent();
		
		$self->{'ldapGatewayDaemon'}->Log('info', "Translating from Base Object from JSON to LDAP ");

		my $entry = Net::LDAP::Entry->new;
		$entry->dn($baseObject->{dn});
		my @attributes = @{$reqData->{"attributes"}};

		my %attributesAsHash = map { $_ => 1 } @attributes;
		if(exists($attributesAsHash{"*"})) {
			undef @attributes
		}

		if (@attributes) {
			$self->{'ldapGatewayDaemon'}->Log('info', "Translation will be filterred to return only requested attributes");
			foreach my $key (@attributes) {
				foreach my $value ($baseObject->{$key}) {
					$entry->add ($key => $value);
				}
			}
		} else {
			foreach my $key (keys $baseObject) {
				foreach my $value ($baseObject->{$key}) {
					$entry->add ($key => $value);
				}
			}
		}

		push @entries, $entry;

		return ldapReturnStruct(LDAP_SUCCESS), @entries;
	} elsif ($responseCode == 401) {
			$self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server");
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
	}

	$self->{'ldapGatewayDaemon'}->Log('err', "Unexpected search error");
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

sub searchFoFirstLevelContainers {
	my $self = shift;
	my ($reqData, $fullRequest) = @_;

	$self->{'ldapGatewayDaemon'}->Log('notice', "Incoming request for First Level Containers");

	my @entries;

	my $restClientWithAnswer = restGetPath("/firstlevelcontainers");

	my $responseCode = $restClientWithAnswer->responseCode();

	if ($responseCode == 200) {
		$self->{'ldapGatewayDaemon'}->Log('notice', "First Level Containers request got valid answer from REST API");

		$self->{'ldapGatewayDaemon'}->Log('debug', "JSON Object representing the First Level Containers: ".$restClientWithAnswer->responseContent());
		
		my $arrayOfRecords = decode_json $restClientWithAnswer->responseContent();
		
		foreach my $record (@$arrayOfRecords) {
			$self->{'ldapGatewayDaemon'}->Log('info', "Translating from JSON to LDAP for: ".$record->{dn});

			my $entry = Net::LDAP::Entry->new;
			$entry->dn($record->{dn});
			delete $record->{dn};
			my @attributes = @{$reqData->{"attributes"}};

			my %attributesAsHash = map { $_ => 1 } @attributes;
			if(exists($attributesAsHash{"*"})) {
				undef @attributes
			}
			
			if (@attributes) {
				$self->{'ldapGatewayDaemon'}->Log('info', "Translation will be filterred to return only requested attributes");
				foreach my $key (@attributes) {
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
			$self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server");
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
	}

	$self->{'ldapGatewayDaemon'}->Log('err', "Unexpected search error");
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

sub searchOnSubTree {
	my $self = shift;
	my ($reqData, $fullRequest) = @_;

	$self->{'ldapGatewayDaemon'}->Log('notice', "Incoming LDAP SEARCH");

	my @entries;

	my $jsonRequest = encode_json $reqData;

	$self->{'ldapGatewayDaemon'}->Log('debug', "JSON object representing the LDAP SEARCH: ".$jsonRequest);

	my $restClientWithAnswer = restPostAtPathWithJSONObject("/search", $jsonRequest);

	my $responseCode = $restClientWithAnswer->responseCode();

	if ($responseCode == 200) {
		$self->{'ldapGatewayDaemon'}->Log('notice', "LDAP SEARCH got valid answer from REST API");

		$self->{'ldapGatewayDaemon'}->Log('debug', "JSON Object representing the LDAP SEARCH RESULT: ".$restClientWithAnswer->responseContent());
		
		my $arrayOfRecords = decode_json $restClientWithAnswer->responseContent();
		
		foreach my $record (@$arrayOfRecords) {
			$self->{'ldapGatewayDaemon'}->Log('info', "Translating from JSON to LDAP for: ".$record->{dn});

			my $entry = Net::LDAP::Entry->new;
			$entry->dn($record->{dn});
			delete $record->{dn};
			my @attributes = @{$reqData->{"attributes"}};

			my %attributesAsHash = map { $_ => 1 } @attributes;
			if(exists($attributesAsHash{"*"})) {
				undef @attributes
			}

			if (@attributes) {
				$self->{'ldapGatewayDaemon'}->Log('info', "Translation will be filterred to return only requested attributes");
				foreach my $key (@attributes) {
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
			$self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server");
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
	}

	$self->{'ldapGatewayDaemon'}->Log('err', "Unexpected search error");
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

sub searchRootDSE {
	my $self = shift;
	my ($reqData, $fullRequest) = @_;

	$self->{'ldapGatewayDaemon'}->Log('notice', "Incoming ROOT DSE request");

	my @entries;

	my $restClientWithAnswer = restGetPath("/rootdse");

	my $responseCode = $restClientWithAnswer->responseCode();

	if ($responseCode == 200) {
		$self->{'ldapGatewayDaemon'}->Log('notice', "ROOT DSE request got valid answer from REST API");

		$self->{'ldapGatewayDaemon'}->Log('debug', "JSON Object representing the ROOT DSE: ".$restClientWithAnswer->responseContent());
		
		my $rootDSE = decode_json $restClientWithAnswer->responseContent();
		
		$self->{'ldapGatewayDaemon'}->Log('info', "Translating from ROOT DSE from JSON to LDAP ");

		my $entry = Net::LDAP::Entry->new;
		$entry->dn("");
		my @attributes = @{$reqData->{"attributes"}};

		my %attributesAsHash = map { $_ => 1 } @attributes;
		if(exists($attributesAsHash{"*"})) {
			undef @attributes
		}

		if (@attributes) {
			$self->{'ldapGatewayDaemon'}->Log('info', "Translation will be filterred to return only requested attributes");
			foreach my $key (@attributes) {
				foreach my $value ($rootDSE->{$key}) {
					$entry->add ($key => $value);
				}
			}
		} else {
			foreach my $key (keys $rootDSE) {
				foreach my $value ($rootDSE->{$key}) {
					$entry->add ($key => $value);
				}
			}
		}

		push @entries, $entry;

		return ldapReturnStruct(LDAP_SUCCESS), @entries;
	} elsif ($responseCode == 401) {
			$self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server");
		return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
	}

	$self->{'ldapGatewayDaemon'}->Log('err', "Unexpected search error");
	return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

1;
