package EasyLogin::LDAPGatewayHandler;

use strict;
use warnings;

use Net::LDAP::Server;
use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_OPERATIONS_ERROR LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_SYNTAX LDAP_NO_SUCH_OBJECT LDAP_INVALID_CREDENTIALS LDAP_UNAVAILABLE LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Entry;
use JSON;
use REST::Client;
use Net::Daemon;
use List::MoreUtils qw(uniq);

use base 'Net::LDAP::Server';
use fields qw(ldapGatewayDaemon);

our $server_base_url = $ENV{'EASYLOGIN_BASE_URL'}; 

# Constructor
sub new {
    my $class = shift;
    my $daemon = shift;
    
    my $self = $class->SUPER::new($daemon->{socket});
    
    $self->{'ldapGatewayDaemon'} = $daemon;
    
    $self->{'ldapGatewayDaemon'}->Log('notice', "New instance of LDAPGatewayHandler created for '".$server_base_url."'");
    
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
    my $request_url =  $server_base_url.'/ldap/v1'.$path;
    
    ### TODO: if available, add the auth token in authentication headers
    $client->POST($request_url, $jsonBody, { "Content-type" => 'application/json', "Accept" => 'application/json'});
    return $client;
}

sub restGetPath {
    my $path = shift;
    
    my $client = REST::Client->new();
    
    ### TODO: use configuration system (CloudFoundry supported?) to find the REST API
    my $request_url =  $server_base_url.'/ldap/v1'.$path;
    
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
        
        $self->{'ldapGatewayDaemon'}->Log('debug', "JSON Object used for authentication: ".$jsonRequest);
        my $restClientWithAnswer = restPostAtPathWithJSONObject("/auth", $jsonRequest);
        
        my $responseCode = $restClientWithAnswer->responseCode();
        
        if ($responseCode == 200) {
            ### TODO: grab the auth token from responseHeader
            
            $self->{'ldapGatewayDaemon'}->Log('notice', "LDAP BIND OK");
            return ldapReturnStruct(LDAP_SUCCESS);
        } elsif ($responseCode == 401) {
            $self->{'ldapGatewayDaemon'}->Log('notice', "LDAP BIND NOT OK");
            return ldapReturnStruct(LDAP_INVALID_CREDENTIALS);
        }
        
        $self->{'ldapGatewayDaemon'}->Log('notice', "LDAP BIND KO");
        return ldapReturnStruct(LDAP_OPERATIONS_ERROR);
    } else {
        $self->{'ldapGatewayDaemon'}->Log('notice', "LDAP BIND NOT SENT");
        return ldapReturnStruct(LDAP_INVALID_CREDENTIALS);
    }
    
    $self->{'ldapGatewayDaemon'}->Log('notice', "LDAP BIND KO KO");
    return ldapReturnStruct(LDAP_OPERATIONS_ERROR);
}

### Called to perform an object lookup
sub search {	
    my $self = shift;
    my ($reqData, $fullRequest) = @_;
    
    my $baseObject = $reqData->{"baseObject"};
    
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
            @attributes = grep { $_ ne "dn" } @attributes;
            @attributes = uniq @attributes;
            
            my %attributesAsHash = map { $_ => 1 } @attributes;
            if(exists($attributesAsHash{"*"})) {
                undef @attributes
            }
            
            if (@attributes) {
                $self->{'ldapGatewayDaemon'}->Log('info', "Translation will be filterred to return only requested attributes");
                foreach my $key (@attributes) {
                    if (length $key > 0) {
                        foreach my $value ($record->{$key}) {
                            $entry->add ($key => $value);
                        }
                    }
                }
            } else {
                delete $record->{hasSubordinates};
                foreach my $key (keys %{ $record }) {
                    foreach my $value ($record->{$key}) {
                        $entry->add ($key => $value);
                    }
                }
            }
            push @entries, $entry;
        }
        
        return ldapReturnStruct(LDAP_SUCCESS), @entries;
    } elsif ($responseCode == 401) { #unauthorized
        $self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server (401)");
        return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
    } elsif ($responseCode == 403) { #forbidden
        $self->{'ldapGatewayDaemon'}->Log('warn', "Search denied by EasyLogin Server (403)");
        return ldapReturnStruct(LDAP_UNWILLING_TO_PERFORM);
    }
    
    $self->{'ldapGatewayDaemon'}->Log('err', "Unexpected search error (".$responseCode.")");
    return ldapReturnStruct(LDAP_OPERATIONS_ERROR), @entries;
}

1;
