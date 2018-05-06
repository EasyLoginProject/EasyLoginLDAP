FROM perl:latest

COPY src /usr/local/EasyLoginLDAP
WORKDIR /usr/local/EasyLoginLDAP

RUN cpan o conf prerequisites_policy 'follow'
RUN cpan o conf build_requires_install_policy yes
RUN cpan o conf commit
RUN cpan install Log::Log4perl
RUN cpan install JSON
RUN cpan install Convert::ASN1
RUN cpan install Net::LDAP
RUN cpan install Net::LDAP::Server
RUN cpan install Net::Daemon
RUN cpan install REST::Client
RUN cpan install List::MoreUtils

EXPOSE 389

ENTRYPOINT ["/usr/local/EasyLoginLDAP/easyloginldap"]
