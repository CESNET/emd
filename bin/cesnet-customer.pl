#!/bin/perl -w

use strict;
use utf8;
use lib qw(./lib);
use XML::LibXML;
use Sys::Syslog qw(:standard :macros);
use AppConfig qw(:expand);
use emd2::Utils qw (logger local_die startRun stopRun);
use emd2::Checker qw (checkXMLValidity);
use myPerlLDAP::conn;
use myPerlLDAP::entry;
use myPerlLDAP::attribute;
use myPerlLDAP::utils qw(:all);

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';

my $config = AppConfig->new
    ({
	GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
	CASE => 1,
	CREATE => '.*',
     },
     
     cfg                => { DEFAULT => '' },
     
     metadata           => { DEFAULT => 'eduid+idp' },

     LDAPServer         => {DEFAULT => ''},
     LDAPServerPort     => {DEFAULT => LDAPS_PORT},
     UseSSL             => {DEFAULT => 1},
     BindDN             => {DEFAULT => ''},
     BindPassword       => {DEFAULT => ''},
     eduIDOrgBase       => {DEFAULT => 'ou=Organizations,o=eduID.cz,o=apps,dc=cesnet,dc=cz'},
     showStats          => {DEFAULT => 0},
    );

my $conn = new myPerlLDAP::conn({"host"   => $config->LDAPServer,
                                 "port"   => $config->LDAPServerPort,
                                 "bind"   => $config->BindDN,
                                 "pswd"   => $config->BindPassword,
                                 "certdb" => $config->UseSSL}) or
    local_die "Can't create myPerlLDAP::conn object";
$conn->init or
    local_die "Can't open LDAP connection to ".$config->LDAPServer.":".$config->LDAPServerPort.": ".$conn->errorMessage;

$config->args(\@ARGV) or
    die "Can't parse cmdline args";
$config->file($config->cfg) or
    die "Can't open config file \"".$config->cfg."\": $!";

# nacist metadata
my $parser = XML::LibXML->new;
open my $fh, $config->metadata or
    local_die "Failed to open ".$config->metadata.": $!";
my $string = join('', <$fh>);
my $xml;
eval {
    $xml = $parser->parse_string($string);
};
if ($@) {
    my $err = $@;
    local_die "Failed to parse file ".$config->metadata.": $@";
};
close $fh;

my $root = $xml->documentElement;

my @missing;
my @problems;
my @zakaznici;
my @ostatni;
my @clenove;
my $now = time;
my $total = 0;
# projet entity ID jestli je zname
foreach my $entity (@{$root->getElementsByTagNameNS($saml20_ns, 'EntityDescriptor')}) {
    # overit ze se jedna o IdP, tj. ma
    next unless @{$entity->getElementsByTagNameNS($saml20_ns, 'IDPSSODescriptor')};

    $total++;
    my $entityID = $entity->getAttribute('entityID');

    my $sres = $conn->search($config->eduIDOrgBase,
			     LDAP_SCOPE_ONE,
			     '(entityidofidp='.$entityID.')')
	or die "Can't search: ".$conn->errorMessage;
    if ($sres->count == 0) {
	my $ldif = "dn: dc=$now,ou=Organizations,o=eduID.cz,o=apps,dc=cesnet,dc=cz
dc: $now
objectClass: top
objectClass: eduIDczOrganization
oPointer: dc=,ou=Organizations,dc=cesnet,dc=cz
entityidofidp: $entityID\n\n";
	$now++;
	push @missing, "$ldif";
    } elsif ($sres->count == 1) {
	# tohle jsme hledali - nic delat nemusime, jen si poznamename statistiky
	my $entry = $sres->nextEntry;
	my $oPointer = $entry->getValues('oPointer')->[0];
	my $orgEntry = $conn->read($oPointer) or
	    local_die "Failed to read $oPointer: ".$conn->errorMessage;
	my $zakaznik = $orgEntry->getValues('cesnetActive')->[0] || 'FALSE';
	my $clen = $orgEntry->getValues('cesnetMember')->[0] || 'FALSE';
	my $o = $orgEntry->getValues('o', 'lang-cs')->[0];
	if ($clen =~ /TRUE/i) {
	    push @clenove, "$o ($entityID)";
	};
	if ($zakaznik =~ /TRUE/i) {
	    my $z = "$o ($entityID)";
	    $z .= ' MEMBER' if ($clen =~ /TRUE/i);
	    push @zakaznici, $z;
	} else {
	    push @ostatni, "$o ($entityID)";
	};
    } elsif ($sres->count > 1) {
	push @problems, "Multiple records for $entityID in baseDN=".$config->eduIDOrgBase."\n";
    };
};

if ($config->showStats) {
    printf("Total known entities: %d, customers: %d (members: %d), other: %d
Unknown entities: ".scalar(@missing)."\n\n",
	   $total, scalar(@zakaznici), scalar(@clenove), scalar(@ostatni));
    print("List of customers:\n",
	  join("\n", sort map { "    $_"} @zakaznici)."\n\n");
    print("List of other members:\n",
	  join("\n", sort map { "    $_"} @ostatni)."\n\n"); 
};

print("Complete following LDIF and submit it into LDAP:

".join('', @missing)."\n");
