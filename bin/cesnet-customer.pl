#!/usr/bin/perl -w

use strict;     # cs_CZ.UTF-8 locales required!!!
use utf8;
use locale;
use lib qw(./emd/lib);
use Data::Dumper;
use XML::LibXML;
use Sys::Syslog qw(:standard :macros);
use AppConfig qw(:expand);
use emd2::Utils qw (logger local_die startRun stopRun);
use emd2::Checker qw (checkXMLValidity);
use myPerlLDAP::conn;
use myPerlLDAP::entry;
use myPerlLDAP::attribute;
use myPerlLDAP::utils qw(:all);
use JSON;

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $saml20attr_ns = 'urn:oasis:names:tc:SAML:metadata:attribute';
my $saml20asrt_ns = 'urn:oasis:names:tc:SAML:2.0:assertion';

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

# https://www.eduid.cz/cs/tech/categories/eduidcz - kategorie IdP v eduID.cz
#   (idp_category='university' and ((affiliate='employee') or (affiliate='faculty') or (affiliate='member') or (affiliate='student') or (affiliate='staff'))) or
#   (idp_category='avcr' and (affiliate='member')) or
#   (idp_category='library' and (affiliate='employee')) or
#   (idp_category='hospital' and (affiliate='employee')) or
#   (idp_category='other' and ((affiliate='employee') or (affiliate='member')))
#
# Implementace diskutovana v https://rt.cesnet.cz/rt/Ticket/Display.html?id=264604

my $category2affiation = {
    'http://eduid.cz/uri/idp-group/university' => ['employee', 'faculty', 'member', 'student', 'staff' ],
    'http://eduid.cz/uri/idp-group/avcr'       => ['member'],
    'http://eduid.cz/uri/idp-group/library'    => ['employee'],
    'http://eduid.cz/uri/idp-group/hospital'   => ['employee'],
    'http://eduid.cz/uri/idp-group/other'      => ['employee'],
};

sub update_affiliation {
    my $entry = shift;
    my $entity = shift;
    my $zakaznik = shift;

    my $idp_category = '';
    my $affiliations = [];

    my $entityID = $entity->getAttribute('entityID');
    my $entryDN = $entry->dn;

  ATTRIBUTES:
    foreach my $entityAttributes (@{$entity->getElementsByTagNameNS($saml20attr_ns, 'EntityAttributes')}) {
	#<mdattr:EntityAttributes>
	#  <saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="http://macedir.org/entity-category">
        #    <saml:AttributeValue>http://eduid.cz/uri/idp-group/library</saml:AttributeValue>
        #  </saml:Attribute>
        #</mdattr:EntityAttributes> at /home/mdx/emd/bin/cesnet-customer.pl line 48.

	foreach my $attribute (@{$entityAttributes->getElementsByTagNameNS($saml20asrt_ns, 'Attribute')}) {
	    next unless $attribute;
	    next unless ($attribute->getAttribute('Name') eq 'http://macedir.org/entity-category');

	    foreach my $aval (@{$attribute->getElementsByTagNameNS($saml20asrt_ns, 'AttributeValue')}) {
		$idp_category = $aval->textContent;
		$idp_category =~ s/\s//mg;

		# IdP muze byt pouze v jedne kategorii, to je pravidlo eduID.cz.
		last ATTRIBUTES if ($idp_category =~ m,http://eduid.cz/uri/idp-group/,);

		$idp_category = '';
	    };
	};
    };

    if (length($idp_category)>0 and (exists $category2affiation->{$idp_category})) {
	$affiliations = $category2affiation->{$idp_category} if ($zakaznik);
    } else {
	logger(LOG_INFO, "$entityID is missing entity category!");
    };

    my (@add, @del);
    my $cca = $entry->attr('cesnetCustomerAffiliation');
    if ((not defined $cca) and (@{$affiliations})) {
	# entry nema zadny
	$entry->addValues('cesnetCustomerAffiliation', $affiliations);
	push @add, @{$affiliations};
    } else {
	my @ldap = ();
	@ldap = @{$cca->getValues} if ($cca);

	# zkontrolovat jestli v LDAPu mame vsechny atributy ktere bych meli mit
	foreach my $affiliation (@{$affiliations}) {
	    unless (grep { $_ eq $affiliation } @ldap) {
		push @add, $affiliation;
		$entry->addValues('cesnetCustomerAffiliation', $affiliation);
	    };
	};

	# zkontrolovat jestli v LDAPu nemame neco navic
	foreach my $ldap (@ldap) {
	    unless (grep { $_ eq $ldap} @{$affiliations}) {
		push @del, $ldap;
		$entry->removeValues('cesnetCustomerAffiliation', $ldap);
	    };
	};
    };

    if ((@add > 0) or (@del > 0)) {
	my @log;
	push @log, map { "+$_"; } @add;
	push @log, map { "-$_"; } @del;
	logger(LOG_INFO,
	       "$entityID ($entryDN): cesnetCustomerAffiliation: ".join(", ", @log));
    };

    return $entry->isModified;
};

# <EntityDescriptor xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" entityID="https://whoami-dev.cesnet.cz/idp/shibboleth">
#   <Extensions>
#     <mdattr:EntityAttributes>
#     ...
#       <saml:Attribute Name="http://macedir.org/entity-category" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
#         <saml:AttributeValue>http://refeds.org/category/hide-from-discovery</saml:AttributeValue>
#         <saml:AttributeValue>http://eduid.cz/uri/idp-group/other</saml:AttributeValue>
#     </saml:Attribute>

sub hideFromDiscovery {
    my $entity = shift;

    foreach my $element (@{$entity->getElementsByTagNameNS($saml20asrt_ns, 'AttributeValue')}) {
	my $val = $element->textContent;
	$val =~ s/^\s+//g;
	$val =~ s/\s+$//g;

	return 1 if ($val eq 'http://refeds.org/category/hide-from-discovery');
    };

    return 0;
};

$config->args(\@ARGV) or
    die "Can't parse cmdline args";
$config->file($config->cfg) or
    die "Can't open config file \"".$config->cfg."\": $!";

my $conn = construct myPerlLDAP::conn({"host"   => $config->LDAPServer,
				       "port"   => $config->LDAPServerPort,
				       "bind"   => $config->BindDN,
				       "pswd"   => $config->BindPassword,
				       "certdb" => $config->UseSSL}) or
    local_die "Can't create myPerlLDAP::conn object";
$conn->init or
    local_die "Can't open LDAP connection to ".$config->LDAPServer.":".$config->LDAPServerPort.": ".$conn->errorMessage;

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

my @entityIDs;
my @missing;
my @problems;
my @zakaznici;
my @ostatni;
my @clenove;
my $now = time;
my $total = 0;
my @komoraExport;

# projet entity ID ve federaci jestli je zname
foreach my $entity (@{$root->getElementsByTagNameNS($saml20_ns, 'EntityDescriptor')}) {
    # overit ze se jedna o IdP, tj. ma
    next unless @{$entity->getElementsByTagNameNS($saml20_ns, 'IDPSSODescriptor')};
    # pokud je oznacena jako hide from discovery tak se ji nebudeme zabyvat
    next if hideFromDiscovery($entity);

    $total++;
    my $entityID = $entity->getAttribute('entityID');
    push @entityIDs, $entityID;

    my $sres = $conn->search($config->eduIDOrgBase,
			     LDAP_SCOPE_ONE,
			     '(entityidofidp='.$entityID.')')
	or die "Can't search: ".$conn->errorMessage;
    if ($sres->count == 0) {
	my $ldif = "dn: dc=$now,ou=Organizations,o=eduID.cz,o=apps,dc=cesnet,dc=cz
dc: $now
objectClass: top
objectClass: eduidczorganization
oPointer: dc=__DOPLNIT__,ou=Organizations,dc=cesnet,dc=cz
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

	my %komoraExport = (
	    entityID => $entityID,
	    organizace => $o,
	    ldapID => $orgEntry->getValues('dc')->[0],
	    abraCustomerId => $orgEntry->getValues('cesnetAbraOrgID')->[0] || undef,
	    clientId => $orgEntry->getValues('cesnetOrgID')->[0] || undef,
	    );
	push @komoraExport, \%komoraExport;

	if ($clen =~ /TRUE/i) {
	    push @clenove, "$o ($entityID)";
	};

	my @services;

	# proverit jestli maji eduroam
	my $e_res = $conn->search('o=eduroam,o=apps,dc=cesnet,dc=cz',
				  LDAP_SCOPE_SUBTREE,
				  '(&(|(eduroamConnectionStatus=in-process)(eduroamConnectionStatus=connected))(oPointer='.$oPointer.'))')
	    or die "Can't search: ".$conn->errorMessage;
	push @services, 'eduroam' if $e_res->count;

	# proverit jestli maji TCS
	my $t_res = $conn->search('ou=Organizations,o=TCS2,o=apps,dc=cesnet,dc=cz',
				  LDAP_SCOPE_SUBTREE,
				  '(&(entryStatus=active)(tcs2CesnetOrgDN='.$oPointer.'))')
	    or die "Can't search: ".$conn->errorMessage;
	push @services, 'TCS' if $t_res->count;

        my $bzakaznik = 0;
	if ($zakaznik =~ /TRUE/i) {
	    $bzakaznik = 1;
	    my $z = "$o ($entityID) ";
	    push @services, 'CESNET MEMBER' if ($clen =~ /TRUE/i);
	    push @zakaznici, $z.join(', ', @services);
	} else {
            my $oo = $o;
	    $oo = '' unless(defined($o));
	    push @ostatni, "$oo ($entityID) ".join(', ', @services);
	};

	if (update_affiliation($entry, $entity, $bzakaznik)) {
	    # neco se zmenilo v LDAPu;
	    if ($conn->update($entry)) {
		logger(LOG_INFO, "$entityID updated");
	    } else {
		logger(LOG_INFO, "$entityID failed to update LDAP: ".$conn->errorMessage);
	    };
	};
    } elsif ($sres->count > 1) {
	push @problems, "Multiple records for $entityID in baseDN=".$config->eduIDOrgBase."\n";
    };
};

# vyexportovat data pro komoru
open(KOMORA, ">".$config->komoraExport)
    or local_die("Can't write into: ".$config->komoraExport);
my $json_str = JSON->new->pretty->encode(\@komoraExport);
print KOMORA $json_str;
close KOMORA;

# projet entityID v LDAPu jestli se nam tam neflaka neco co uz nepotrebujeme
my @extra;
my $filter = '(!(|'.join('', map { "(entityIDofIdP=$_)"} @entityIDs).'))';
my $sres = $conn->search($config->eduIDOrgBase,
			 LDAP_SCOPE_ONE,
			 $filter)
    or die "Can't search: ".$conn->errorMessage;
while (my $entity = $sres->nextEntry) {
    my $dc = $entity->getValues('dc')->[0];
    my $entityID = $entity->getValues('entityIDofIdP')->[0];

    push @extra, "$entityID (dc=$dc)";
};

if ($config->showStats) {
    print("Subject: [eduID.cz #267261] monthly eduID.cz IdP review\n\n");
    printf("Total known entities: %d, customers: %d (members: %d), other: %d
Entities not registered in LDAP: ".scalar(@missing)."
Entities orphaned in LDAP: ".scalar(@extra)."\n\n",
	   $total, scalar(@zakaznici), scalar(@clenove), scalar(@ostatni));
    print("List of CESNET customers and members (".scalar(@zakaznici)."):\n",
	  join("\n", sort map { "    $_"} @zakaznici)."\n\n");
    print("List of other eduID.cz members (".scalar(@ostatni)."):\n",
	  join("\n", sort map { "    $_"} @ostatni)."\n\n"); 
};

if (scalar(@missing) or scalar(@extra)) {
    print("Subject: [eduID.cz #330914] Pripominka aktualizace ciselniku organizaci v eduID.cz\n");

    if (@missing) {
	print("Complete following LDIF and submit it into LDAP:

".join('', @missing)."\n");
    };

    if (@extra) {
	print("Folowing entityID are not present in ".$config->metadata.":
".join('', map { "  $_\n" } @extra)."\n");
    };
};
