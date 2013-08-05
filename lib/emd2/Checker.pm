#/usr/bin/perl -w

package emd2::Checker;

use strict;
use Carp;
use emd2::Utils qw(:all);
use Data::Dumper;
use Crypt::OpenSSL::X509;
use MIME::Base64 qw(decode_base64);
use Date::Manip;
use List::MoreUtils qw(uniq);
use File::Temp qw(tempdir);

# vyzaduje: opensaml2-schemas

use vars qw($VERSION @ISA %EXPORT_TAGS);

@ISA = qw(Exporter);
$VERSION = "0.0.1";
%EXPORT_TAGS = (
                all => [qw(checkEntityDescriptor checkXMLValidity)],
                );
# Add Everything in %EXPORT_TAGS to @EXPORT_OK
Exporter::export_ok_tags('all');

use constant CHECK_OK => 0;
use constant CHECK_FAILED => 1;
use constant CHECK_XML_VALIDITY => 2;
use constant CHECK_ENTITYID => 3;
use constant CHECK_TECHNICAL_CONTACT => 4;
use constant CHECK_ORGANIZATION => 15;
use constant CHECK_ORGANIZATION_EN => 5;
use constant CHECK_ORGANIZATION_CS => 6;
use constant CHECK_ENDPOINTS => 7;
use constant CHECK_SAML20 => 8;
use constant CHECK_SAML11 => 9;
use constant CHECK_SAML10 => 10;
use constant CHECK_X509CERTIFICATE => 11;
use constant CHECK_EXTENSIONS_SCOPE => 12;
use constant CHECK_DISCOVERY_RESPONSE_BINDING => 13;
use constant CHECK_UI_INFO => 14;

my $smd_ns     = 'urn:mace:shibboleth:metadata:1.0';
my $md_ns      = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $ds_ns      = 'http://www.w3.org/2000/09/xmldsig#';
my $idpdisc_ns = 'urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol';
my $eduidmd_ns = "http://eduid.cz/schema/metadata/1.0";
my $mdui_ns    = "urn:oasis:names:tc:SAML:metadata:ui";

my $saml2_metadata_schema = '/usr/share/xml/opensaml/saml-schema-metadata-2.0.xsd';
$XML::LibXML::Error::WARNINGS=0;

sub checkXMLValidity {
  my $xml = shift;
  my $schema = shift;

  return (undef, ['Empty String', '']) if ((not defined($xml)) or ($xml eq ''));

  # test jestli se XML da vubec naparsovat
  my $parser = XML::LibXML->new;
  my $doc;
  eval {
    $doc = $parser->parse_string($xml);
  };

  if ($@) {
    return (undef, ["$@", '']);
  };

  # test validity vuci schematu
  eval {
    #if (not defined($LibXMLSchema)){
      my $LibXMLSchema = XML::LibXML::Schema->new(
					       location => $schema
					      );
    #};
    $LibXMLSchema->validate($doc);
  };

  if ($@) {
    my $msg = $@;
    $msg =~ s/\n//g;
    if ($msg =~ /^(unknown-[0-9a-f\: ]+)/) {
      my $fname = $1;
      $msg =~ s/$fname//g;
    };
    return (undef, [$msg, ''], $doc);
  };


  return (1, undef, $doc);
};

sub checkTechnicalContact {
  my $dom = shift;

  foreach my $cp ($dom->getElementsByTagNameNS($md_ns, 'ContactPerson')) {
    my $contactType = lc($cp->getAttribute('contactType') || '');
    if ($contactType eq 'technical') {
      my $email = getXMLelementAStext($cp, 'EmailAddress') || getXMLelementAStext($cp, 'md:EmailAddress');

      return (undef, ['Technical contact must have EmailAddress.', $cp->nodePath])
	if (not (defined($email)));

      return 1;
    };
  };

  return (undef, ['Technical contact is missing.', $dom->nodePath]);
};

sub checkOrganization {
  my $node = shift;
  my $elements = shift;

  my @org = ($node->getElementsByTagNameNS($md_ns, 'Organization'));
  my $num_org = scalar @org;

  if ($num_org==1) {
    my @missing;
    my $org = $org[0];

    if ($org->parentNode->nodeName !~ /EntityDescriptor/) {
      return(undef, ['Organization element must be child of EntityDescriptor.', $org->nodePath]);
    };
  } elsif ($num_org==0) {
    return(undef, ['Missing Organization element.', $node->nodePath]);
  } else {
    return(undef, ['Found multiple Organization elements. There must be exactly one.',
		  $org[0]->parentNode->nodePath]);
  };

  return 1;
};

sub _checkOrganization {
  my $node = shift;
  my $elements = shift;
  my $lang = shift;

  my @org = ($node->getElementsByTagNameNS($md_ns, 'Organization'));
  my $num_org = scalar @org;

  if ($num_org==1) {
    my @missing;
    my $org = $org[0];

    foreach my $oe (@{$elements}) {
      my $found_lang = 0;
      my @oe = ($org->getElementsByTagNameNS($md_ns, $oe));
      foreach my $oe (@oe) {
	$found_lang = 1 if ($oe->getAttribute('xml:lang') eq $lang);
      };
      push @missing, "$oe \@lang='$lang'" unless ($found_lang);	
    };

    if (@missing) {
      my $msg = sprintf("Organization: missing ".join(', ', @missing)).".";
      return(undef, [$msg, $org->nodePath]);
    };

  };

  return 1;
};

sub checkOrganizationEN {
  my $dom = shift;

  return _checkOrganization($dom,
			    ['OrganizationName', 'OrganizationDisplayName', 'OrganizationURL'],
			    'en');
};

sub checkOrganizationCS {
  my $dom = shift;

  return _checkOrganization($dom,
			    ['OrganizationDisplayName'],
			    'cs');
};

sub checkLocation {
  my $node = shift;
  my @msg;

  my $res = _checkLocation($node, \@msg);

  if (@msg) {
    return (undef, @msg);
  };

  return 1;
};

sub _checkLocation {
  my $node = shift;
  my $msg = shift;

  if ($node->can('hasAttribute')) {
    if ($node->hasAttribute('Location')) {
      my $loc = $node->getAttribute('Location') || '';
      my $name = $node->nodeName;
      my $path = $node->nodePath;
      unless ($loc =~ /^https:\/\//i) {
	my $err = ["HTTPS usage is required.", $path];
	push @{$msg}, $err;
      };
      if ($loc =~ /:\/\/localhost/i) {
	my $err = ["Localhost is not permited as EndPoint.", $path];
	push @{$msg}, $err;
      };
      if ($loc =~ /:\/\/[0-9\+.]+\//) {
	my $err = ["IP address is not permited as EndPoint.", $path];
	push @{$msg}, $err;
      };
    };
  };

  foreach my $child ($node->childNodes) {
    _checkLocation($child, $msg);
  };

  return 1;
};

my $samlRules =
  {
   'IDPSSODescriptor' =>
     {
      'urn:mace:shibboleth:1.0' =>
         {
	  'NameIDFormat' => ['urn:mace:shibboleth:1.0:nameIdentifier'],
	  'SingleSignOnService' => ['urn:mace:shibboleth:1.0:profiles:AuthnRequest'],
	 },
       'urn:oasis:names:tc:SAML:1.1:protocol' =>
          {
 	  'NameIDFormat' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'],
 	  'SingleSignOnService' => ['urn:mace:shibboleth:1.0:profiles:AuthnRequest'],
 	 },
      'urn:oasis:names:tc:SAML:2.0:protocol' =>
         {
	  'NameIDFormat' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
			     'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
	  'SingleSignOnService' => ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'],
	 },
     },
   'SPSSODescriptor' =>
     {
      'urn:mace:shibboleth:1.0' =>
         {
	  'NameIDFormat' => ['urn:mace:shibboleth:1.0:nameIdentifier'],
	  'AssertionConsumerService' => ['urn:mace:shibboleth:1.0:profiles:AuthnRequest'],
	 },
       'urn:oasis:names:tc:SAML:1.1:protocol' =>
          {
 	  'NameIDFormat' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'],
 	  'AssertionConsumerService' => ['urn:mace:shibboleth:1.0:profiles:AuthnRequest'],
 	 },
      'urn:oasis:names:tc:SAML:2.0:protocol' =>
         {
	  'NameIDFormat' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
			     'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'],
	  'AssertionConsumerService' => ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'],
	 },
      },
  };

sub checkSAML {
  my $node = shift;
  my $IdP = shift;
  my $version = shift;
  my $mandatory = shift || 1;

  my $SSODescriptor;
  if ($IdP) {
    $SSODescriptor = $node->getElementsByTagNameNS($md_ns, 'IDPSSODescriptor')->[0];
  } else {
    $SSODescriptor = $node->getElementsByTagNameNS($md_ns, 'SPSSODescriptor')->[0];
  };
  return (undef, ["Document is missing SP/IDPSSODescriptor", $node->nodePath]) unless ($SSODescriptor);

  my @problems;

  if ($SSODescriptor->getAttribute('protocolSupportEnumeration') =~ /$version/) {
    my $SSOnodeName = $SSODescriptor->nodeName;
    $SSOnodeName =~ s/^.*://;

    my @NameIDFormat = @{$samlRules->{$SSOnodeName}->{$version}->{NameIDFormat}};

    my @error;
    my $found = 0;
    foreach my $NameIDFormat (@NameIDFormat) {
      my $f = 0;
      foreach my $nIDfElement (@{$node->getElementsByTagNameNS($md_ns, 'NameIDFormat')}) {
	$f++ if ($nIDfElement->textContent eq $NameIDFormat);
      };

      unless ($f) {
	push @error, ["NameIDFormat suport is missing required $NameIDFormat.",
		      $SSODescriptor->nodePath];
      };
    };
    if ($IdP) {
      push @problems, @error if ($found<@NameIDFormat);
    } else {
      push @problems, @error if ($found<0);
    };

    my $EndPointElementName = 'SingleSignOnService';
    $EndPointElementName = 'AssertionConsumerService' unless ($IdP);
    my @EndPoints = @{$samlRules->{$SSOnodeName}->{$version}->{$EndPointElementName}};

    @error = ();
    $found = 0;
    foreach my $EndPoint (@EndPoints) {
      my $f = 0;
      foreach my $epElement (@{$node->getElementsByTagNameNS($md_ns, $EndPointElementName)}) {
	$f++ if ($epElement->getAttribute('Binding') =~ /$EndPoint/);
      };

      unless ($f) {
	push @error, ["$EndPointElementName support is missing required $EndPoint.",
		      $node->nodePath];
      };
      $found += $f;
    };
    if ($IdP) {
      push @problems, @error if ($found<@NameIDFormat);
    } else {
      push @problems, @error if ($found<0);
    };

    if (@problems) {
      return (undef, @problems);
    };
  } else {
    return (undef, ["IDPSO|SPSSODescriptor must define $version support.", $node->nodePath]) if ($mandatory);
  };

  return 1;
};

sub checkSAML20 {
  my $node = shift;

  foreach my $descriptor ($node->getElementsByTagNameNS($md_ns, 'SPSSODescriptor'),
			  $node->getElementsByTagNameNS($md_ns, 'IDPSSODescriptor')) {
    my $protocols = $descriptor->getAttribute('protocolSupportEnumeration');
    return 1 if ($protocols =~ /urn:oasis:names:tc:SAML:2.0:protocol/);
  };

  return (undef, 'IDPSO|SPSSODescriptor must declare SAML2.0 support');
};

sub checkX509Certificate {
  my $node = shift;
  my $days = 30;
  my $reqKeyLength = 2048;

  my %certs;
  my $tempDir = tempdir(CLEANUP => 1);

  foreach my $keyDescriptor ($node->getElementsByTagNameNS($md_ns, 'KeyDescriptor')) {
    my $keyUse = $keyDescriptor->getAttribute('use') || '';

    my @problems;
    foreach my $ds_x509cert ($keyDescriptor->getElementsByTagNameNS($ds_ns, 'X509Certificate')) {
      my $pem = $ds_x509cert->textContent;
      my $der;
      eval {
	local $SIG{__WARN__} = sub {};
	$der = decode_base64($pem);
      };
      my $x509;
      eval { $x509 = Crypt::OpenSSL::X509->new_from_string($der, Crypt::OpenSSL::X509::FORMAT_ASN1); };
      if ($@) {
	my $error = $@;
	$error =~ s/^.*: *//;
	$error =~ s, at lib/emd2/Checker.pm.*,,;
	$error =~ s/\s+$//;
	return (undef, [$error, $ds_x509cert->nodePath]);
      };

      # -- Kontrola platnosti ------------------------------
      my $notAfter = $x509->notAfter;
      # Prohodit rok a casovou zonu
      $notAfter =~ s/(\d{4})\s+(\w+)$/$2 $1/;
      $notAfter = UnixDate(ParseDate($notAfter), "%s");
      my $serial = $x509->serial || '';
      if (($notAfter-time) < 0) {
	my $msg = sprintf('Certificate subject="%s", serial=%s, issued="%s" is expired.',
			$x509->subject, $serial, $x509->issuer, $x509->notAfter);
	push @problems, [$msg, $ds_x509cert->nodePath];
      } elsif (($notAfter-time) < ($days*24*60*60)) {
	my $msg = sprintf('Certificate subject="%s", serial=%s, issued="%s" is valid until "%s", that is less than $days days.',
			$x509->subject, $serial, $x509->issuer, $x509->notAfter);
	push @problems, [$msg, $ds_x509cert->nodePath];
      } else {
	# Certificate is valid
	# -- Kontrola delky privatniho klice -----------------
	open(OPENSSL, "| openssl x509 -noout -text -inform der >$tempDir/crt");
	print OPENSSL $der;
	close(OPENSSL);

	open(CRT, "<$tempDir/crt");
	my $keyLength;
	while(my $line = <CRT>) {
	  if ($line =~ /RSA Public Key.*\((\d+)\s+bit\)/) {
	    $keyLength = $1;
	  };
	};
	close(CRT);

	if ($keyLength < $reqKeyLength) {
	  my $msg = sprintf('Certificate subject="%s", serial=%s, issued="%s" has key of length %d required is %d.',
			    $x509->subject, $serial, $x509->issuer, $keyLength, $reqKeyLength);
	  push @problems, [$msg, $ds_x509cert->nodePath];
	} else {
	  $certs{$keyUse}->{certOK} = 1;
	};
      };
    };

    push @{$certs{$keyUse}->{problems}}, @problems;
  };

  return (undef, ['Missing KeyDescriptor element.', $node->nodePath])
    if (scalar(keys %certs) == 0);

  my @problems;
  foreach my $keyUse (keys %certs) {
    if ((not exists($certs{$keyUse}->{certOK})) or ($certs{$keyUse}->{certOK} == 0)) {
      push @problems, @{$certs{$keyUse}->{problems}};
    };
  };

  if (@problems) {
    return (undef, @problems);
  };

  return 1;
};

sub checkEntityID {
  my $node = shift;

  my @IdP = $node->getElementsByTagNameNS($md_ns, 'IDPSSODescriptor');
  my $IdP = @IdP;
  my @SP = $node->getElementsByTagNameNS($md_ns, 'SPSSODescriptor');
  my $SP = @SP;

  my $SSODescriptor;
  $SSODescriptor = $IdP[0] if $IdP;
  $SSODescriptor = $SP[0] if $SP;

  return (undef, ["Document is missing SP/IDPSSODescriptor", $node->nodePath]) unless ($SSODescriptor);

  my $v10 = 0;
     $v10 = 1 if ($SSODescriptor->getAttribute('protocolSupportEnumeration') =~ /urn:mace:shibboleth:1.0/);

  my $v11 = 0;
     $v11 = 1 if ($SSODescriptor->getAttribute('protocolSupportEnumeration') =~ /urn:oasis:names:tc:SAML:1.1:protocol/);

  my $v20 = 0;
     $v20 = 1 if ($SSODescriptor->getAttribute('protocolSupportEnumeration') =~ /urn:oasis:names:tc:SAML:2.0:protocol/);

  return (undef, ['EntityDescriptor is missing entityID attribute', $node->nodePath], $IdP, $SP, $v10, $v11, $v20)
    unless ($node->hasAttribute('entityID'));
  my $entityID = $node->getAttribute('entityID');
  unless ($entityID =~ /^http[s]{0,1}:\/\//i) {
    return (undef, ["Entity ID must start with https:// or http://", $node->nodePath], $IdP, $SP, $v10, $v11, $v20);
  };
  if ($entityID =~ /:\/\/localhost\//) {
    return (undef, ["Entity ID must not be localhost.", $node->nodePath], $IdP, $SP, $v10, $v11, $v20);
  };
  if ($entityID =~ /:\/\/[0-9\.]+\//) {
    return (undef, ["Entity ID must not be IP address.", $node->nodePath], $IdP, $SP, $v10, $v11, $v20);
  };

  my @republishTargets;
  foreach my $republishTarget ($node->getElementsByTagNameNS($eduidmd_ns, 'RepublishTarget')) {
    push @republishTargets, $republishTarget->textContent;
  };

  #warn "$entityID: IdP=$IdP, SP=$SP, V1.0=$v10, V1.1=$v11, V2.0=$v20\n";

  return (1, undef, $IdP, $SP, $v10, $v11, $v20, \@republishTargets);
};

sub checkExtensionsScope {
  my $node = shift;

  my $path = $node->nodePath;
  foreach my $descriptor ($node->getElementsByTagNameNS($md_ns, 'IDPSSODescriptor')) {
    $path = $descriptor->nodePath;
    foreach my $extensions ($descriptor->getElementsByTagNameNS($md_ns, 'Extensions')) {
      $path = $extensions->nodePath;
      foreach my $extensions ($extensions->getElementsByTagNameNS($smd_ns, 'Scope')) {
	return 1;
      };
    };
  };

  return (undef, ["IDPSSODescriptor/Extensions/Scope is missing. Found '$path'.", $node->nodePath]);
};

sub checkUIInfo {
  my $node = shift;

  my @UIinfo;
  my $path = $node->nodePath;
  foreach my $descriptor ($node->getElementsByTagNameNS($md_ns, 'IDPSSODescriptor'),
			  $node->getElementsByTagNameNS($md_ns, 'SPSSODescriptor')) {
    $path = $descriptor->nodePath;
    foreach my $extensions ($descriptor->getElementsByTagNameNS($md_ns, 'Extensions')) {
      $path = $extensions->nodePath;
      foreach my $UIinfo ($extensions->getElementsByTagNameNS($mdui_ns, 'UIInfo')) {
	push @UIinfo, $UIinfo;
      };
    };
  };

  if (@UIinfo) {
    # Opravdu tech UIInfo muze byt vic? Spis asi nee ne?
    foreach my $UIinfo (@UIinfo) {
      foreach my $elementName ('DisplayName', 'Description') {
	if (my $elements = $node->getElementsByTagNameNS($mdui_ns, $elementName)) {
	  my @lang;
	  foreach my $element (@{$elements}) {
	    my $elementValue = $element->textContent || '';
	    if ($elementValue =~ /^\s*$/m) {
	      return (undef, ['Element '.$elementName.' may not be empty.', $element->nodePath]);
	    };
	    push @lang, $element->getAttribute('xml:lang') || '';
	  };
	  foreach my $lang ('en', 'cs') {
	    unless (grep {$_ eq $lang} @lang) {
	      return (undef, ['Element '.$elementName.' must have lang='.$lang.' version.', $UIinfo->nodePath]);
	    };
	  };
	} else {
	  return (undef, ['UIInfo is missing required '.$elementName.' element.', $UIinfo->nodePath]);
	};
      };
    };
    # Zadny problem nenalezen, tak to asi bude OK
    return 1;
  } else {
    return (undef, ["IDPSSODescriptor|SPSSODescriptor/Extensions/UIInfo is missing. Found '$path'.",
		    $node->nodePath]);
  };
};


sub checkDiscoveryResponseBinding {
  my $node = shift;

  foreach my $dr ($node->getElementsByTagNameNS($idpdisc_ns, 'DiscoveryResponse')) {
#    die $dr->toString;
    return (undef, ['DiscoveryResponse is missing required Binding attribute.', $dr->nodePath])
      unless ($dr->hasAttribute('Binding'));
  };

  return 1;
};

sub print_error {
  my $code = shift;
  my $message = shift || 'Unknown error';

  warn "$code: $message\n";
};

sub checkEntityDescriptor {
  my $xml = shift;
  my @errors;

  my ($res, $message, $dom);

  foreach my $schema (#$saml2_metadata_schema,
		      '/home/semik/proj/emd2/schema/eduidmd.xsd') {
    ($res, $message, $dom) = checkXMLValidity($xml, $schema);
    if ((not defined($res)) and (not defined($dom))) {
      my @h;
      push @h, CHECK_XML_VALIDITY, $message;
      my %h = @h;

      return (CHECK_FAILED, \%h);
    };
    push @errors, (CHECK_XML_VALIDITY, $message) unless($res);
  };

  my $root = $dom->documentElement;

  my $IdP = 0;
  my $SP = 0;
  my $v10 = 0;
  my $v11 = 0;
  my $v20 = 0;
  my $republishTargets = [];
  ($res, $message, $IdP, $SP, $v10, $v11, $v20, $republishTargets) = checkEntityID($root);
  push @errors, (CHECK_ENTITYID, $message) unless($res);

  ($res, $message) = checkSAML($root, $IdP, 'urn:oasis:names:tc:SAML:2.0:protocol', 1);
  push @errors, (CHECK_SAML20, $message) unless($res);

  if ($v11) {
    ($res, $message) = checkSAML($root, $IdP, 'urn:oasis:names:tc:SAML:1.1:protocol', 1);
    # SEMIK 10.2.2013 nejsem si jistej proc bychom na tomhle meli trvat
    #push @errors, (CHECK_SAML11, $message) unless($res);
  };

  if ($v10) {
    ($res, $message) = checkSAML($root, $IdP, 'urn:mace:shibboleth:1.0', 1);
    push @errors, (CHECK_SAML10, $message) unless($res);
  };

  ($res, $message) = checkTechnicalContact($root);
  push @errors, (CHECK_TECHNICAL_CONTACT, $message) unless($res);

  ($res, $message) = checkOrganization($root, 1);
  push @errors, (CHECK_ORGANIZATION, $message) unless($res);

  ($res, $message) = checkOrganizationEN($root, 1);
  push @errors, (CHECK_ORGANIZATION_EN, $message) unless($res);

  ($res, $message) = checkOrganizationCS($root, 1);
  push @errors, (CHECK_ORGANIZATION_CS, $message) unless($res);

  ($res, $message) = checkLocation($root);
  push @errors, (CHECK_ENDPOINTS, $message) unless($res);

  ($res, $message) = checkX509Certificate($root);
  push @errors, (CHECK_X509CERTIFICATE, $message) unless($res);

  my $ui_info_checked = 0;
  if ($IdP) {
    ($res, $message) = checkExtensionsScope($root);
    push @errors, (CHECK_EXTENSIONS_SCOPE, $message) unless($res);
    $ui_info_checked = 1;

    ($res, $message) = checkUIInfo($root);
    push @errors, (CHECK_UI_INFO, $message) unless($res);
    $ui_info_checked = 1;
  };

  ($res, $message) = checkDiscoveryResponseBinding($root);
  push @errors, (CHECK_DISCOVERY_RESPONSE_BINDING, $message) unless($res);


  if (defined($republishTargets) and (scalar(@{$republishTargets})>0)) {
    # Spravce entity ji chce publikovat nekam dale. Je treba
    # zkontrolovat specificke pozadavky toho nekam dale.
    if (grep {$_ eq 'http://edugain.org/'} @{$republishTargets}) {
      unless ($ui_info_checked) {
	# Spravce chce entitu publikovat do edugainu takze je treba zkontrolovat mdui
	# Semik: 5.8.2013 - MDUI je povinne pro vsechny IdP proto tahle vyjimka
	($res, $message) = checkUIInfo($root);
	push @errors, (CHECK_UI_INFO, $message) unless($res);
	$ui_info_checked = 1;
      };
    };
  };

  if (@errors) {
    my %errors = @errors;
    return (CHECK_FAILED, \%errors, $dom);
  };


  return (CHECK_OK, undef, $dom);
};


1;
