#!/usr/bin/perl -w

# apt-get install libcrypt-openssl-x509-perl libmime-lite-perl

use strict;
use lib qw(emd2/lib lib);
use Data::Dumper;
use Date::Manip;
use XML::LibXML;
use Crypt::OpenSSL::X509;
use MIME::Base64 qw(decode_base64);
use MIME::Lite;
use Encode qw(encode);
use utf8;

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $saml20attr_ns = 'urn:oasis:names:tc:SAML:metadata:attribute';
my $saml20asrt_ns = 'urn:oasis:names:tc:SAML:2.0:assertion';
my $xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance';
my $ds_ns = 'http://www.w3.org/2000/09/xmldsig#';
my $mdrpi_ns = 'urn:oasis:names:tc:SAML:metadata:rpi';
my $mdui_ns = 'urn:oasis:names:tc:SAML:metadata:ui';
my $mdeduid_ns = 'http://eduid.cz/schema/metadata/1.0';

my $metadata = $ARGV[0]; 
my $parser = XML::LibXML->new;
open my $fh, $metadata or die "Failed to open $metadata: $!";
#binmode $fh, ":utf8";
my $string = join('', <$fh>);
my $xml;
eval {
    $xml = $parser->parse_string($string);
};
if ($@) {
    my $err = $@;
    die "Failed to parse file $metadata: $@";
};
close $fh;

my $days = 0;
my $root = $xml->documentElement;
foreach my $entity (@{$root->getElementsByTagNameNS($saml20_ns, 'EntityDescriptor')}) {
    my $entityID = $entity->getAttribute('entityID');
    
    # Zatim jen CZ
    next unless ($entityID =~ /\.cz\//);

    my %expired_certs;
    my $valid_certs = 0;
    foreach my $X509Certificate (@{$entity->getElementsByTagNameNS($ds_ns, 'X509Certificate')}) {
	my $pem = $X509Certificate->textContent;
	my $der;
	eval {
	    local $SIG{__WARN__} = sub {};
	    $der = decode_base64($pem);
	};

	my $x509;
	eval { $x509 = Crypt::OpenSSL::X509->new_from_string($der, Crypt::OpenSSL::X509::FORMAT_ASN1); };

	my $notAfter = $x509->notAfter;
	# Prohodit rok a casovou zonu
	$notAfter =~ s/(\d{4})\s+(\w+)$/$2 $1/;
	$notAfter = UnixDate(ParseDate($notAfter), "%s");
	my $serial = $x509->serial || '';
	if (($notAfter-time) < 0) {
	    $expired_certs{$x509->subject} = $x509;	    
	} else {
	    $valid_certs++;
	};
    };

    if (%expired_certs) {
	# Entita ma nejaky vyexpirovany certifikaty
	my @to;
	foreach my $contact (@{$entity->getElementsByTagNameNS($saml20_ns, 'ContactPerson')}) {
	    if ($contact->getAttribute('contactType') eq 'technical') {
		my $email = $contact->getElementsByTagNameNS($saml20_ns, 'EmailAddress')->[0];
		$email = $email->textContent;
		$email =~ s/^mailto://i;
		push @to, $email;
	    };
	};

	my $x509 = (values(%expired_certs))[0];

	# semik debug --------------------------------------
	#next;
	my $msg = 'Dobrý den,

entita
  '.$entityID.'
registrovaná v eduID.cz má v metadatech expirovaný certifikát. Jedná 
se o certifikát vydaný na jméno:
  '.$x509->subject.'
jehoz platnost skončila '.$x509->notAfter.'

Prosíme, zajistěte jeho výměnu/odstranění z metadat. 

Informace o certifikátech v eduID.cz:
  https://www.eduid.cz/cs/tech/certificates

Informace o postupu publikace nových metadat:
  https://www.eduid.cz/cs/tech/metadata-publication#publikace_metadat

S pozdravem

  eduID.cz tým';

	my $m = MIME::Lite->new(
	    From    => 'eduid-admin@eduid.cz',
	    Bcc     => 'eduid-admin@eduid.cz',
	    #To      => 'jan@tomasek.cz',
	    To      => join(', ', @to),
	    Subject => 'Vyexpirovany certifikat u '.$entityID,
	    Type    => 'text/plain; charset=UTF-8',
	    Data    => encode('utf8', $msg),
	    Encoding => 'quoted-printable',
	    );
	$m->send;
    };
};


