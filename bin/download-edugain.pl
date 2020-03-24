#!/usr/bin/perl -w

# dep: libfile-touch-perl libgit-repository-perl

use strict;
use lib qw(emd2/lib lib);
use Data::Dumper;
use AppConfig qw(:expand);
use XML::LibXML;
use Sys::Syslog qw(:standard :macros);
use emd2::Utils qw (logger local_die startRun stopRun store_to_file prg_name);
use HTTP::Request;
use LWP::UserAgent;
use Date::Manip;
use Date::Format;
use File::Temp qw(tempfile);
use File::Touch;
use Git::Repository;
use Net::SSL;
use IO::Socket::SSL;
use utf8;
use open ':encoding(UTF-8)';

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';

sub entityID2fname {
    my $id = shift;

    $id =~ s/http(|s):\/\///;
    $id =~ s/\/$//g;
    $id =~ s/\//%2F/g;

    return $id;
};

sub load_ignore_list {
  my $file = shift;
  my %ign;

  open(F, "<$file") or die "Failed to read: $file: $!";
  while (my $line=<F>) {
    $line =~ s/^\s*//g;
    $line =~ s/\s*$//g;

    $ign{$line}++;
  };

  return %ign;
};

sub verify_signature {
  my $content = shift;
  my $signing_cert = shift;

  my $parser = XML::LibXML->new;
  my $doc = $parser->parse_string($content);
  my $signature = $doc->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->[0];
  my $keyInfo = $signature->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'KeyInfo')->[0];
  $keyInfo->unbindNode;

  my ($fh, $filename) = tempfile('/tmp/edugain-XXXXXX');
  print $fh $doc->toString;
  close ($fh);

  my ($fh_xmlsec1, $xmlsec1) = tempfile('/tmp/xmllsec-XXXXXX');
  `/usr/bin/xmlsec1 --verify --pubkey-pem $signing_cert --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor $filename >$xmlsec1 2>&1`;
  my $err = $? >> 8;

  unless ($err) {
    unlink($xmlsec1);
    unlink($filename);
    return 1;
  } else {
    open(F, "<$xmlsec1");
    foreach my $line (<F>) { logger(LOG_ERR, $line); };
    logger(LOG_ERR, 'Failed to execute xmlsec1: '.$err);

    unlink($xmlsec1);
    unlink($filename);

    return;
  };

return;

};

sub filter_AttributeConsumingService {
  my $entityID = shift;
  my $entity = shift;

  my $known_rq = {};
  my $modified = 0;

  foreach my $acs (@{$entity->getElementsByTagNameNS($saml20_ns, 'AttributeConsumingService')}) {
    foreach my $rq (@{$entity->getElementsByTagNameNS($saml20_ns, 'RequestedAttribute')}) {
      my $name = $rq->getAttribute('Name');
      if (exists $known_rq->{$name}) {
	$modified++;
	$acs->removeChild($rq);
	logger(LOG_INFO, "Entity $entityID has duplicate AttributeConsumingService/RequestedAttribute[\@Name=$name], removed.");
      } else {
	$known_rq->{$name}++;
      }
    };
  };

  return $modified;
};

startRun;

my $md_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },
   cfg                   => { DEFAULT => '' },
   ignore_list           => { DEFAULT => undef },
   metadata_dir          => { DEFAULT => undef },
   metadata_file         => { DEFAULT => undef },
   metadata_url          => { DEFAULT => undef },
   saml2_metadata_schema => { DEFAULT => undef },
   signing_cert          => { DEFAULT => undef },
   commit_log            => { DEFAULT => '/tmp/download-edugain.log' },
  );

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";


my $request = HTTP::Request->new('GET', $config->metadata_url);
#if( -f $config->metadata_file ) {
#  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
#      $atime,$mtime,$ctime,$blksize,$blocks) = stat($config->metadata_file);
#  warn $mtime;
#  my $ims = time2str(localtime($mtime));
#  warn $ims;
#  $request->header('If-Modified-Since', $ims);
#};
# debugovani SSL:
#   perl -MIO::Socket::SSL=debug4 ...
my $ua = LWP::UserAgent->new(
		             ssl_opts => { verify_hostname => 1,
					   SSL_ca_path => '/etc/ssl/certs' }
);
my $response = $ua->request($request);

logger(LOG_INFO, sprintf('Metadata download %s: %s',
			 $config->metadata_url,
			 $response->code));
if ($response->is_success) {
  # Overeni podpisu
  if (verify_signature($response->content, $config->signing_cert)) {
    # V podstate bychom vubec nemuseli stena metadata ukladat na disk v
    # tehle forme. Ulozene mame data rozsekana na entityID. Takze tady
    # se klidne muze stat ze ulozime neco co vubec neni XML. Dal
    # nasleduje validace podpisu u souboru na disku... opetovne cteni je
    # docela hloupe, ale mozna lepsi nez validovat neco na disku a pak
    # pracovat s necim jinym v pameti.
    my $metadata = $response->content;

    # LWP doda data jako serii bajtu nikoli UTF8 string
    utf8::decode($metadata) unless utf8::is_utf8($metadata);

    if (store_to_file($config->metadata_file, $metadata)==0) {
      touch($config->metadata_file);
      logger(LOG_INFO, sprintf('Nothing new. Terminating.'));
      stopRun;
      exit 0;
    };
    logger(LOG_INFO, sprintf('Updated file %s with source metadata',
			     $config->metadata_file));
  } else {
    logger(LOG_INFO, sprintf('Failed to verify downloaded XML data signature. Terminating.'));
    exit 0;
  };
} else {
  logger(LOG_ERR, sprintf('Failed to download metadata.'));
  exit 1;
};

my $parser = XML::LibXML->new;
open(F, '<'.$config->metadata_file) or do {
  logger(LOG_ERR, sprintf('Failed to open file %s: %s',
			  $config->metadata_file, $!));
  exit 1;
};
my $str = join('', <F>);
close(F);

my $doc;
eval {
  $doc = $parser->parse_string($str);
};
if ($@) {
  logger(LOG_ERR, $@);
  exit 1;
};

# Odstraneni RoleDescriptor

# Od cca 14.11.2014 jsou v eduGAINu entity ktere obsahuji
# RoleDescriptor, coz by asi nebylo tak zly, ale prusvih je ze hodota
# v xsi:type neni definovana v beznych schematech a pak to kolabuje:
#
#Nov 17 03:56:28 emd download-edugain.pl[30454]: unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor', attribute '{http://www.w3.org/2001/XMLSchema-instance}type': The QName value '{http://docs.oasis-open.org/wsfed/federation/200706}ApplicationServiceType' of the xsi:type attribute does not resolve to a type definition.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor': The type definition is abstract.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor', attribute '{http://www.w3.org/2001/XMLSchema-instance}type': The QName value '{http://docs.oasis-open.org/wsfed/federation/200706}SecurityTokenServiceType' of the xsi:type attribute does not resolve to a type definition.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor': The type definition is abstract.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor', attribute '{http://www.w3.org/2001/XMLSchema-instance}type': The QName value '{http://docs.oasis-open.org/wsfed/federation/200706}ApplicationServiceType' of the xsi:type attribute does not resolve to a type definition.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor': The type definition is abstract.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor', attribute '{http://www.w3.org/2001/XMLSchema-instance}type': The QName value '{http://docs.oasis-open.org/wsfed/federation/200706}SecurityTokenServiceType' of the xsi:type attribute does not resolve to a type definition.
#unknown-a685810:0: Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor': The type definition is abstract.
# Je treba pridat schema:
# https://github.com/ukf/ukf-meta/blob/master/mdx/schema/ws-federation.xsd

# Semik: Obavam se to udela nasim SP/IdP problem s validaci, takze
# tenhle element odstranuji. Jenze co kdyz to bude nekdo potrebovat?

foreach my $roleDescriptor (@{$doc->getElementsByTagNameNS($saml20_ns, 'RoleDescriptor')}) {
  $roleDescriptor->unbindNode();
};

# Overeni
eval {
  my $LibXMLSchema = XML::LibXML::Schema->new(
					      location => $config->saml2_metadata_schema,
					     );
  $LibXMLSchema->validate($doc);
};
if ($@) {
  logger(LOG_ERR, $@);
  logger(LOG_ERR, "Failed to valiadate metadata against schema - terminating");
  exit 1;
};

# Nacteni ignore listu
my %ignore_entityID = ('edugain.tag', 1);
foreach my $ignore_list (map { $str=$_; $str =~ s/^ //; $str =~ s/ $//; $str; }
			 split(',', $config->ignore_list)) {

  %ignore_entityID = (
		      %ignore_entityID,
		      load_ignore_list($ignore_list)
		     );
};

my $update = 0;
my @git_log;
my @add;
my @updated;
my %eduGain;
foreach my $ed ($doc->getElementsByTagNameNS($md_ns, 'EntityDescriptor')) {
  my $entityID = $ed->getAttribute('entityID');
  # Nakonec jsme se s Milanem dohodli ze reseni platnosti nechame na ucastnicicih
  #$ed->removeAttribute('cacheDuration') if $ed->hasAttribute('cacheDuration');
  #$ed->removeAttribute('validUntil') if $ed->hasAttribute('validUntil');

  my $id = entityID2fname($entityID);

  filter_AttributeConsumingService($entityID, $ed);

  if (exists $ignore_entityID{$entityID}) {
    logger(LOG_INFO, "Entity $entityID is on ignore_list: skipping.");
    next;
  };

  my $dom = XML::LibXML::Document->new('1.0', 'utf-8');
  $dom->setDocumentElement($ed);
  my $eds = $dom->toString;
  utf8::decode($eds) unless utf8::is_utf8($eds);

  $eduGain{$entityID}++;
  my $file = $config->metadata_dir."/$id.xml";

  my $stf = store_to_file($file, $eds);
  if ($stf == 1) {
    $update++;
    logger(LOG_INFO, "Entity $entityID was changed -> updated $file.");
    push @git_log, "u $file";
    push @updated, $file;
  } elsif ($stf == 2) {
    $update++;
    push @add, $file;
    logger(LOG_INFO, "New entity $entityID stored to $file.");
  } else {
    #logger(LOG_INFO, "Entity $entityID is still same.");
  };
};

# zkontrolovat jestli se nam v adresari s metadaty nevali nejaky
# zastaraly entity
opendir(my $dh, $config->metadata_dir) || die "Can't opendir ".$config->metadata_dir.": $!";
my @files = grep { /\.xml$/ && -f $config->metadata_dir."/$_" } readdir($dh);
my %files = map { $_ => 1 } @files;
foreach my $entityID (keys %eduGain) {
    my $f = entityID2fname($entityID).'.xml';
    if (exists($files{$f})) {
	delete $files{$f};
    };
};
closedir $dh;

my $eduGain = join("\n", sort keys %eduGain);
$update++ if (store_to_file($config->metadata_dir."/edugain.tag", $eduGain));

my $r = Git::Repository->new(work_tree => $config->metadata_dir,
			     {quiet => 1}
    );

if (keys %files) {
    foreach my $file (keys %files) {
	$r->run('rm' => $file);
	my $ret = $? >> 8;
	if ($ret > 0) {
	    logger(LOG_ERR, "git rm $file terminated with error_code=$ret");
	    exit 1;
	} else {
	    logger(LOG_ERR, "git rm $file OK");
	    push @git_log, "d $file";
	};
    };

    $update++;
};

if (@add) {
    foreach my $file (@add) {
	$r->run('add' => $file);
	my $ret = $? >> 8;
	if ($ret > 0) {
	    logger(LOG_ERR, "git add $file terminated with error_code=$ret");
	    exit 1;
	} else {
	    logger(LOG_ERR, "git add $file OK");
	    push @git_log, "a $file";
	};
    };

    $update++;
};

if ($update) {
    my $first_line = 'updated '.scalar(@updated).'; added '.scalar(@add).'; removed '.scalar(keys %files).' by '.prg_name;
    my $mdir_reg = $config->metadata_dir.'(/|)';
    logger(LOG_INFO, $first_line);
    open(COMMIT_LOG, ">".$config->commit_log);
    print COMMIT_LOG $first_line."\n\n";
    print COMMIT_LOG join("\n",
			  map { $_ =~ s,$mdir_reg,,; $_; } @git_log)."\n";
    close(COMMIT_LOG);
    $r->run('commit' => '-a', '-F', $config->commit_log);
    my $ret = $? >> 8;
    unlink($config->commit_log);
    if ($ret > 0) {
	logger(LOG_INFO, "git commit terminated with error_code=$ret");
	exit 1;
    } else {
	logger(LOG_INFO, "sucessfull commit");
	$r->run('push');
	my $ret = $? >> 8;
	if ($ret > 0) {
	    logger(LOG_INFO, "git commit terminated with error_coce=$ret");
	    exit 1;
	} else {
	    logger(LOG_INFO, "sucessfull push");
	};
    };
};

stopRun;
