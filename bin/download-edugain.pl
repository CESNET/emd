#!/usr/bin/perl -w

use strict;
use lib qw(lib);
use Data::Dumper;
use AppConfig qw(:expand);
use XML::LibXML;
use Sys::Syslog qw(:standard :macros);
use emd2::Utils qw (logger local_die startRun stopRun store_to_file prg_name);
use HTTP::Request;
use LWP::UserAgent;
use Date::Manip;
use Date::Format;

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
my $ua = LWP::UserAgent->new;
my $response = $ua->request($request);

logger(LOG_INFO, sprintf('Metadata download %s: %s',
			 $config->metadata_url,
			 $response->code));
if ($response->is_success) {
  # V podstate bychom vubec nemuseli stena metadata ukladat na disk v
  # tehle forme. Ulozene mame data rozsekana na entityID. Takze tady
  # se klidne muze stat ze ulozime neco co vubec neni XML. Dal
  # nasleduje validace podpisu u souboru na disku... opetovne cteni je
  # docela hloupe, ale mozna lepsi nez validovat neco na disku a pak
  # pracovat s necim jinym v pameti.
  if (store_to_file($config->metadata_file, $response->content)==0) {
    logger(LOG_INFO, sprintf('Nothing new. Terminating.'));
    exit 0;
  };
  logger(LOG_INFO, sprintf('Updated file %s with source metadata',
			   $config->metadata_file));
} else {
  logger(LOG_ERR, sprintf('Failed to download metadata.'));
  exit 1;
};

# Overeni podpisu.
# xmlsec1 --verify --trusted-pem /home/edugain/edugain-cert.pem  /tmp/edugain-10.xml
# Bohuzel xmlsec1 to nezvladne, tak do vyreseni to zatim neoverujeme.

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

# Overeni
eval {
  my $LibXMLSchema = XML::LibXML::Schema->new(
					      location => $config->saml2_metadata_schema,
					     );
  $LibXMLSchema->validate($doc);
};
if ($@) {
  logger(LOG_ERR, $@);
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
my @add;
my %eduGain;
foreach my $ed ($doc->getElementsByTagNameNS($md_ns, 'EntityDescriptor')) {
  my $entityID = $ed->getAttribute('entityID');
  # Nakonec jsme se s Milanem dohodli ze reseni platnosti nechame na ucastnicicih
  #$ed->removeAttribute('cacheDuration') if $ed->hasAttribute('cacheDuration');
  #$ed->removeAttribute('validUntil') if $ed->hasAttribute('validUntil');

  my $id = $entityID;
  $id =~ s/http(|s):\/\///;
  $id =~ s/\/$//g;
  $id =~ s/\//%2F/g;

  if (exists $ignore_entityID{$entityID}) {
    logger(LOG_INFO, "Entity $entityID is on ignore_list: skipping.");
    next;
  };

  my $dom = XML::LibXML::Document->new('1.0', 'utf-8');
  $dom->setDocumentElement($ed);
  my $eds = $dom->toString;

  $eduGain{$entityID}++;
  my $file = $config->metadata_dir."/$id.xml";

  my $stf = store_to_file($file, $eds);
  if ($stf == 1) {
    $update++;
    logger(LOG_INFO, "Entity $entityID was changed -> updated $file.");
  } elsif ($stf == 2) {
    $update++;
    push @add, $file;
    logger(LOG_INFO, "New entity $entityID stored to $file.");
  } else {
    #logger(LOG_INFO, "Entity $entityID is still same.");
  };
};

my $eduGain = join("\n", sort keys %eduGain);
$update++ if (store_to_file($config->metadata_dir."/edugain.tag", $eduGain));

if (@add) {
  my $cmd = '/usr/bin/svn add --username svnwriter --config-dir /home/edugain/.svnc '.join(" ", @add);
  open(SVNC, "$cmd 2>&1 |") or do {
    logger(LOG_ERR, "Failed to execute svn add: $?");
    exit 1;
  };
  my @out = <SVNC>;
  close(SVNC);
  my $ret = $? >> 8;
  if ($ret > 0) {
    logger(LOG_ERR, "svn add terminated with error_code=$ret. Output:");
    foreach my $line (@out) { logger(LOG_ERR, $line); };	
    exit 1;
  } else {
    logger(LOG_INFO, 'Sucessfull commit: '.$cmd.", terminated with $?");
    foreach my $line (@out) { logger(LOG_ERR, $line); };	
  };
};

if ($update) {
  my $cmd = '/usr/bin/svn commit --username svnwriter --config-dir /home/edugain/.svnc '.
    $config->metadata_dir.' -m "Automatic update by '.prg_name.'"';
  open(SVNC, "$cmd 2>&1 |") or do {
    logger(LOG_ERR, "Failed to execute svn commit: $?");
    exit 1;
  };
  my @out = <SVNC>;
  close(SVNC);
  my $ret = $? >> 8;
  if ($ret > 0) {
    logger(LOG_ERR, "svn add terminated with error_code=$ret. Output:");
    foreach my $line (@out) { logger(LOG_ERR, $line); };	
    exit 1;
  } else {
    logger(LOG_INFO, "Some entities in store were updated.");
    foreach my $line (@out) { logger(LOG_ERR, $line); };	
  };
};
