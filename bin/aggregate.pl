#!/usr/bin/perl -w

# apt-get install libdate-manip-perl libxml-libxml-perl libproc-processtable-perl libappconfig-perl libxml-tidy-perl

use strict;
use lib qw(emd2/lib lib);
use Data::Dumper;
use Date::Manip;
use XML::LibXML;
use XML::Tidy;
use Sys::Syslog qw(:standard :macros);
use AppConfig qw(:expand);
use emd2::Utils qw (logger local_die startRun stopRun);
use emd2::Checker qw (checkXMLValidity);
use utf8;

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1,
    CREATE => '.*',
   },

   cfg           => { DEFAULT => '' },

   metadata_dir  => { DEFAULT => '' },
   output_dir    => { DEFAULT => '' },

   sign_cmd      => { DEFAULT => undef },

   federations   => { DEFAULT => undef },

   force         => { DEFAULT => undef },

   max_age       => { DEFAULT => 12*60*60 }, # sekundy
   validity      => { DEFAULT => '30 days'}, # cokoliv dokaze ParseDate
  );

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance';
my $ds_ns = 'http://www.w3.org/2000/09/xmldsig#';
my $mdrpi_ns = 'urn:oasis:names:tc:SAML:metadata:rpi';
my $mdui_ns = 'urn:oasis:names:tc:SAML:metadata:ui';
my $mdeduid_ns = 'http://eduid.cz/schema/metadata/1.0';

my $schemaLocation = 'urn:oasis:names:tc:SAML:2.0:metadata saml-schema-metadata-2.0.xsd urn:mace:shibboleth:metadata:1.0 shibboleth-metadata-1.0.xsd http://www.w3.org/2000/09/xmldsig# xmldsig-core-schema.xsd';

my $IdP_tag = 'idp';
my $SP_tag = 'sp';

sub tidyEntityDescriptor {
  my $node = shift;

  $node->removeAttributeNS($saml20_ns, 'validUntil');
  $node->removeAttribute('ID');

  return $node;
};

sub load {
  my $dir = shift;
  my %md;

  opendir(DIR, $dir) || local_die "Can't opendir $dir: $!";
  my @files = grep { -f "$dir/$_" } readdir(DIR);
  closedir DIR;

  # load metadata elements
  foreach my $file (grep {$_ =~ /.xml$/} @files) {
    my $parser = XML::LibXML->new;
    open my $fh, "$dir/$file" or local_die "Failed to open $dir/$file: $!";
    #binmode $fh, ":utf8";
    my $string = join('', <$fh>);
    my $xml;
    eval {
      $xml = $parser->parse_string($string);
    };
    if ($@) {
      my $err = $@;
      local_die "Failed to parse file $dir/$file: $@";
    };
    close $fh;

    my $root = $xml->documentElement;
    my $entityID = $root->getAttribute('entityID');
    $md{$entityID}->{md} = tidyEntityDescriptor($root);
    my @stat = stat("$dir/$file");

    $md{$entityID}->{mtime} = $stat[9];
    if ($root->getElementsByTagNameNS($saml20_ns, 'IDPSSODescriptor')) {
      push @{$md{$entityID}->{tags}}, $IdP_tag;
    } elsif ($root->getElementsByTagNameNS($saml20_ns, 'SPSSODescriptor')) {
      push @{$md{$entityID}->{tags}}, $SP_tag;
    } else {
      local_die "entityID=$entityID neni SP ani IdP???";
    };

    # Zkontrolovat jestli entita nechce republishnout do nektery dalsi federace
    foreach my $rr (@{$root->getElementsByTagNameNS($mdeduid_ns, 'RepublishRequest')}) {
      foreach my $rt ($rr->childNodes) {
	if ($rt->nodeName =~ /:RepublishTarget$/) {
	  my $rt_value = $rt->textContent;

	  if ($rt_value eq 'http://edugain.org/') {
	    push @{$md{$entityID}->{tags}}, 'eduid2edugain';
	  };
	};
      };
    };
  };

  # load tag files
  foreach my $file (grep {$_ =~ /.tag$/} @files) {
    open(F, "$dir/$file") || local_die "Can't read $dir/$file: $!";
    my $tag = $file; $tag =~ s/\.tag$//;
    while (my $line = <F>) {
      chomp($line);
      next if ($line =~ /^#/);
      next if ($line =~ /^\s*$/);
      if (exists($md{$line})) {
	push @{$md{$line}->{tags}}, $tag;
      } else {
	logger(LOG_INFO, "Tag file \"$file\" contains unknown entityID \"$line\".");
      };
    };
  };

  return \%md;
};

sub filter {
  my $md = shift;
  my $filter = shift;

  my $f = join('+', sort @{$filter});

  my %md;
  my $mtime = 0;
  foreach my $entityID (keys %{$md}) {
    my $found = 0;
    foreach my $tag (@{$filter}) {
      $found++ if (grep {$_ eq $tag} @{$md->{$entityID}->{tags}});
    };

    #logger(LOG_DEBUG, "filter=$f; entityID=$entityID; found=$found\n");

    if ($found == @{$filter}) {
      $md{$entityID} = $md->{$entityID};
      $mtime = $md->{$entityID}->{mtime} if ($md->{$entityID}->{mtime} > $mtime);
    };
  };

  return (\%md, $mtime);
};

sub eduGAIN_root {
  my $doc_root = shift;

  $doc_root->setNamespace($mdrpi_ns, 'mdrpi', 0);
  $doc_root->setNamespace($mdui_ns, 'mdui', 0);

  #<Extensions>
  #    <mdrpi:PublicationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" creationInstant="2012-04-02T11:30:00Z" publisher="https://www.eduid.cz/edugain/edugain.xml">
  #        <mdrpi:UsagePolicy xml:lang="en">https://www.eduid.cz/edugain/tou.txt</mdrpi:UsagePolicy>
  #    </mdrpi:PublicationInfo>
  #</Extensions>

  my $tou_comment = new XML::LibXML::Comment(' Use of this metadata is subject to the Terms of Use at https://www.eduid.cz/edugain/tou.txt ');
  $doc_root->appendChild($tou_comment);

  my $extensions = new XML::LibXML::Element('Extensions');
  $doc_root->addChild($extensions);

  my $pub_info = new XML::LibXML::Element('mdrpi:PublicationInfo');
  $pub_info->setAttribute('publisher', 'https://metadata.eduid.cz/entities/eduid2edugain');
  my $ci = UnixDate(Date_ConvTZ(ParseDate('now'),UnixDate(ParseDate('now'), '%Z'), 'Z'), '%Y-%m-%dT%H:%M:%SZ');
  $pub_info->setAttribute('creationInstant', $ci);
  $extensions->addChild($pub_info);
  my $us_pol = new XML::LibXML::Element('mdrpi:UsagePolicy');
  $us_pol->setAttribute('xml:lang', 'en');
  $us_pol->appendText('https://www.eduid.cz/edugain/tou.txt');
  $pub_info->addChild($us_pol);
};

sub eduGAIN_entity {
  my $entity = shift;

  # Najit Extensions
  my @ext = $entity->getChildrenByTagNameNS($saml20_ns, 'Extensions');
  my $ext;
  unless (@ext) {
    # Nepovedlo se najit Extensions - takovahle entita by se vubec
    # nemela dostat do skladu, kontroluje se to pri vkladani.

    $ext = new XML::LibXML::Element('Extensions');
    $entity->insertBefore($ext, $entity->firstChild);
  } else {
    # Povedlo se a tak berem tu prvni. Puvodne se pracovalo s
    # getElementsByTagNameNS ktere hleda bez ohledu na hirerchaii.
    $ext = $ext[0];
  };

  # <mdrpi:RegistrationInfo xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" registrationAuthority="http://www.eduid.cz/">
  #   <mdrpi:RegistrationPolicy xml:lang="en">http://www.eduid.cz/wiki/_media/en/eduid/policy/policy_eduid_en-1_1.pdf</mdrpi:RegistrationPolicy>
  #   <mdrpi:RegistrationPolicy xml:lang="cs">http://www.eduid.cz/wiki/_media/eduid/policy/policy_eduid_cz-1_1-3.pdf</mdrpi:RegistrationPolicy>
  # </mdrpi:RegistrationInfo>

  my $ri = new XML::LibXML::Element('mdrpi:RegistrationInfo');
  $ri->setAttribute('registrationAuthority', 'http://www.eduid.cz/');
  $ext->addChild($ri);

  my $rp_en = new XML::LibXML::Element('mdrpi:RegistrationPolicy');
  $rp_en->setAttribute('xml:lang', 'en');
  $rp_en->appendText('http://www.eduid.cz/wiki/_media/en/eduid/policy/policy_eduid_en-1_1.pdf');
  $ri->addChild($rp_en);

  my $rp_cs = new XML::LibXML::Element('mdrpi:RegistrationPolicy');
  $rp_cs->setAttribute('xml:lang', 'cs');
  $rp_cs->appendText('http://www.eduid.cz/wiki/_media/eduid/policy/policy_eduid_cz-1_1-3.pdf');
  $ri->addChild($rp_cs);
};

sub aggregate {
  my $md = shift;
  my $name = shift;
  my $validUntil = shift;

  my $dom = XML::LibXML::Document->createDocument('1.0', 'utf-8');
  my $root = XML::LibXML::Element->new('EntitiesDescriptor');
  $dom->adoptNode($root);
  $dom->setDocumentElement($root);

  $root->setNamespace($saml20_ns);
  $root->setNamespace($xsi_ns, 'xsi', 0);
  $root->setNamespace($ds_ns, 'ds', 0);

  $root->setAttribute('Name', $name);
  $root->setAttribute('validUntil', $validUntil);
  $root->setAttributeNS($xsi_ns, 'schemaLocation', $schemaLocation);

  eduGAIN_root($root) if ($name eq 'eduid.cz-edugain');

  foreach my $entityID (keys %{$md}) {
    my $entity = $md->{$entityID}->{md}->cloneNode(1);
    eduGAIN_entity($entity) if ($name eq 'eduid.cz-edugain');
    $dom->adoptNode($entity);
    $root->addChild($entity);
  };

  return $dom;
};

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

startRun($config->cfg);

my $validUntil = UnixDate(ParseDate('30 days'), '%Y-%m-%dT%H:%M:%SZ');

my $md = load($config->metadata_dir);

foreach my $fed_id (split(/ *, */, $config->federations)) {
  my $fed_filters = $fed_id.'_filters';
  my $fed_name = $fed_id.'_name';

  foreach my $key (split(/ *, */, $config->$fed_filters)) {
    my ($entities, $mtime) = filter($md, [split(/\+/, $key)]);

    my $f = $config->output_dir."/$key-unsigned";
    my $export = 1;

    if (-f $f) {
      # Test jestli na disku je starsi fail nez ty co jsme nacetli ||
      # jestli neni fail na disku prilis stary || nebyl fail na disku
      # vytvoren v budoucnosti
      my @stat = stat($f);
      my $now = time;
      $export = ($stat[9] < $mtime) || ($now < $stat[9]) || (($now-$stat[9])>$config->max_age);
      logger(LOG_DEBUG, "Will overwrite file $f: src_mtime=$mtime, f_mtime=$stat[9].\n") if $export;
    };

    $export = 1 if ($config->force);

    if ($export) {
      logger(LOG_DEBUG,  "Exporting $key to file $f.");
      my $doc = aggregate($entities, $config->$fed_name, $validUntil);
      my $tidy = XML::Tidy->new('xml' => $doc->toString);
      $tidy->tidy();

      my $tidy_string = $tidy->toString;
      my ($res, $msg, $dom) = checkXMLValidity($tidy_string, 'emd2/schema/eduidmd.xsd');

      if ($res) {
	logger(LOG_DEBUG, "Newly created XML document is valid with schema.");

	open(F, ">$f") or local_die "Cant write to $f: $!";
	binmode F, ":utf8";
	print F $tidy_string;
	close(F);

	if (defined($config->sign_cmd)) {
	  my $cmd = sprintf($config->sign_cmd, $f, $config->output_dir.'/'.$key);
	  logger(LOG_DEBUG,  "Signing: '$cmd'");
	  my $cmd_fh;
	  open(CMD, "$cmd 2>&1 |") or local_die("Failed to exec $cmd: $!");
	  my @cmd_out = <CMD>;
	  close(CMD);
	  my $ret = $? >> 8;
	  if ($ret > 0) {
	    logger(LOG_ERR,  "Command $cmd terminated with error_code=$ret. Output:");
	    foreach my $line (@cmd_out) {
	      logger(LOG_ERR, $line);
	    };
	  };
	};
      } else {
	logger(LOG_ERR, "Newly created XML document is invalid: ".$msg->[0]);
	exit 1;
      };
    };
  };
};

stopRun($config->cfg);
