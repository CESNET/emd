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

   svn_config_dir        => { DEFAULT => undef },

   metadata_dir  => { DEFAULT => '' },
   output_dir    => { DEFAULT => '' },

   sign_cmd      => { DEFAULT => undef },

   federations   => { DEFAULT => undef },

   force         => { DEFAULT => undef },

   max_age       => { DEFAULT => 12*60*60 }, # sekundy
   validity      => { DEFAULT => '25 days'}, # cokoliv dokaze ParseDate
  );

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $saml20attr_ns = 'urn:oasis:names:tc:SAML:metadata:attribute';
my $saml20asrt_ns = 'urn:oasis:names:tc:SAML:2.0:assertion';
my $xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance';
my $ds_ns = 'http://www.w3.org/2000/09/xmldsig#';
my $mdrpi_ns = 'urn:oasis:names:tc:SAML:metadata:rpi';
my $mdui_ns = 'urn:oasis:names:tc:SAML:metadata:ui';
my $mdeduid_ns = 'http://eduid.cz/schema/metadata/1.0';

my $clarin_tag = 'http://eduid.cz/uri/sp-group/clarin';
my $mefanet_tag = 'http://eduid.cz/uri/group/mefanet';

my $libraries_tag = 'http://eduid.cz/uri/idp-group/library';
my $avcr_tag = 'http://eduid.cz/uri/idp-group/avcr';
my $university_tag = 'http://eduid.cz/uri/idp-group/university';

my $schemaLocation = 'urn:oasis:names:tc:SAML:2.0:metadata saml-schema-metadata-2.0.xsd urn:mace:shibboleth:metadata:1.0 shibboleth-metadata-1.0.xsd http://www.w3.org/2000/09/xmldsig# xmldsig-core-schema.xsd';

my $IdP_tag = 'idp';
my $SP_tag = 'sp';

sub tidyEntityDescriptor {
  my $node = shift;
  my $entityID = $node->getAttribute('entityID');

  # Semik: 24.7.2013 - je mozny ze tohle nikdy nechodilo pridal jsem
  # odstranovani i bez jmeneho prostoru a zacalo to odstranovat
  # validUntil u https://secure.palgrave-journals.com/shibboleth

  $node->removeAttributeNS($saml20_ns, 'validUntil');
  $node->removeAttribute('validUntil');

  $node->removeAttributeNS($saml20_ns, 'ID');
  $node->removeAttribute('ID');

  # Odstraneni podpisu na metadatech entit - do 24.7.2013 se to muselo
  # odstranovat manualne. Nemam 100% potvrzeny ze by to byvalo bylo
  # zpusobilo potize. Ale Honza Ch. mel trable po pridani IdP
  # nature.com u nichz nedoslo k odstraneni validUntil a prave podpisu.
  foreach my $element ($node->getElementsByTagNameNS($ds_ns, 'Signature')) {
    $node->removeChild($element);
    logger(LOG_INFO, "Removed ".$element->nodeName." from metadata of $entityID.");
  };

  # Semik: 28. 8. 2013 - Po problemech s nature.com (OpenAthens SP
  # 2.0) jsem se rozhodl vyhazovat element X509SerialNumber aby byla
  # metadata validni tak je nezbytne vyhodit nadrazeny
  # X509IssuerSerial. Problem jsem konzultoval v listu eduGAIN-discuss
  # kde se ozval Ian Young s tim ze uz pekne dlouho v UK federaci
  # tenhle element odstranuji prave kvuli temto potizim.
  foreach my $element (
		       #$node->getElementsByTagNameNS($ds_ns, 'X509SubjectName'),
		       $node->getElementsByTagNameNS($ds_ns, 'X509IssuerSerial'),
		      ) {
    $element->unbindNode;
    logger(LOG_INFO, "Removed ".$element->nodeName." from metadata of $entityID.");
  };

  # Semik: 3. 4. 2014 - odstraneni skupiny SP clarin - tohle ridime pomoci clarin_sp.tag
  foreach my $element ($node->getElementsByTagNameNS($saml20asrt_ns, 'AttributeValue')) {
      if($element->textContent =~ m,$clarin_tag,) {
	  $element->parentNode->unbindNode;
	  logger(LOG_INFO, "Removed ".$element->parentNode->nodeName." from metadata of $entityID.");
      };
      if($element->textContent =~ m,$mefanet_tag,) {
	  $element->parentNode->unbindNode;
	  logger(LOG_INFO, "Removed ".$element->parentNode->nodeName." from metadata of $entityID.");
      };
      if($element->textContent =~ m,$libraries_tag,) {
	  $element->parentNode->unbindNode;
	  logger(LOG_INFO, "Removed ".$element->parentNode->nodeName." from metadata of $entityID.");
      };
      if($element->textContent =~ m,$avcr_tag,) {
	  $element->parentNode->unbindNode;
	  logger(LOG_INFO, "Removed ".$element->parentNode->nodeName." from metadata of $entityID.");
      };
      if($element->textContent =~ m,$university_tag,) {
	  $element->parentNode->unbindNode;
	  logger(LOG_INFO, "Removed ".$element->parentNode->nodeName." from metadata of $entityID.");
      };
  };

  return $node;
};

sub load_registrationInstant {
    my $dir = shift;
    my $md = shift;

    open(F, "<$dir/eduid.registration") or return;
    while (my $line = <F>) {
	chomp($line);
	if ($line =~ /(\S+)\s+(.*)/) {
	    $md->{$1}->{registrationInstant} = $2;
	};
    };
    close(F);
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
    $md{$entityID}->{registrationInstant} = UnixDate(ParseDate('epoch '.$stat[9]), '%Y-%m-%dT%H:%M:%SZ');

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
  my $or_filter = shift;

  my $f = join('+', sort @{$filter});

  # or filter umoznuje rikat ze chceme entity s tagem hostel a soucasne z federace eduid
  my %or_md;
  if (@{$or_filter}) {
    foreach my $entityID (keys %{$md}) {
      my $or_found = 0;
      foreach my $tag (@{$or_filter}) {
	$or_found++ if (grep {$_ eq $tag} @{$md->{$entityID}->{tags}});
      };

      if ($or_found) {
	$or_md{$entityID} = $md->{$entityID};
      };
    };
    $md = \%or_md;
  };

  # normalni filter rika ze chceme entity s tagem eduid a idp
  my %md;
  my $mtime = 0;
  foreach my $entityID (keys %{$md}) {
    my $found = 0;
    my $or_found = 0;
    foreach my $tag (@{$filter}) {
      $found++ if (grep {$_ eq $tag} @{$md->{$entityID}->{tags}});
      $or_found++ if (grep {$_ eq $tag} @{$md->{$entityID}->{tags}});
    };

    #logger(LOG_DEBUG, "filter=$f; or_filter=$or_f; entityID=$entityID; found=$found; or_found=$or_found\n");

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
  my $registrationInstant = shift;

  # Najit Extensions
  my @ext = $entity->getChildrenByTagNameNS($saml20_ns, 'Extensions');
  my $ext;
  unless (@ext) {
    # Nepovedlo se najit Extensions - takovahle entita by se vubec
    # nemela dostat do skladu, kontroluje se to pri vkladani.

    $ext = new XML::LibXML::Element('Extensions');
    $ext->setNamespace($saml20_ns, 'md', 1);
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
  $ri->setAttribute('registrationInstant', $registrationInstant);
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

sub tag_entity {
  my $entity = shift;
  my $tag_uri = shift;

  ## Najit SPSSODescriptor
  #my @SPSSO = $entity->getChildrenByTagNameNS($saml20_ns, 'SPSSODescriptor');
  #my $SPSSO = $SPSSO[0];

  # Najit ci vytvorit Extensions
  my @ext = $entity->getChildrenByTagNameNS($saml20_ns, 'Extensions');
  my $ext;
  unless (@ext) {
    # Nepovedlo se najit Extensions - takovahle entita by se vubec
    # nemela dostat do skladu, kontroluje se to pri vkladani.

    $ext = new XML::LibXML::Element('Extensions');
    $ext->setNamespace($saml20_ns, 'md', 1);
    $entity->insertBefore($ext, $entity->firstChild);
  } else {
    # Povedlo se a tak berem tu prvni. Puvodne se pracovalo s
    # getElementsByTagNameNS ktere hleda bez ohledu na hirerchaii.
    $ext = $ext[0];
  };

  #<EntityAttributes xmlns="urn:oasis:names:tc:SAML:metadata:attribute">
  #    <Attribute xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" Name="http://macedir.org/entity-category">
  #        <AttributeValue>http://eduid.cz/uri/sp-group/clarin</AttributeValue>
  #    </Attribute>
  #</EntityAttributes>

  # najit ci vytvorit vlozit EntityAttribute
  my @ea = $ext->getChildrenByTagNameNS($saml20attr_ns, 'EntityAttributes');
  my $ea;
  unless (@ea) {
      $ea = new XML::LibXML::Element('mdattr:EntityAttributes');
      $ext->addChild($ea);
  } else {
      $ea = $ea[0];
  };

  # najit ci vlozit Attribute
  my @a = $ea->getChildrenByTagNameNS($saml20attr_ns, 'Attribute');
  my $a;
  unless (@a) {
      $a = new XML::LibXML::Element('mdasrt:Attribute');
      $a->setAttribute('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      $a->setAttribute('Name', 'http://macedir.org/entity-category');
      $ea->addChild($a);
  } else {
      $a = $a[0];
  };

  my $av = new XML::LibXML::Element('mdasrt:AttributeValue');
  $av->appendText($tag_uri);
  $a->addChild($av);
};

sub aggregate {
  my $md = shift;
  my $name = shift;
  my $validUntil = shift;
  my $ID = shift || 'undefined';
  $ID =~ s/[^a-zA-Z0-0]/_/g;

  my $dom = XML::LibXML::Document->createDocument('1.0', 'utf-8');
  my $root = XML::LibXML::Element->new('EntitiesDescriptor');
  $dom->adoptNode($root);
  $dom->setDocumentElement($root);

  $root->setNamespace($saml20_ns);
  $root->setNamespace($xsi_ns, 'xsi', 0);
  $root->setNamespace($ds_ns, 'ds', 0);
  $root->setNamespace($saml20attr_ns, 'mdattr', 0);
  $root->setNamespace($saml20asrt_ns, 'mdasrt', 0);


  $root->setAttribute('Name', $name);
  $root->setAttribute('validUntil', $validUntil);
  $root->setAttribute('ID' , $ID);
  $root->setAttributeNS($xsi_ns, 'schemaLocation', $schemaLocation);

  eduGAIN_root($root) if ($name eq 'eduid.cz-edugain');

  foreach my $entityID (keys %{$md}) {
    my $entity = $md->{$entityID}->{md}->cloneNode(1);
    eduGAIN_entity($entity, $md->{$entityID}->{registrationInstant}) if ($name eq 'eduid.cz-edugain');
    tag_entity($entity, $clarin_tag) if (grep {$_ eq 'clarin_sp'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $mefanet_tag) if (grep {$_ eq 'mefanet_sp'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $libraries_tag) if (grep {$_ eq 'libraries'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $university_tag) if (grep {$_ eq 'university'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $avcr_tag) if (grep {$_ eq 'avcr'} @{$md->{$entityID}->{tags}});
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

my $validUntil = UnixDate($config->validity, '%Y-%m-%dT%H:%M:%SZ');

my $md = load($config->metadata_dir);
load_registrationInstant($config->metadata_dir, $md);

foreach my $fed_id (split(/ *, */, $config->federations)) {
  my $fed_filters = $fed_id.'_filters';
  my $fed_name = $fed_id.'_name';

  foreach my $key (split(/ *, */, $config->$fed_filters)) {
    $key =~ s/\'//g;

    my @or_tags;
    my $or_tags_name = $fed_id.'_or_tags';
    # Konstrukce $config->varlist('^'.$or_tags_name.'$') je vypis
    # vsech promenych ktery odpovidaji uvedenemu regularnimu
    # vyrazu. Tedy je to metoda jak zjistit jestli nejaka promena je
    # nebo neni definovana. Kdyz se pouzije nedefinovana promena tak
    # AppConfig vypisuje chyby.
    if ($config->varlist('^'.$or_tags_name.'$')) {
      @or_tags = (split(/ *, */, $config->$or_tags_name));
    };
    my ($entities, $mtime) = filter($md, [split(/\+/, $key)], \@or_tags);

    my $pref = '';
    $pref = $fed_id.'+' if ($config->varlist('^'.$or_tags_name.'$'));
    $pref =~ s/\+$// if ($key eq ''); # smazat koncove plus ktere se tam objevi kdyz je key='';
    my $f = $config->output_dir."/$pref$key-unsigned";
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
      my $doc = aggregate($entities, $config->$fed_name, $validUntil, $key);
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
	  my $cmd = sprintf($config->sign_cmd, $f, $config->output_dir.'/'.$pref.$key);
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
	my $f = "/tmp/$pref$key-xml-invalid";
	open(F, ">$f") or local_die "Cant write to $f: $!";
	binmode F, ":utf8";
	print F $tidy_string;
	close(F);

	logger(LOG_ERR, "Newly created XML document is invalid: ".$msg->[0]." Stored as $f.");

	exit 1;
      };
    };
  };
};

stopRun($config->cfg);
