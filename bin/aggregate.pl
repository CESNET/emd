#!/usr/bin/perl -w

# apt-get install libdate-manip-perl libxml-libxml-perl libproc-processtable-perl libappconfig-perl libnumber-bytes-human-perl libcrypt-openssl-x509-perl

use strict;
use lib qw(emd2/lib lib);
use Data::Dumper;
use Date::Manip;
use XML::LibXML;
use Sys::Syslog qw(:standard :macros);
use AppConfig qw(:expand);
use emd2::Utils qw (logger prg_name local_die startRun stopRun xml_strip_whitespace);
use emd2::Checker qw (checkXMLValidity);
use Proc::ProcessTable;
use Number::Bytes::Human qw(format_bytes);
use utf8;

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1,
    CREATE => '.*',
   },

   cfg           => { DEFAULT => '' },

   svn_config_dir=> { DEFAULT => undef },

   metadata_dir  => { DEFAULT => '' },
   output_dir    => { DEFAULT => '' },

   sign_cmd      => { DEFAULT => undef },
   sign256_cmd   => { DEFAULT => undef },

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

my $mefanet_tag = 'http://eduid.cz/uri/group/mefanet';
my $mojeid_edu_tag = 'http://eduid.cz/uri/sp-group/mojeid-edu';

my $library_tag = 'http://eduid.cz/uri/idp-group/library';
my $avcr_tag = 'http://eduid.cz/uri/idp-group/avcr';
my $university_tag = 'http://eduid.cz/uri/idp-group/university';
my $hospital_tag = 'http://eduid.cz/uri/idp-group/hospital';
my $cesnet_tag = 'http://eduid.cz/uri/idp-group/cesnet';
my $other_tag = 'http://eduid.cz/uri/idp-group/other';
my $aa_access_tag = 'http://eduid.cz/uri/sp-group/aa.cesnet.cz';

my $schemaLocation = 'urn:oasis:names:tc:SAML:2.0:metadata saml-schema-metadata-2.0.xsd urn:mace:shibboleth:metadata:1.0 shibboleth-metadata-1.0.xsd http://www.w3.org/2000/09/xmldsig# xmldsig-core-schema.xsd';

my $IdP_tag = 'idp';
my $SP_tag = 'sp';

sub getSelfSize {
    my $t = Proc::ProcessTable->new();

    foreach my $p ( @{$t->table} ) {
	if($p->pid() == $$) {
	    return format_bytes($p->size, bs=>1024);
	}
    }
    return -1;
};

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

  foreach my $element ($node->getElementsByTagNameNS($saml20asrt_ns, 'AttributeValue')) {
      my $parent = $element->parentNode;
      my $textContent = $element->textContent;
      my $removed = 0;

      if($textContent =~ m,$mefanet_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$mojeid_edu_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$library_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$other_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$avcr_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$university_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$hospital_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$cesnet_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };
      if($textContent =~ m,$aa_access_tag,) {
	  $parent->removeChild($element);
	  $removed++;
	  logger(LOG_INFO, "Removed ".$element->nodeName."=$textContent from metadata of $entityID.");
      };

      # Kontrola ze po pripadnem odstraneni nezustane prazdny
      # element. Pouziti textoveho obsahu je ojeb ale zda se ze to
      # funguje vcetne komentaru.
      # ....
      #  <EntityAttributes>
      #    <Attribute>
      #      <AttributeValue>
      #       
      if ($removed) {
	  my $text = $parent->parentNode->textContent;
	  if ($text =~ /^\s*$/) {
	      my $parent2 = $parent->parentNode;
	      $parent2->parentNode->removeChild($parent2);
	      logger(LOG_INFO, "Removed empty ".$parent2->nodeName." from metadata of $entityID.");
	  };
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
      $xml = $parser->parse_string($string, { no_blanks => 1 });
    };
    if ($@) {
      my $err = $@;
      local_die "Failed to parse file $dir/$file: $@";
    };
    close $fh;


    my $root = $xml->documentElement;
    xml_strip_whitespace($root);
    #die $root->toString;
    my $entityID = $root->getAttribute('entityID');
    $md{$entityID}->{md} = tidyEntityDescriptor($root);

    my @stat = stat("$dir/$file");
    $md{$entityID}->{mtime} = $stat[9];
    $md{$entityID}->{registrationInstant} = UnixDate(ParseDate('epoch '.$stat[9]), '%Y-%m-%dT%H:%M:%SZ');

    my $idpsp = 0;
    if ($root->getElementsByTagNameNS($saml20_ns, 'IDPSSODescriptor') or
        $root->getElementsByTagNameNS($saml20_ns, 'AttributeAuthorityDescriptor')) {
      push @{$md{$entityID}->{tags}}, $IdP_tag;
      $idpsp++;
    };
    if ($root->getElementsByTagNameNS($saml20_ns, 'SPSSODescriptor')) {
      push @{$md{$entityID}->{tags}}, $SP_tag;
      $idpsp++;
    };
    unless ($idpsp) {
      logger(LOG_WARNING, "entityID=$entityID neni SP ani IdP???");
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

  # zlikvidovat z eduid2edugain ty co nejsou v eduid ... tohle je stupidni
  foreach my $entityID (keys %md) {
    my @tags = @{$md{$entityID}->{tags}};

    my @ex_tags = grep {$_ ne 'eduid2edugain'} @tags;
    if ((scalar(@tags) > scalar(@ex_tags)) and
	not (grep {$_ eq 'eduid'} @ex_tags)) {
      logger(LOG_INFO, "Entity \"$entityID\" is not taged anywhere, it should be deleted from SVN."); 
      $md{$entityID}->{tags} = \@ex_tags;
    }
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

  #my $entityID = $entity->getAttribute('entityID');
  #warn $entityID;

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
    $entity->setNamespace($saml20_ns, 'md', 0);
    $entity->insertBefore($ext, $entity->firstChild);
  } else {
    # Povedlo se a tak berem tu prvni. Puvodne se pracovalo s
    # getElementsByTagNameNS ktere hleda bez ohledu na hirerchaii.
    $ext = $ext[0];
  };

  # najit ci vytvorit vlozit EntityAttribute
  my @ea = $ext->getChildrenByTagNameNS($saml20attr_ns, 'EntityAttributes');
  my $ea;
  unless (@ea) {
      $ea = new XML::LibXML::Element('EntityAttributes');
      $ea->setNamespace($saml20attr_ns, 'mdattr', 1);
      $entity->setNamespace($saml20attr_ns, 'mdattr', 0);
      $ext->addChild($ea);
  } else {
      $ea = $ea[0];
  };

  # najit ci vlozit Attribute
  my $a;
  foreach my $_a ($ea->getChildrenByTagNameNS($saml20asrt_ns, 'Attribute')) {
      my $name = $_a->getAttribute('Name');
      # zkontrolovat ze jsme nasli Attribute se spravnym jmenem
      if ($name eq 'http://macedir.org/entity-category') {
	  $a = $_a;
      };
  };
  unless ($a) {
      $a = new XML::LibXML::Element('Attribute');
      $a->setNamespace($saml20asrt_ns, 'saml', 1);
      $entity->setNamespace($saml20asrt_ns, 'saml', 0);
      $a->setAttribute('NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
      $a->setAttribute('Name', 'http://macedir.org/entity-category');
      $ea->addChild($a);
  };

  my $av = new XML::LibXML::Element('AttributeValue');
  $av->setNamespace($saml20asrt_ns, 'saml', 1);
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
  $root->setNamespace($saml20asrt_ns, 'saml', 0);

  $root->setAttribute('Name', $name);
  $root->setAttribute('validUntil', $validUntil);
  $root->setAttribute('ID' , $ID);
  $root->setAttributeNS($xsi_ns, 'schemaLocation', $schemaLocation);

  eduGAIN_root($root) if ($name eq 'eduid.cz-edugain');

  foreach my $entityID (sort keys %{$md}) {
    my $entity = $md->{$entityID}->{md}->cloneNode(1);
    eduGAIN_entity($entity, $md->{$entityID}->{registrationInstant}) if ($name eq 'eduid.cz-edugain');
    tag_entity($entity, $mefanet_tag) if (grep {$_ eq 'mefanet_sp'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $mojeid_edu_tag) if (grep {$_ eq 'mojeid-edu'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $library_tag) if (grep {$_ eq 'library'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $other_tag) if (grep {$_ eq 'other'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $university_tag) if (grep {$_ eq 'university'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $hospital_tag) if (grep {$_ eq 'hospital'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $avcr_tag) if (grep {$_ eq 'avcr'} @{$md->{$entityID}->{tags}});
    tag_entity($entity, $aa_access_tag) if (grep {$_ eq 'aa-access'} @{$md->{$entityID}->{tags}});
    $dom->adoptNode($entity);
    $root->addChild($entity);
  };

  return $dom;
};

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

my $name = $config->cfg;
$name =~ s/^.*\///;
$name =~ s/\.cfg$//g;
prg_name($name);
startRun($config->cfg);

# otevrit adresar s metadaty a nacist vsechny konfigy a naplnit
# promenou federations
opendir(my $dh, $config->metadata_dir) || die "Can't opendir ".$config->metadata_dir.": $!";
my @fed_cfg = grep { /\.cfg$/ } readdir($dh);
closedir $dh;

my @fed;
foreach my $fed_cfg (@fed_cfg) {
    my $fed = $fed_cfg;
    $fed =~ s/\.cfg$//g;
    push @fed, $fed;

    # nacteni fragmentu konfigurace
    $fed_cfg = $config->metadata_dir."/$fed_cfg";
    $config->file($fed_cfg) or die "Can't open config file \"$fed_cfg\": $!";
    # TODO vzit si casovou znacku posledni modifikace
};
$config->set('federations', join(',', @fed));

my $validUntil = UnixDate($config->validity, '%Y-%m-%dT%H:%M:%SZ');

my $md = load($config->metadata_dir);

load_registrationInstant($config->metadata_dir, $md);

foreach my $fed_id (split(/ *, */, $config->federations)) {
  prg_name('aggregate-'.$fed_id);

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
    my $no_entities = scalar(keys %{$entities});

    if ($export and $no_entities) {
      logger(LOG_DEBUG,  "Exporting $key to file $f.");
      my $doc = aggregate($entities, $config->$fed_name, $validUntil, $key);

      my $parser = XML::LibXML->new;
      # Volani toStringC14N zajisti normalizaci namespace, tj. vyhazi
      # zbytecne opakovane deklarace ktere jsou na zacatku dokumentu a
      # pak se opakuji u spousty jednotlivych entit. Kodovani je nutno deklarovat
      # aby to parse_string nasledne dobre nacetlo abylo to v UTF8.
      my $xml = $parser->parse_string('<?xml version="1.0" encoding="utf-8"?>'."\n".$doc->toStringC14N);

      # Volani toString(1) zajisti pretyPrint XML, tak aby jednotlivy
      # elementy byly pekne odsazeny. Prekvapive vystup neni validni
      # utf8 string, takze je potreba volat utf8:decode aby se to
      # nasledne dobre ulozilo na disk, mozna kdyz by se odstranil ten
      # binmode tak by to nebylo nutny.
      my $tidy_string = $xml->toString(1);
      utf8::decode($tidy_string) unless utf8::is_utf8($tidy_string);

      my ($res, $msg, $dom) = checkXMLValidity($tidy_string, 'emd2/schema/eduidmd.xsd');

      if ($res) {
	logger(LOG_DEBUG, "Newly created XML document is valid with schema.");

	open(F, ">$f") or local_die "Cant write to $f: $!";
	binmode F, ":utf8";
	print F $tidy_string;
	close(F);
	
	foreach my $sign_cmd (
                               # $config->sign_cmd, - tohle na novym mdx uz nechceme
	                       $config->sign256_cmd
	    ) {
	    my $cmd = sprintf($sign_cmd, $f, $config->output_dir.'/'.$pref.$key);
	    logger(LOG_DEBUG,  "Signing: '$cmd'");
	    my $cmd_fh;
	    open(CMD, "$cmd 2>&1 |") or local_die("Failed to exec $cmd: $! $@");
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
