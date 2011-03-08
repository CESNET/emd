#!/usr/bin/perl -w

use strict;
use lib qw(emd2/lib);
use Data::Dumper;
use Date::Manip;
use XML::LibXML;
use XML::Tidy;
use Sys::Syslog qw(:standard :macros);
use AppConfig qw(:expand);
use emd2::Utils qw (logger local_die startRun stopRun);
use utf8;

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },

   cfg           => { DEFAULT => '' },

   metadata_dir  => { DEFAULT => '' },
   output_dir    => { DEFAULT => '' },

   sign_cmd      => { DEFAULT => undef },

   filters       => { DEFAULT => undef },

   force         => { DEFAULT => undef },

   max_age       => { DEFAULT => 12*60*60 }, # sekundy
   validity      => { DEFAULT => '30 days'}, # cokoliv dokaze ParseDate
  );

my $saml20_ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
my $xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance';
my $ds_ns = 'http://www.w3.org/2000/09/xmldsig#';
my $schemaLocation = 'urn:oasis:names:tc:SAML:2.0:metadata saml-schema-metadata-2.0.xsd urn:mace:shibboleth:metadata:1.0 shibboleth-metadata-1.0.xsd http://www.w3.org/2000/09/xmldsig# xmldsig-core-schema.xsd';

my $IdP_tag = 'idp';
my $SP_tag = 'sp';

sub tidyEntityDescriptor {
  my $node = shift;

  $node->removeAttributeNS($saml20_ns, 'validUntil');

  return $node;
};

sub load {
  my $dir = shift;
  my %md;
  my %tag;

  opendir(DIR, $dir) || local_die "Can't opendir $dir: $!";
  my @files = grep { -f "$dir/$_" } readdir(DIR);
  closedir DIR;

  # load metadata elements
  foreach my $file (grep {$_ =~ /.xml$/} @files) {
    my $parser = XML::LibXML->new;
    open my $fh, "$dir/$file" or local_die "Failed to open $dir/$file: $!";
    #binmode $fh, ":utf8";
    my $string = join('', <$fh>);
    my $xml = $parser->parse_string($string);
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

  foreach my $entityID (keys %{$md}) {
    my $entity = $md->{$entityID}->{md}->cloneNode(1);
    $dom->adoptNode($entity);
    $root->addChild($entity);
  };

  return $dom;
};

startRun;

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

my $validUntil = UnixDate(ParseDate('30 days'), '%Y-%m-%dT%H:%M:%SZ');


my $md = load($config->metadata_dir);

foreach my $key (split(/ *, */, $config->filters)) {
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
    my $doc = aggregate($entities, 'https://eduid.cz/metadata', $validUntil);
    my $tidy = XML::Tidy->new('xml' => $doc->toString);
    $tidy->tidy();

    open(F, ">$f") or local_die "Cant write to $f: $!";
    binmode F, ":utf8";
    #$doc->toFH(\*F);
    #print F $doc->toString;
    print F $tidy->toString;
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
  };
};

stopRun;
