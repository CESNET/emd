#!/usr/bin/perl -w

use strict;
use lib qw(lib);
use Data::Dumper;
use AppConfig qw(:expand);
use XML::LibXML;
use emd2::Utils qw(:all);
use emd2::Checker qw(:all);
use emd2::CheckFilter qw(:all);

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },
   'error_filter'    => {DEFAULT => './metadata-exceptions'},
   'metadata'        => {DEFAULT => undef},
  );

$config->args(\@ARGV) or
  die "Can't parse cmdline args";

my $filters = loadFiltersFromFile($config->error_filter) or
  die sprintf('Failed to read file %s: %s', $config->error_filter, $!)."\n";

my $parser = XML::LibXML->new;

open(F, '<'.$config->metadata) or
  die sprintf('Failed to open file %s: %s', $config->metadata, $!);
my $str = join('', <F>);
close(F);

my ($res, $errors, $dom) = checkEntityDescriptor($str);
my $root = $dom->documentElement if ($dom);

if ($res == 0) {
  print "OK\n";
  exit 0;
} else {
  my $entityID = 'failed to parse XML';
  $entityID = $root->getAttribute('entityID') if ($root);

  my ($e, $w) = filterErrors($entityID, $filters, $errors);
  if (%{$w} or %{$e}) {
    warn "$entityID\n";
    warn ew2string($e, 'error') if (%{$e});
    warn ew2string($w, 'warning') if (%{$w});
    exit 1;
  };

  print "OK\n";
  exit 0;
};
