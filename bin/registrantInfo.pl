#!/usr/bin/perl -w

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

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

my $dir = $config->metadata_dir;
opendir(DIR, $dir) || local_die "Can't opendir $dir: $!";
my @files = grep { -f "$dir/$_" } readdir(DIR);
closedir DIR;

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

    my $cmd = 'svn log --config-dir '.$config->svn_config_dir.' '."$dir/$file";
    open(SVNI, "$cmd 2>&1 |") or die "Failed to execute $cmd: $?";
    my $reg_time = undef;
    while (my $line = <SVNI>) {
	$reg_time = $3 if ($line =~ m,^(r\d+)\s+\|(.*?)\|\s+([^()]+),);
    };
    close(SVNI);

    if ($reg_time) {
	$reg_time = UnixDate(ParseDate($reg_time), '%Y-%m-%dT%H:%M:%SZ');
	print "$entityID\t$reg_time\n";
    } else {
	warn $file;
    };
};
