#!/usr/bin/perl -w

use strict;
use lib qw(emd2/lib);
use Sys::Syslog qw(:standard :macros);
use emd2::Utils qw (logger local_die startRun stopRun);
use AppConfig qw(:expand);

startRun;

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },
   cfg                   => { DEFAULT => '' },
   svn_config_dir        => { DEFAULT => undef },
   svn_data_dir          => { DEFAULT => undef },
   svn_repository        => { DEFAULT => undef },
   svn_module            => { DEFAULT => 'metadata' },
   svn_revision_file     => { DEFAULT => 'metadata' },
   aggregate             => { DEFAULT => undef },
   aggregate_cmd         => { DEFAULT => undef },
 );

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

my $cmd = 'svn info --config-dir '.$config->svn_config_dir.' '.
  $config->svn_repository.' '.$config->svn_data_dir;
open(SVNI, "$cmd 2>&1 |") or die "Failed to execute $cmd: $?";
my $repository = 0;
my $local = 0;
my $location = 0;
my $loc_dir = $config->svn_data_dir;
my $svn_module = $config->svn_module;
while (my $line = <SVNI>) {
  $location = 1 if ($line =~ m,^Path: $svn_module,);
  $location = 2 if ($line =~ m,^Working Copy Root Path: $loc_dir,);
  if ($line =~ /^Revision: (\d+)/) {
    my $rev = $1;
    $repository = $rev if ($location == 1);
    $local = $rev if ($location == 2);
  };
};
close(SVNI);

if ($repository ne $local) {
  logger(LOG_DEBUG,  "Repository $svn_module has changed (remote=$repository, local=$local)");
  my $cmd = 'svn checkout -q --config-dir '.$config->svn_config_dir.' '.$config->svn_repository.' '.$config->svn_data_dir;
  open(SVNC, $cmd.' 2>&1 |') or die "Failed to execute svn checkout: $?";
  my @out = <SVNC>;
  close(SVNC);
  my $ret = $? >> 8;
  if ($ret > 0) {
    logger(LOG_ERR,  "svn checkout terminated with error_code=$ret. Output:");
    foreach my $line (@out) { logger(LOG_ERR, $line); };	
  } else {
    logger(LOG_DEBUG,  "Local repository successfully updated.");

    # Zaznamenat posledni verzi SVN
    open(REV, ">".$config->svn_revision_file);
    print REV $local;
    close(REV);

    foreach my $line (@out) { logger(LOG_ERR, $line); };	
    if ($config->aggregate) {
      my $cmd = $config->aggregate_cmd;
      open(AGG, "$cmd 2>&1|") or die "Failed to execute aggregate: $?";
      my @out = <AGG>;
      close(AGG);
      my $ret = $? >> 8;
      if ($ret > 0) {
	logger(LOG_ERR,  "aggregate terminated with error_code=$ret. Output:");
	foreach my $line (@out) { logger(LOG_ERR, $line); };	
      };
    };
  };
};

stopRun;
