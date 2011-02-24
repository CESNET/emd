#!/usr/bin/perl -w

use strict;
use lib qw(emd2/lib);
use Sys::Syslog qw(:standard :macros);
use emd2::Utils qw (logger local_die startRun stopRun);

startRun;

open(SVNI, 'svn info --config-dir /home/mdx/.svnc svn+chssh://cml2.cesnet.cz/data/metadata /home/mdx/metadata|') or die "Failed to execute svn info: $?";
my $repository = 0;
my $local = 0;
my $location = 0;
while (my $line = <SVNI>) {
  $location = 1 if ($line =~ m,^Path: metadata,);
  $location = 2 if ($line =~ m,^Path: /home/mdx/metadata,);
  if ($line =~ /^Revision: (\d+)/) {
    my $rev = $1;
    $repository = $rev if ($location == 1);
    $local = $rev if ($location == 2);
  };
};
close(SVNI);

if ($repository ne $local) {
  logger(LOG_DEBUG,  "Repository has changed (remote=$repository, local=$local)");
  open(SVNC, 'svn checkout -q --config-dir /home/mdx/.svnc svn+chssh://cml2.cesnet.cz/data/metadata /home/mdx/metadata 2>&1 |') or die "Failed to execute svn checkout: $?";
  my @out = <SVNC>;
  close(SVNC);
  my $ret = $? >> 8;
  if ($ret > 0) {
    logger(LOG_ERR,  "svn checkout terminated with error_code=$ret. Output:");
    foreach my $line (@out) {
      logger(LOG_ERR, $line);
    };	
  } else {
    logger(LOG_DEBUG,  "Local repository successfully updated.");
    open(AGG, '/usr/bin/perl /home/mdx/emd2/bin/aggregate.pl --cfg /home/mdx/aggregate.cfg 2>&1|') or die "Failed to execute aggregate: $?";
    my @out = <AGG>;
    close(AGG);
    my $ret = $? >> 8;
    if ($ret > 0) {
      logger(LOG_ERR,  "aggregate terminated with error_code=$ret. Output:");
      foreach my $line (@out) { logger(LOG_ERR, $line); };	
    };
  };
};

stopRun;
