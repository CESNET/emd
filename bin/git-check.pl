#!/usr/bin/perl -w

# dep: libgit-repository-perl

use strict;
use lib qw(emd2/lib);
use Sys::Syslog qw(:standard :macros);
use emd2::Utils qw (logger local_die startRun stopRun);
use AppConfig qw(:expand);
use Git::Repository;
use Data::Dumper;

my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },
   cfg                   => { DEFAULT => '' },
   git_repository        => { DEFAULT => undef },
   git_branch            => { DEFAULT => 'origin/master' },
   aggregate             => { DEFAULT => undef },
   aggregate_cmd         => { DEFAULT => undef },
 );

$config->args(\@ARGV) or
  die "Can't parse cmdline args";
$config->file($config->cfg) or
  die "Can't open config file \"".$config->cfg."\": $!";

startRun($config->cfg);

# start from an existing working copy
my $r = Git::Repository->new(work_tree => $config->git_repository,
			     {quiet => 1});
my $output = $r->run('fetch');
$output = $r->run('log', 'HEAD..'.$config->git_branch);

if ($output ne '') {
    my @output = split("\n", $output);
    logger(LOG_DEBUG,  "Repository ".$config->git_repository." has changed ($output[0])");
    $output = $r->run('pull');
    if ($? >> 8) {
	logger(LOG_ERR,  "git pull terminated with error_code=".($? >> 8));
    } else {
	logger(LOG_ERR,  "git pull OK");
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
	} else {
	    logger(LOG_ERR,  "no aggregation configured");
	};
    };
};

stopRun($config->cfg);


