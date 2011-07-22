#/usr/bin/perl -w

package emd2::Utils;

use strict;
use vars qw($VERSION @ISA %EXPORT_TAGS);
use Sys::Syslog qw(:standard :macros);
use Proc::ProcessTable;
use File::Temp qw(tempfile);
use Digest::MD5 qw (md5_hex md5_base64);

@ISA = qw(Exporter);
$VERSION = "0.0.1";
%EXPORT_TAGS = (
                all => [qw(getNormalizedEntityID getXMLelementAStext ew2string
			   logger local_die startRun stopRun store_to_file prg_name)]
                );
# Add Everything in %EXPORT_TAGS to @EXPORT_OK
Exporter::export_ok_tags('all');

sub getXMLelementAStext {
  my $node = shift;
  my $element_name =  shift;

  foreach my $element ($node->getElementsByTagName($element_name)) {
    return $element->textContent;
  };

  return;
};

sub getNormalizedEntityID {
  my $node = shift;

  return unless ($node->hasAttribute('entityID'));
  my $id = lc $node->getAttribute('entityID');

  $id =~ s/[\:\/\.]/_/g;
  $id =~ s/_+/_/g;
  $id =~ s/_+$//;

  return $id;
};

sub ew2string {
  my $errors = shift;
  my $prefix = shift;
  my $str;

  foreach my $e (sort {$a <=> $b} keys %{$errors}) {
    for(my $i=0; $i<(@{$errors->{$e}}/2); $i++) {
      my $msg = $errors->{$e}->[$i*2];
      my $path = $errors->{$e}->[$i*2+1];
      $str .= "  $prefix: $e
    msg: $msg\n";
      if ($path) {
	$str .= "    path: $path\n\n";
      } else {
	$str .= "\n";
      };
    };
  };

  return $str;
};

my $prg_name = $0;
$prg_name =~ s/.*\///;

sub prg_name {
  return $prg_name;
};

sub syslog_escape {
  my $str = shift;
  my @chr = split(//, $str);

  for(my $i=0; $i<@chr; $i++) {
    if (ord($chr[$i])>127) {
      $chr[$i] = sprintf('\0x%X', ord($chr[$i]));
    };
  };

  return join('', @chr);
};


sub logger {
  my $priority = shift;
  my $msg = shift;

  openlog($prg_name, 'pid', LOG_LOCAL1);
  setlogmask(LOG_MASK(LOG_ALERT) | LOG_MASK(LOG_CRIT) |
	     LOG_MASK(LOG_DEBUG) | LOG_MASK(LOG_EMERG) |
	     LOG_MASK(LOG_ERR) | LOG_MASK(LOG_INFO) |
	     LOG_MASK(LOG_NOTICE) | LOG_MASK(LOG_WARNING));
  syslog($priority, syslog_escape($msg));
  closelog;
};

sub local_die {
  my $message = shift;

  logger(LOG_ERR, $message);
  exit(1);
};

my $PID_dir="/tmp";

sub startRun {
  my $prg = shift || $0;
  $prg =~ s/.*\///;
  my $pidFile = "$PID_dir/$prg.pid";

  my $counter = 1;
  while ((-e $pidFile) and ($counter > 0)) {
    logger(LOG_INFO, "File \"$pidFile\" in way, waiting ($counter).");
    sleep 5;
    $counter--;
  };

  if (-e $pidFile) {
    open(PID, "<$pidFile") or die "Can't read file \"$pidFile\"";
    my $pid = <PID>; chomp($pid);
    close(PID);

    my $t = new Proc::ProcessTable;
    my $found = 0;
    foreach my $p ( @{$t->table} ){
      $found = 1 if ($p->pid == $pid);
    };

    if ($found) {
      my $msg = "We are already running as PID=$pid, terminating!";
      logger(LOG_ERR, $msg);
      exit 1;
      die $msg;
    }

    logger(LOG_INFO, "Overwriting orphaned PID file \"$pidFile\"");
  };

  open(RUN, ">$pidFile") or die "Can't create file \"$pidFile\": $!";
  print RUN $$;
  close(RUN);
};

sub stopRun {
  my $prg = shift || $0;
  $prg =~ s/.*\///;
  my $pidFile = "$PID_dir/$prg.pid";

  die "Can't remove file \"$pidFile\"! " unless unlink("$pidFile");
};

sub store_to_file {
  my $filename = shift;
  my $content = shift;

  my $res = 1;

  if ( -f $filename ) {
    my $c = $content; utf8::encode($c);
    my $md5_new = md5_hex($c);
    my $cmd = 'md5sum '.$filename.' | sed "s/ .*//"';
    my $old_md5sum = `$cmd`; chomp($old_md5sum);

    # Obsah souboru se nezmenil?
    return 0 if ($md5_new eq $old_md5sum);
  } else {
    # Soubor neexistuje
    $res = 2;
  };

  my ($tmp_fh, $tmp_filename) = tempfile("/tmp/emd-utils`-XXXXXX");
  binmode $tmp_fh, ":utf8";
  print $tmp_fh $content;
  close($tmp_fh);
  rename($tmp_filename, "$filename") or die "Failed to move $tmp_filename to $filename: $!";
  chmod(0644, "$filename");

  return $res;
};

1;
