#/usr/bin/perl -w

package emd2::Utils;

use strict;
use vars qw($VERSION @ISA %EXPORT_TAGS);
use Sys::Syslog qw(:standard :macros);
use Proc::ProcessTable;
use File::Temp qw(tempfile);
use Digest::MD5 qw (md5_hex md5_base64);
use XML::LibXML;
use Data::Dumper;
use utf8;

my $prg_name = $0;
$prg_name =~ s/.*\///;

@ISA = qw(Exporter);
$VERSION = "0.0.1";
%EXPORT_TAGS = (
                all => [qw(getNormalizedEntityID getXMLelementAStext ew2string
			   logger local_die startRun stopRun store_to_file
                           prg_name xml_strip_whitespace)]
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

sub prg_name {
    my $arg = shift;

    if (defined($arg)) {
	$prg_name = $arg
    };

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

sub trim {
    my ($text)=@_;
    $text=~s/^\s*//mg;
    $text=~s/\s*$//mg;
    return $text;
}

sub xml_strip_whitespace_it {
    my ($node)=@_;
    my $nodeType = $node->nodeType();
    if ($nodeType == XML::LibXML::XML_TEXT_NODE) {
	my $data=trim($node->getData());
	if ($data ne "") {
	    $node->setData($data);
	}
    } elsif ($nodeType == XML::LibXML::XML_ELEMENT_NODE) {
	die $node->toString;
    };
};


sub xml_strip_whitespace {
    my $node = shift;

    foreach my $child_node ($node->childNodes) {
	my $nodeType = $child_node->nodeType();
	if ($nodeType == XML::LibXML::XML_TEXT_NODE) {
	    my $data=trim($child_node->getData());
	    if ($data ne "") {
		$child_node->setData($data);
	    } else {
		$child_node->unbindNode();
	    }
	} else {
	    xml_strip_whitespace($child_node);
	};
    };
}


1;
