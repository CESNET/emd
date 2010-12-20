#/usr/bin/perl -w

package emd2::Utils;

use strict;
use vars qw($VERSION @ISA %EXPORT_TAGS);

@ISA = qw(Exporter);
$VERSION = "0.0.1";
%EXPORT_TAGS = (
                all => [qw(getNormalizedEntityID getXMLelementAStext ew2string)]
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

1;
