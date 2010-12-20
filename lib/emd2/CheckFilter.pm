#/usr/bin/perl -w

package emd2::CheckFilter;

use strict;
use emd2::Utils qw(:all);
use Data::Dumper;

use vars qw($VERSION @ISA %EXPORT_TAGS);

@ISA = qw(Exporter);
$VERSION = "0.0.1";
%EXPORT_TAGS = (
                all => [qw(filterErrors loadFiltersFromFile)],
                );
# Add Everything in %EXPORT_TAGS to @EXPORT_OK
Exporter::export_ok_tags('all');

sub loadFiltersFromFile {
  my $filename = shift;

  my %filters;
  my $entityID;

  open(FILE, "<$filename") or return;
  while (my $line = <FILE>) {
    chomp($line);
    $line =~ s/^\s+//;
    $line =~ s/\s+$//;

    next if ($line =~ /^#/);

    if ((not defined($entityID)) and ($line =~ /^http/)) {
      $entityID = $line;
    } elsif ((defined($entityID)) and ($line =~ /^(\d+)([WI]):\s*(.+)$/)) {
      my $errorNo = $1;
      my $type = $2;
      my $regex = $3;

      $filters{$entityID}->{$errorNo}->{type} = $type;
      $filters{$entityID}->{$errorNo}->{regex} = $regex;
    } elsif ($line =~ /^$/) {
      $entityID = undef;
    };
  };

  return \%filters;
};

sub filterErrors {
  my $eid = shift;
  my $f = shift;
  my $e = shift;

  my %e;
  my %w;

  foreach my $errorCode (keys %{$e}) {
    if (defined($f->{$eid}) and defined($f->{$eid}->{$errorCode})) {
      my $errorDesc = $e->{$errorCode}->[0];
      my $type = $f->{$eid}->{$errorCode}->{type};
      my $regex = $f->{$eid}->{$errorCode}->{regex};

      if ($errorDesc =~ /$regex/) {
	# regex sedi budeme ho bud ignorovat a nebo z nej udelame varovani
	next if ($type eq 'I');
	# bude to varovnani
	$w{$errorCode} = $e->{$errorCode};
      } else {
	# regex nesedi takze je to normalni error
	$e{$errorCode} = $e->{$errorCode};
      };
    } else {
      # pro tenhle eror neexistuje zadna vyjimka
      $e{$errorCode} = $e->{$errorCode};
    };
  };

  return (\%e, \%w);
};


1;
