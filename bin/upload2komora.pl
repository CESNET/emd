#!/usr/bin/perl -w

use strict;
use AppConfig qw(:expand);
use lib qw(./emd/lib);
use emd2::Utils qw (:all);
use Sys::Syslog qw(:standard :macros);
use POSIX;
use Data::Dumper;
use myPerlLDAP::conn;
use myPerlLDAP::entry;
use myPerlLDAP::attribute;
use myPerlLDAP::utils qw(:all);
use Sys::Syslog;
use Date::Manip;
use Digest::SHA qw(hmac_sha256_base64);
use URI::Encode qw(uri_encode);
use LWP::UserAgent;
use JSON;
use Date::Manip;
use utf8;

sub getAPIURL {
    my $config = shift;

    my $nonce = sprintf("%08X", rand(0xFFFFFFFF));
    my $ts = UnixDate('now', '%Y-%m-%d');

    my $params = "?nonce=$nonce&appKey=".uri_encode($config->APIKey, {encode_reserved => 1}).'&'.
	'ServiceId='.uri_encode($config->ServiceId, {encode_reserved => 1}).'&'.
	'ApplicationGarantId='.uri_encode($config->ApplicationGarantId, {encode_reserved => 1}).'&'.
	'DateFrom='.uri_encode($ts, {encode_reserved => 1}).'&'.
	'DateTo='.uri_encode($ts, {encode_reserved => 1});

    my $b64_sig = hmac_sha256_base64($params, $config->APISecret);
    while (length($b64_sig) % 4) { $b64_sig .= '='; };

    my $url = $config->APIURL.$params.'&sign='.uri_encode($b64_sig, {encode_reserved => 1});
};

sub getJSONfromURL {
    my $config = shift;

    my $url = getAPIURL($config);

    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
    my $res = $ua->get($url);

    if ($res->is_success) {
        my $content = $res->content;
        utf8::decode($content);
        my $json = from_json($content);
        return $json;
    } else {
        logger(LOG_ERR, "Failed to access komora: ".$res->status_line);
        return
    };
};


my $config = AppConfig->new
  ({
    GLOBAL=> { EXPAND => EXPAND_ALL, ARGCOUNT => 1 },
    CASE => 1
   },
   CFGFilename   => {DEFAULT => 'upload2komora.cfg'},

   DataFile      => {DEFAULT => ''},

   ServiceId     => {DEFAULT => '' },
   ApplicationGarantId => {DEFAULT => '' },
   APIKey        => {DEFAULT => ''},
   APISecret     => {DEFAULT => ''},
   APIURL        => {DEFAULT => ''},
  );

$config->args(\@ARGV) or die "Can't parse cmdline args";
$config->file($config->CFGFilename) or die "Can't open config file \"".$config->CFGFilename."\": $!";

#die 'curl -X POST "'.getAPIURL($config).'" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "dataFile=@eduid-idp.json;type=application/json"'."\n";

my $url = getAPIURL($config);
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });

my $req = $ua->post($url,
		    Content_Type => 'form-data',
		    Content => [
			'dataFile' => [ $config->DataFile ],		
		    ]);

local_die("Failed to access komora: HTTP_CODE=".$req->code.' message='.$req->decoded_content)
    unless ($req->is_success);

my $jres;
eval {
    $jres = JSON->new->decode($req->decoded_content);
};

local_die("Upload to komora failed: $@; ".$req->decoded_content)
    if ($@);

if ($jres->{ok}) {
    my $id = 'undef';
    $id = $jres->{recordId} if (exists($jres->{recordId}));
    $id = $jres->{tempFileName} if (exists($jres->{tempFileName}));

    logger(LOG_DEBUG, "komora upload OK, stored as recordId=$id");
    exit 0;
};

local_die("Upload to komora failed: ".$req->decoded_content);
