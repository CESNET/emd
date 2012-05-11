#!/usr/bin/perl -w

use strict;
use lib qw(lib);
use Data::Dumper;
use XML::LibXML;
use emd2::Utils qw(:all);
use emd2::Checker qw(:all);

my @tests = (
	     {
	      file => '/dev/null',
	      errors => {
			 emd2::Checker::CHECK_XML_VALIDITY => ['Empty String', '']
			},
	     },
	     {
	      file => 'tests/non-valid-xml',
	      errors => {
			 emd2::Checker::CHECK_XML_VALIDITY => [':1: parser error : Start tag expected, \'<\' not found
bla bla
^
', '']
			},
	     },
	     {
	      file => 'tests/no-langcs-org',
	      errors => {
			 emd2::Checker::CHECK_ORGANIZATION_CS =>
			   ['Organization: missing OrganizationDisplayName @lang=\'cs\'.',
			    '/*/*[3]'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			   ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			    '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/zero-org',
	      errors => {emd2::Checker::CHECK_ORGANIZATION_EN =>
			   ['Missing Organization element.',
			    '/*'],
			 emd2::Checker::CHECK_ORGANIZATION_CS =>
			   ['Missing Organization element.',
			    '/*'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			   ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			    '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/multiple-org',
	      errors => {
			 emd2::Checker::CHECK_ORGANIZATION_EN =>
			   ['Found multiple Organization elements. There must be exactly one.',
			    '/*'],
			 emd2::Checker::CHECK_ORGANIZATION_CS =>
			   ['Found multiple Organization elements. There must be exactly one.',
			    '/*'],
			 emd2::Checker::CHECK_XML_VALIDITY =>
			 ["Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}Organization': This element is not expected. Expected is one of ( {urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson, {urn:oasis:names:tc:SAML:2.0:metadata}AdditionalMetadataLocation ).",
			  ''],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			   ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			    '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/missing-tech-c',
	      errors => {
			 emd2::Checker::CHECK_TECHNICAL_CONTACT =>
			 ['Technical contact is missing.', '/*'],
			 emd2::Checker::CHECK_XML_VALIDITY =>
			 ["Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson', attribute 'contactType': [facet 'enumeration'] The value 'DDtechnical' is not an element of the set {'technical', 'support', 'administrative', 'billing', 'other'}.Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}ContactPerson', attribute 'contactType': 'DDtechnical' is not a valid value of the atomic type '{urn:oasis:names:tc:SAML:2.0:metadata}ContactTypeType'.",
			  ''],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/missing-email-tech-c',
	      errors => {
			 emd2::Checker::CHECK_TECHNICAL_CONTACT =>
			 ['Technical contact must have EmailAddress.', '/*/*[4]'],
			 emd2::Checker::CHECK_XML_VALIDITY =>
			 ["Schemas validity error : Element '{urn:oasis:names:tc:SAML:2.0:metadata}XEmailAddress': This element is not expected. Expected is one of ( {urn:oasis:names:tc:SAML:2.0:metadata}EmailAddress, {urn:oasis:names:tc:SAML:2.0:metadata}TelephoneNumber ).",
			  ''],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/missing-certificate',
	      errors => {
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Missing KeyDescriptor element.', '/*']
			},
	     },
	     {
	      file => 'tests/expired-certificate',
	      errors => {
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="O=CESNET, O=CESNET, CN=radius2.eduroam.cz", serial=02DD, issued="C=CZ, O=CESNET, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate']
			},
	     },
	     {
	      file => 'tests/not-parsable-certificate',
	      errors => {
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['failed to read X509 certificate.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate']
			},
	     },
	     {
	      file => 'tests/missing-ext-scope',
	      errors => {
			 emd2::Checker::CHECK_EXTENSIONS_SCOPE =>
			 [ 'IDPSSODescriptor/Extensions/Scope is missing. Found \'/*/*[1]/*[1]\'.',
			   '/*'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/entityID-localhost',
	      errors => {
			 emd2::Checker::CHECK_ENTITYID =>
			 ['Entity ID must not be localhost.', '/*'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/endpoint-localhost',
	      errors => {
			 emd2::Checker::CHECK_ENDPOINTS =>
			 ['Localhost is not permited as EndPoint.', '/*/*[1]/*[11]'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			   ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			    '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	     },
	     {
	      file => 'tests/endpoint-http',
	      errors => {
			 emd2::Checker::CHECK_ENDPOINTS =>
			 ['HTTPS usage is required.', '/*/*[1]/*[10]'],
			 emd2::Checker::CHECK_X509CERTIFICATE =>
			 ['Certificate subject="DC=cz, DC=cesnet-ca, O=University of J. E. Purkyne, CN=idp.ujep.cz", serial=42B387AC, issued="DC=cz, DC=cesnet-ca, CN=CESNET CA" is expired.',
			  '/*/*[1]/*[2]/ds:KeyInfo/ds:X509Data/ds:X509Certificate'],
			},
	      },
	     {
	      file => 'tests/missing-discoveryresponse-binding',
	      errors => {
			 emd2::Checker::CHECK_DISCOVERY_RESPONSE_BINDING =>
			 ['DiscoveryResponse is missing required Binding attribute.',
			  '/md:EntityDescriptor/md:SPSSODescriptor/md:Extensions/idpdisc:DiscoveryResponse'],
			},
	      },
	    );

foreach my $test (@tests) {
  my $file = $test->{file};
  open(F, "<$file") or die "Failed to read $file: $!";
  my $content = join('', <F>);
  close(F);

  my ($res, $errors) = checkEntityDescriptor($content);

#  warn Dumper($errors);

  # Zkontrolovat jestli to vraci co ma vratit
  my $exp_errors = join(',', sort keys %{$test->{errors}});
  if (not defined($errors)) {
    warn sprintf("Test $file failed it returned undef when '%s' was expected.\n",
		 $exp_errors);
  } elsif (scalar %{$errors} ne scalar %{$test->{errors}}) {
    warn sprintf("Test $file failed it returned '%s' when '%s' was expected.\n",
		 join(',', sort keys %{$errors}) || '',
		 $exp_errors);
  } else {
    foreach my $exp_code (keys %{$test->{errors}}) {
      if (not exists $errors->{$exp_code}) {
	warn sprintf("Test $file failed. It detected errors '%s' but not expected '$exp_code'.\n",
		     join(',', sort keys %{$errors}) || '');
      } else {
	for(my $i=0; $i<(@{$test->{errors}->{$exp_code}}/2); $i++) {
	  if ($test->{errors}->{$exp_code}->[2*$i] ne $errors->{$exp_code}->[2*$i]) {
	    warn sprintf("Test $file failed. It correctly detected error '%d', but explanation: '%s' is different than expected '%s'\n",
			 $exp_code,
			 $errors->{$exp_code}->[2*$i],
			 $test->{errors}->{$exp_code}->[2*$i]
			 );
	    warn Dumper($errors);
	  };
	  if ($test->{errors}->{$exp_code}->[2*$i+1] ne $errors->{$exp_code}->[2*$i+1]) {
	    warn sprintf("Test $file failed. It correctly detected error '%d', but XPath: '%s' is different than expected '%s'\n",
			 $exp_code,
			 $errors->{$exp_code}->[2*$i+1],
			 $test->{errors}->{$exp_code}->[2*$i+1]
			 );
	  };
	};
      };
    };
  };
};
