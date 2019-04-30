#!/bin/bash

XSL='<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  version="1.0">
  <xsl:strip-space elements="*" />
  <xsl:output mode="text" omit-xml-declaration="yes"/> 

  <xsl:template match="ds:Signature">
  </xsl:template>

  <xsl:template match="/">
    <xsl:apply-templates select="md:EntitiesDescriptor"/>
  </xsl:template>

  <xsl:template match="md:EntityDescriptor"><xsl:value-of select="@entityID"/><xsl:text>&#10;</xsl:text></xsl:template>

</xsl:stylesheet>
';

#echo $XSL | xsltproc - /var/www/md/eduid
#exit 0;

PD=/tmp/porovnani
if [ ! -d $PD ]
then
    mkdir $PD
else
    rm $PD/*
fi

for F in `ls -1 /var/www/md/*| grep -v unsigned`;
do
    FF=`basename $F`;

    echo ">> $FF <<";

    wget -q -O $PD/old-$FF.xml https://metadata.eduid.cz/entities/$FF

    echo $XSL | xsltproc - /var/www/md/$FF > $PD/new-$FF.entityID
    echo $XSL | xsltproc - $PD/old-$FF.xml > $PD/old-$FF.entityID

    if ! diff $PD/new-$FF.entityID $PD/old-$FF.entityID >/dev/null 2>&1
    then
	echo "PROBLEM: Rozdilne pocty/poradi entit v $FF"
	diff $PD/new-$FF.entityID $PD/old-$FF.entityID
    else
	echo "OK: Pocty entit a poradi sedi"
	#ls -l $PD/old-$FF.xml /var/www/md/$FF
    fi
done
