# eduID.cz metadata agregátor a daší federační věci

## git-check.pl
[Kontrolovátko GIT](bin/git-check.pl) které se pravidelně spouští z cronu, kontroluje lokální a vzdálený GIT repositář s metadaty. Pokud je k dispozici nějaká novinka, tak aktualizuje a spouští [aggregator](bin/aggregate.pl).

Příklad konfigurace (git-check-eduid.cfg):
```
git_repository=/home/mdx/eduid-metadata
aggregate=1
aggregate_cmd='/usr/bin/perl /home/mdx/emd2/bin/aggregate.pl --cfg /home/mdx/aggregate-eduid.cfg'
```
Použití: ``/home/mdx/emd2/bin/git-check.pl --cfg /home/mdx/git-check-eduid.cfg``

## aggregate.pl
[Aggregátor metadat](bin/aggregate.pl) slouží ke spojení jednotlivých entityDescriptorů z souborů v GIT do metadat federace na základě různých tagů. Zajištuje také volání podpisovače (XmlSigner viz níže). Volání je zaštováno z [Kontrolovátka GIT](bin/git-check.pl) a o půlnoci je vynucen podpis cronem.

Příklad konfigurace (aggregate-eduid.cfg):
```
metadata_dir = '/home/mdx/eduid-metadata'
output_dir = '/var/www/md'
sign256_cmd = '/usr/bin/java -jar /opt/signer/XmlSigner.jar -cfg /etc/signer/signer.cfg -i %s -o %s'
federations = eduid, cesnet_int, hostel, eduid2edugain, aa.cesnet.cz
validity = '27 days'

[eduid]
filters = eduid, eduid+idp, eduid+sp, eduid+idp+library, eduid+idp+university, eduid+idp+avcr, eduid+idp+hospital, eduid+idp+cesnet, eduid+idp+other
name = https://eduid.cz/metadata

[cesnet_int]
filters = cesnet-int, cesnet-int+idp, cesnet-int+sp
name = https://cesnet-int.cesnet.cz/metadata

[hostel]
filters = hostel
name = https://hostel.eduid.cz/metadata

[eduid2edugain]
filters = eduid2edugain
name = eduid.cz-edugain
```
Použití: ``/home/mdx/emd2/bin/aggregate.pl --cfg /home/mdx/aggregate-eduid.cfg``

## download-edugain.pl
[Stahovač a kouskovač eduGAINu](bin/download-edugain.pl) stahuje oficiální metadata eduGAINu, validuje je, kouskuje na jednotlivé soubory a ukládá do GIT projektu edugain pro [Aggregátor metadat](bin/aggregate.pl). Pravidelně se pouští z cronu.

## cesnet-customer.pl
[cesnet-customer.pl](bin/cesnet-customer.pl) zpracovává eduID.cz metadata IdP a pro každou entityID kontroluje číselník v LDAPu jestli ji máme evidovanou. Pokud ne, tak prostřednictvím crona mailuje před-připravený LDIF který se musí doplnit o vazbu entityID - DN organizace z CESNETího číselníku. Pokud se zavolá s parametrem ``--showStats=1`` tak zobrazí jednoduché statistiky o entitách v eduID.cz z pohledu jestli majitelé jsou nebo nejsou zákazníky CESNETu.

Skript dále zajištuje plnění atributu ``cesnetCustomerAffiliation`` pro jednotlivé záznamy v LDAPu na základě kategorie entity a toho jestli dotyčná entita patří nebo nepatří zákazníkovi.

## upload2komora.pl
[upload2komora.pl](bin/upload2komora.pl) slouží k nahrání exportu (viz proměná DataFile v níže uvedeném konfiguráku) mapujícího entityID na obchodnický identifikátor zákazníka na systém [komora.cesnet.cz](https://komora.cesnet.cz/). Příklad konfigurace (upload2komora.cfg):

```
DataFile            = '/home/mdx/komora-export/eduid-idp.json'
ServiceId           = 1
ApplicationGarantId = 1
APIKey              = 'EduIdApplication'
APISecret           = 'secret-1-2-3'
APIURL              = 'https://komora-4t.w2lan.cesnet.cz/publicapi/api/ServiceRecord/SendData'
```

## resign-download.sh
[resign-download.sh](bin/resign-download.sh) stahování a přepodepisování metadat z jaggeru. Tento skript pozbude platnosti po spuštění metamana.

## XmlSigner
Certifikát používaný pro podpisy metadat v eduID.cz je uložený v HSM, podpis realizujeme pomocí vlastní utility [XmlSigner](https://github.com/CESNET/XmlSigner).

## check_metadata
Používáme plugin [check_metadata](https://github.com/CESNET/check_metadata) pro nagios/icingu určený ke kontrole platnosti podpisu a platnosti metadat.

# Zastaralé skripty

## svn-check.pl
[Kontrolovátko SVN](bin/svn-check.pl) které se pravidelně spouští z cronu, kontroluje lokální a vzdálený SVN repositář s metadaty. Pokud je k dispozici nějaká novinka, tak aktualizuje a spouští [aggregator](bin/aggregate.pl).
