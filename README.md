# eduID.cz metadata agregátor a daší federační věci

## svn-check.pl
[Kontrolovátko SVN](bin/svn-check.pl) které se pravidelně spouští z cronu, kontroluje lokální a vzdálený SVN repositář s metadaty. Pokud je k dispozici nějaká novinka, tak aktualizuje a spouští [aggregator](bin/aggregate.pl).

## git-check.pl
[Kontrolovátko GIT](bin/git-check.pl) které se pravidelně spouští z cronu, kontroluje lokální a vzdálený GIT repositář s metadaty. Pokud je k dispozici nějaká novinka, tak aktualizuje a spouští [aggregator](bin/aggregate.pl).

## aggregate.pl
[Aggregátor metadat](bin/aggregate.pl) slouží ke spojení jednotlivých entityDescriptorů z souborů v GIT do metadat federace na základě různých tagů. Zajištuje také volání podpisovače (TODO, do gitu!). Volání je zaštováno z [Kontrolovátka GIT](bin/git-check.pl) a o půlnoci je vynucen podpis cronem.

## download-edugain.pl
[Stahovač a kouskovač eduGAINu](bin/download-edugain.pl) stahuje oficiální metadata eduGAINu, validuje je, kouskuje na jednotlivé soubory a ukládá do GIT projektu edugain pro [Aggregátor metadat](bin/aggregate.pl). Pravidelně se pouští z cronu.

## cesnet-customer.pl
[cesnet-customer.pl](bin/cesnet-customer.pl) zpracovává eduID.cz metadata IdP a pro každou entityID kontroluje číselník v LDAPu jestli ji máme evidovanou. Pokud ne, tak prostřednictvím crona mailuje před-připravený LDIF který se musí doplnit o vazbu entityID - DN organizace z CESNETího číselníku. Pokud se zavolá s parametrem --showStats=1 tak zobrazí jednoduché statistiky o entitách v eduID.cz z pohledu jestli majitelé jsou nebo nejsou zákazníky CESNETu.

Skript dále zajištuje plnění atributu cesnetCustomerAffiliation pro jednotlivé záznamy v LDAPu na základě kategorie entity a toho jestli dotyčná entita patří nebo nepatří zákazníkovi.

## resign-download.sh
[resign-download.sh](bin/resign-download.sh) stahování a přepodepisování metadat z jaggeru.

## XmlSigner
Certifikát používaný pro podpisy metadat v eduID.cz je uložený v HSM, podpis realizujeme pomocí vlastní utility [XmlSigner](https://github.com/CESNET/XmlSigner).

## check_metadata
Používáme plugin [check_metadata](https://github.com/CESNET/check_metadata) pro nagios/icingu určený ke kontrole platnosti podpisu a platnosti metadat.
