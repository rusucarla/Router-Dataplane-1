
# README Dataplane Router

Repository for the first homework of the Communication Networks class. In this homework the students will implement the dataplane of a router.

## Subcerinte rezolvate

Toate

## Cum le-am rezolvat ?

### Procesul de dirijare

Asemanator laboratorului 4, am verificat ca pachetul sa fie valid, i-am cautat cea mai buna ruta si l-am trimis spre destinatie

### Longest Prefix Match eficient

Cum sugera si cerinta, am folosit un trie tree. Am decis sa il implementez binar, pentru a fi mai usor sa compar fiecare bit in parcurgerea tree-ului.

### Protocolul ARP

Am folosit structura pentru tabela statica drept cache al router-ului.

Am avut o structura de date `pachet` in care am tinut minte date importante pentru a le putea accesa direct cand scot pachetul din coada.

Am verificat ca router-ul sa bage in seama doar pachetele ARP care sunt pentru acesta, celalte fiind directionate catre destinatie.

Functionalitatea este cea descrisa si in cerinta:

- primesc ARP Request, trimit un ARP reply
- primesc un ARP Reply, adaug adresa MAC in cache (pentru a face legatura intre IP - MAC) si mai apoi parcurg coada de pachete pentru a vedea pe cine pot trimite in continuare

### Protocolul ICMP

Pentru mesajele de eroare (`Destination Unreachable` si `Time Exceeded`) am facut o functie unde pregateam pachetul ICMP si il trimiteam catre sursa.

Pentru mesajele de tipul `Echo Request` am facut o functie separata pentru a trimite `Echo Reply` in care tot asa am pregatit pachetul si l-am trimis.

### Alte observatii

Am pus toate functiile in router.c pentru a fi mai eficienta rulare codului per total.
