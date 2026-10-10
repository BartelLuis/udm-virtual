# UDM Beast unter Proxmox: experimentelles virtuelles Gateway

Das Tool baut aus der originalen UDM-Beast-Firmware ein ARM64-Bootpaket für
QEMU und Proxmox. Das Profil `virtual` ergänzt die Anpassungen für virtuelle
Hardware und stellt **14 frei zuweisbare Proxmox-Netzwerkports** bereit.
Originalkernel und SquashFS bleiben unverändert; Anpassungen und Einstellungen
liegen in einem separaten beschreibbaren Overlay.

**Bekannte Einschränkung: Ubiquiti Remote Access funktioniert mit der aktuellen
virtuellen Geräteidentität nicht.** Die Cloud lehnt die Registrierung mit
HTTP 400 und `Invalid eeprom` ab. DNS, synchronisierte Uhrzeit und TLS wurden
im Gast geprüft; der EEPROM-Export des originalen Werkzeugs stimmt bytegenau
mit den virtuellen Gerätedaten überein. Welche Prüfung die Cloud verlangt, ist nicht bekannt.
Ein bestätigter Fix liegt derzeit nicht vor.
[Diagnose vom 10. Oktober 2026](verification/remote-access/report.json).

**Die originale Ersteinrichtung und die IPv4-Grundfunktionen der Firewall sind
mit R5 unter QEMU nachgewiesen.** Network erreicht `READY`, die originale
Setup-API richtet ein lokales Besitzerkonto ein, und die daraus erzeugten
UniFi-Regeln bestehen NAT-, TCP-, UDP-, DNS- und WAN-Sperrtests. Die originale
Webseite ist vom LAN per HTTPS erreichbar; interaktive Konfigurationsabläufe
im Browser sind noch ungeprüft. Mit dem Importer R5.1 ist auch der vollständige
Import auf Proxmox 9.2.21 nachgewiesen; die VM wurde dabei ausgeschaltet angelegt.
Nach sauberem Herunterfahren und erneutem Start bleiben Einrichtung und
Konfiguration erhalten; Anmeldung und sämtliche genannten IPv4-Tests bestehen erneut.
Auf einem Intel Xeon läuft ARM64 durch QEMU-TCG-Emulation ohne KVM-Beschleunigung.
Der Erststart mit Einrichtung dauerte auf dem Debian-Testserver rund zwölf
Minuten. Durchsatz, IPv6 und VLANs sind noch nicht getestet.

Liegt bereits das fertige Verzeichnis `build-virtual` mit `manifest.json`,
Kernel, Initramfs und beiden Platten bei, direkt mit
[Auf Proxmox importieren](#auf-proxmox-importieren) fortfahren. Ein Neubau ist
nur zum erneuten Erzeugen des Pakets nötig; auf dem Proxmox-Knoten wird die
Firmwaredatei dafür nicht gebraucht. Das ursprüngliche Firmware-Updatefile
(`*.bin`) ist im Release-Paket nicht enthalten.

## DNS-Korrektur R5.2

R5.2 verhindert zwei zusätzliche DNS-Dienste, die systemd beim ersten Start
des virtuellen Abbilds durch seine Voreinstellungen aktiviert. Der allgemeine
`dnsmasq.service` kollidiert mit dem bereits von UniFi gestarteten dnsmasq.
Zusätzlich ersetzt `systemd-resolved` die Resolver-Datei durch seinen Stub,
obwohl ihm keine vorgeschalteten DNS-Server zugewiesen sind. Dadurch kann die
VM selbst keine Namen auflösen, während der DNS-Dienst für LAN-Clients läuft.

Das virtuelle Bootprofil maskiert diese beiden zusätzlichen Dienste. Eine
fehlende Resolver-Datei oder einen Link auf die Standarddateien von
systemd-resolved ersetzt es atomar durch `nameserver 127.0.0.1`. Eigene
Resolver-Dateien und andere Links bleiben erhalten. UniFi verwaltet weiterhin
seinen dnsmasq und dessen DNS-Server in `/etc/resolv.dnsmasq`.

Die entsprechende Korrektur wurde in einer laufenden R5.1-VM unter Proxmox
bestätigt: Die direkte DNS-Abfrage funktionierte bereits; nach der Änderung
funktionierte auch `getent ahostsv4 google.com`. Die automatische Einrichtung
ist separat mit temporären Gast-Dateibäumen geprüft. Ein vollständiger
Kaltstart mit dem neuen R5.2-Initramfs ist noch nicht geprüft; die nachfolgenden
Boot- und Firewall-Nachweise beziehen sich weiterhin auf R5.
[DNS-Prüfbericht](verification/dns-resolver/report.json).

### Bereits laufende R5-/R5.1-VM korrigieren

Den folgenden Block **in der UniFi-VM** ausführen. Er prüft zuerst den
nativen DNS-Dienst und sichert die bisherige Resolver-Datei. Ein Neuimport
oder Austausch der Zustandsplatte ist dafür nicht nötig.

```sh
nslookup google.com 127.0.0.1 && (
  set -e
  cp -a --backup=numbered /etc/resolv.conf /etc/resolv.conf.before-udm-dns-fix
  systemctl mask dnsmasq.service systemd-resolved.service
  systemctl daemon-reload
  systemctl stop systemd-resolved.service
  f=$(mktemp /etc/resolv.conf.udm.XXXXXX)
  printf 'nameserver 127.0.0.1\n' > "$f"
  chmod 644 "$f"
  mv -Tf "$f" /etc/resolv.conf
  systemctl reset-failed dnsmasq.service
  getent ahostsv4 google.com
)
```

Das maskierte `dnsmasq.service` ist anschließend beabsichtigt inaktiv.
Der von UniFi gestartete Prozess bleibt bestehen; er lässt sich mit
`ss -lntup '( sport = :53 )'` prüfen. Die Änderung liegt im persistenten Overlay.

## Prüfstand und bisherige Laufzeittests

Prüfstand vom 9. Oktober 2026, unter Debian/WSL und auf einem separaten Debian-13-Server:

Die verlinkten Boot- und Paketprüfberichte prüfen den bisherigen Build R5 mit
folgendem SHA256 der `initramfs.gz`:

```text
ccff18466c8bbd099c692d77587a4ee789728ce223a0d653f86c4e752035937f
```

Kernel, Rootfs und ursprüngliches Zustandsabbild sind gegenüber dem vorherigen
Build unverändert. Zusätzlich zu den isolierten Boot- und Testregelprüfungen
wurde R5 auf dem Debian-Server mit unbenutztem Zustandsabbild eingerichtet und
mit der von UniFi selbst erzeugten Firewall-Konfiguration getestet.

| Funktion | Stand |
| --- | --- |
| Originaler ARM64-Kernel, Rootfs und beschreibbares Overlay | R5-Selbsttest auf nativem Linux-Dateisystem bestanden, 100,174 Sekunden Gastzeit, bei umgekehrter PCI-Reihenfolge aller 14 Karten |
| Rootfs-Abbild gegenüber extrahierter Originalpartition | Blockvergleich mit `qemu-img compare`: identisch |
| 14 VirtIO-Ports | Erkennung nachgewiesen |
| Originale HAL-Module, `usdbd`, `uhwd` | Start mit virtuellen Boarddaten nachgewiesen |
| Angepasster originaler UDAPI-Gateway-Dienst | Start und Konfiguration der Linux-Interfaces nachgewiesen |
| Originale UDAPI-Konfigurations-API | In einem früheren Forschungslauf: `PUT /system/ubios/udm/configuration` nach A12-Anpassung akzeptiert |
| LAN-/WAN-DHCP und Erreichbarkeit des LAN-Gateways | Im isolierten Test nachgewiesen |
| UniFi Core über HTTPS | Originale lokale Einrichtung über `POST /api/setup`: HTTP 200; anschließend `isSetup: true` |
| UniFi Network | R5: `READY`, `isReadyForSetup: true`, nach Einrichtung `isConfigured: true`; originale UBIOS-Regeln aktiv |
| AES-GCM-Cacheabgleich | Bytecodeprüfung mit originaler JVM bestanden; integrierter R5-Start, Einrichtungsfreigabe und native Provisionierung erfolgreich |
| Aktualisierung des bekannten R3/R4-Controllerarchivs | Im Forschungsgast erfolgreich; identische R5-Anpassungsdateien und sauberes Herunterfahren nachgewiesen. Anwendungseinstellungen nach Migration noch nicht geprüft |
| FreeRADIUS | Frische lokale TLS-Initialisierung und laufender Dienst im R5-Erststart bestätigt |
| Später PHY-Diagnosehook | Historischer Stand R3/R4: Modulladung verweigert, Ersatzhook erfolgreich und später Systemstart bis zu aktiven `multi-user.target` und `sysready.target` bestätigt |
| IPv4-NAT und Firewall-Paketfilter | Sechs Prüfungen mit originaler UniFi-Regelmenge bestanden; zusätzlich echte TCP-/UDP-Rundläufe und WAN-TCP-Sperre bestanden |
| DNS und Weboberfläche | DNS über das originale Gateway und anonymer HTTPS-Abruf der UniFi-HTML-Seite bestanden |
| Ubiquiti Remote Access / Site Manager | Aktuell nicht funktionsfähig: Cloudregistrierung verweigert das virtuelle EEPROM mit HTTP 400; kein bestätigter Fix |
| Sauberes Herunterfahren und erneuter Start | Besitzeranmeldung, konfigurierte Network-Anwendung und sämtliche nativen IPv4-Tests erneut bestanden |
| Interaktive Browser-Konfiguration, VLANs und IPv6 | Noch offen |
| Kaltstart bis zum abgeschlossenen nativen IPv4-Pakettest | R5 bestanden, rund 716,3 Sekunden; 8 GiB Gast-RAM, sechs emulierte Kerne |
| Import auf einem echten Proxmox-Knoten | R5.1 auf Proxmox 9.2.21 bestanden: automatische VMID, 14 getrennte Ports, beide Platten nach Import blockweise identisch |
| Laufende VM unter Proxmox | R5.1: LAN-DHCP direkt beobachtet; Internet-Ping und DNS-Korrektur durch Gast-Konsolenausgaben des Benutzers bestätigt. R5.2-Kaltstart und Durchsatz noch offen |

Die [Importer-Prüfung](verification/proxmox-vmid/report.json) ergänzt die
[reale Proxmox-Prüfung](verification/proxmox-vmid/live-import-report.json).
R5.1 behebt den falschen Vergleich einer JSON-Zeichenkette wie `"100"` mit der
VMID, wählt freie IDs automatisch und berücksichtigt den Proxmox-Maschinentyp
`virt+pve0`. Im leeren Cluster wurde VM 100 importiert; anschließend wählte die
schreibgeschützte Auswahlprüfung für die belegte Wunsch-ID 100 korrekt ID 101.
Es wurde keine zweite VM erstellt. Bei R5.1 blieben Kernel, Initramfs und beide
gelieferten Plattenabbilder gegenüber R5 unverändert; R5.2 ändert das Initramfs.

Der [native R5-Gateway-Prüfbericht](verification/native-gateway-r5/report.json)
fasst den Erststart auf Debian 13 mit QEMU 10.0.13 und AMD Ryzen 5 3600 zusammen.
Der Forschungsgast verwendet dieselben 20 Anpassungsdateien wie das damalige R5-Release;
nur `/init` ergänzt eine lokale Diagnosekonsole und eine schreibgeschützte
Diagnosefreigabe. Sein Zustandsabbild begann als frisches Overlay des exakten
Release-Abbilds. Die originale Setup-API wurde erst nach der unveränderten
Einrichtungsfreigabe von Network aufgerufen. Die Zugangsdaten des Testkontos
sind nicht Bestandteil des Pakets; jeder Import beginnt mit einem unbenutzten
Zustandsabbild und erhält bei der Einrichtung ein eigenes Besitzerkonto.

Der native Pakettest verwendete keine temporäre Testregelmenge. Acht
unaufgeforderte WAN-ICMP-Pakete wurden während 10,187 Sekunden gesperrt;
anschließend funktionierte ein weiterer NAT-Rundlauf. Im getrennten
Protokolltest bestanden TCP und UDP mit beobachteter WAN-Quelladresse,
DNS-Auflösung über `192.168.1.1` und der HTTPS-Abruf der UniFi-Seite.
Drei eingehende WAN-TCP-Verbindungsversuche erzeugten neun SYN-Pakete und
erreichten den LAN-Empfänger nicht; danach funktionierten TCP und UDP weiter.
Die Testnetze hatten keinen Internet-Uplink. Das belegt grundlegende
IPv4-Funktionen, keine vollständige Prüfung aller Firewall-Funktionen.

Der [R5-Neustartbericht](verification/native-gateway-r5/reboot-report.json)
dokumentiert ein sauberes Herunterfahren und den Start desselben eingerichteten
Zustandsabbilds. Es wurde kein zweites Besitzerkonto eingerichtet. Die normale
Anmeldung über `POST /api/auth/login` und der authentifizierte Systemabruf
bestanden; Core meldet `isSetup: true`, Network wieder `READY` und
`isConfigured: true`. Alle sechs Paketprüfungen bestanden nach rund 116,7
Sekunden einschließlich Start; die Network-Anwendung war nach etwa sechs
Minuten wieder gestartet. Anschließend bestanden auch TCP, UDP, DNS, HTTPS
und die WAN-TCP-Sperre erneut. Das prüft einen regulären Neustart, keine
Stromausfallwiederherstellung, Langzeitstabilität oder HA-Migration.

Der [historische Network-Startbericht](verification/native-network-startup/report.json)
dokumentiert den erfolgreichen Start der Originalanwendung mit den Anpassungen
von **R3/R4**: `READY` um 14:00:50 UTC, automatische Gateway-Adoption abgeschlossen
um 14:01:54 UTC und erfolgreiche Ausführung der späten Boot-Hooks. Der Gast war
danach weiter erreichbar; beide Systemziele waren aktiv. Die Zeitangaben stammen
aus der Gastuhr. Dieser Forschungslauf verwendet ein bereits benutztes
Zustandsabbild und eine zusätzliche lokale Diagnosekonsole; er ist kein
Erststartnachweis mit dem unbenutzten Release-Zustandsabbild. Er bezieht sich auf
den im Bericht genannten R3/R4-Initramfs-Hash.
Network meldete dabei `isReadyForSetup: false`. Die abgeschlossene
Adoption allein belegt weder die Bereitschaft zur Ersteinrichtung noch eine
durch UniFi provisionierte Firewall.

Der separate [AES-GCM-Prüfbericht](verification/native-gcm-cache/report.json)
dokumentiert die beobachteten abweichenden Controllercaches und die Prüfung
der neuen Kandidatenklasse mit `-Xverify:all` in der originalen Gast-JVM.
Dabei wurde die Klasse ohne Initialisierung oder Aufruf ihrer Methoden geladen.
Dieser isolierte JVM-Test wird inzwischen durch den oben verlinkten
erfolgreichen R5-Gateway-Lauf mit nativer Einrichtungsfreigabe ergänzt.

Der [aktuelle Kaltstart-Paketprüfbericht](verification/network-coldboot/report.json) bestätigt LAN- und WAN-DHCP,
LAN-Gateway-Ping, ausgehendes NAT, den Rückweg sowie die Sperre unaufgeforderter
WAN-Pakete. Während 10,088 Sekunden wurden acht ICMP-Testpakete vom WAN gesendet;
keines erreichte das LAN. Ein erfolgreicher NAT-Rundlauf nach dem letzten
gesperrten Testpaket bestätigt, dass die VM weiter Pakete verarbeitete.
Der Test startete mit einem Snapshot des unbenutzten Zustandsabbilds und ausdrücklich
gesetzten temporären Testregeln. Er dauerte einschließlich Kaltstart 357,057 Sekunden: 3 GiB Gast-RAM,
vier emulierte Kerne, QEMU 10.0.13 unter Debian/WSL auf einem AMD Ryzen 4450U.
Das ist kein Durchsatztest und kein Nachweis einer Einrichtung über UniFi.

Der [aktuelle Boot-Selbsttest auf nativem Linux-Dateisystem](verification/boot-selftest/report.json)
bestand mit umgekehrter PCI-Reihenfolge aller 14 Karten in 100,174 Sekunden
Gastzeit; außen gemessen dauerte der Lauf 108,509 Sekunden. Die Zuordnung
von MAC-Adressen zu eth0 bis eth13 wurde dabei im echten Gast korrigiert. Ein früherer WSL-Lauf mit Abbildern unter `/mnt/c`
meldete I/O- und `SQUASHFS error:`-Lesefehler. Er zählt trotz späterem PASS-Marker
als fehlgeschlagen. Die Auswertung lehnt solche Fehler inzwischen ausdrücklich
ab; der anschließende Blockvergleich bestätigte den unveränderten Inhalt der
Originalpartition.

Die Ergebnisse des alten Laborprofils unter `build/`, insbesondere
`build/validation.json`, dokumentieren einen früheren Stand. Sie sind kein
Prüfbericht für das virtuelle Profil. Die verlinkten Berichte unter
`verification/` gelten für die jeweils darin dokumentierten Artefakt-Hashes;
Interaktive Konfigurationsabläufe im Browser und der R5.2-Kaltstart sind
weiterhin nicht getestet; der Import ist mit R5.1 separat nachgewiesen.

## Virtuelles Paket bei Bedarf neu bauen

Für den Import des bereitgestellten Pakets ist dieser Schritt nicht nötig.
Für einen Neubau wird das eigene originale Firmware-Updatefile benötigt.

Benötigt werden Python 3.9 oder neuer und unter Linux `qemu-img`, `mke2fs` und
`unsquashfs`. Für lokale Boot- und Netzwerktests kommt `qemu-system-aarch64`
hinzu. Die entsprechenden Debian-Pakete heißen `qemu-utils`, `e2fsprogs`,
`squashfs-tools` und `qemu-system-arm`. Bei einer Installation ohne empfohlene
Pakete zusätzlich `ipxe-qemu` installieren: QEMU erwartet für die VirtIO-Karten
die Datei `efi-virtio.rom`, auch beim direkten Kernelstart.
Die Skripte installieren keine Pakete.

Das virtuelle Profil ist an die untersuchte Firmware **UDMEA4C.cn10k 5.1.33**
mit diesem vollständigen SHA256 gebunden:

```text
31c8607480519ff164f1eacd4a8c021202afe99914ff56077df32c2d235b1734
```

Auch die Änderungen am originalen Netzwerkprogramm werden anhand seines Hashes
und der erwarteten Maschinenbefehle geprüft. Unbekannte Firmware wird abgelehnt.

Unter Linux aus dem Projektordner:

```bash
python3 build.py --profile virtual --firmware /pfad/firmware.bin --output build-virtual-neu
```

Unter Windows mit vorhandener Debian-WSL-Installation:

```powershell
.\build.ps1 -Profile virtual -Firmware 'C:\Pfad\firmware.bin' -Output build-virtual-neu
```

Ohne expliziten Firmwarepfad muss genau eine `*.bin` im Projektordner liegen.
Eine Datei lässt sich unter Linux mit `--firmware /pfad/firmware.bin` und im
Windows-Wrapper mit `-Firmware 'C:\Pfad\firmware.bin'` angeben. Der Wrapper
akzeptiert für `-Output` und `-Firmware` absolute Windows- oder Linux-Pfade;
relative Pfade beziehen sich auf den Ordner von `build.ps1`.
`--state-size-gib 32` beziehungsweise `-StateSizeGiB 32` ist die Voreinstellung;
zulässig sind 8 bis 256 GiB. Ausgabeordner müssen neu sein. Die Beispiele erzeugen
`build-virtual-neu`; bei dessen Import die folgenden `--assets`-Pfade entsprechend
ersetzen. Unter WSL ein natives Linux-Dateisystem für Build und VM-Abbilder
verwenden, zum Beispiel einen neuen Ausgabeordner unter `/home/luis/`.

Der Build prüft die CRCs des UBNT-Containers und die FIT-Hashes. Vorhandene
Herstellersignaturen werden gemeldet, aber nicht als authentifiziert ausgegeben.
Firmwareprogramme werden beim Build nicht auf dem Host ausgeführt.

## Auf Proxmox importieren

Release-Pfad: `release/udm-beast-proxmox-5.1.33.tar` mit zugehöriger
`.tar.sha256`-Datei. Beide Dateien auf den gewünschten Proxmox-Knoten kopieren.
Im Zielordner zuerst Archiv und danach die entpackten Dateien prüfen:

```bash
sha256sum -c udm-beast-proxmox-5.1.33.tar.sha256
tar xf udm-beast-proxmox-5.1.33.tar
cd udm-beast-proxmox
sha256sum -c SHA256SUMS
```

Nur nach erfolgreichen Prüfungen importieren. Alternativ lassen sich diese
Dateien mit derselben Verzeichnisstruktur einzeln auf den Knoten kopieren:

```text
build-virtual/Image
build-virtual/initramfs.gz
build-virtual/rootfs.qcow2
build-virtual/state.qcow2
build-virtual/manifest.json
proxmox-import.sh
```

Den Storage im Beispiel an den eigenen Knoten anpassen. Die VMID wird
automatisch über Proxmox clusterweit gewählt; dabei zählen auch Container
und Gäste auf anderen Knoten als belegt. Der folgende Aufruf bereitet alle
14 Ports ohne Bridge-Zuordnung vor:

```bash
bash proxmox-import.sh \
  --storage local-lvm --assets ./build-virtual --dry-run
```

Ohne `--apply` prüft der Importer die Dateien und gibt einen ausführbaren
`--apply`-Aufruf aus. Dabei wird noch keine Cluster-Abfrage ausgeführt oder
VMID reserviert. Die Auswahl erfolgt erst bei der Ausführung auf dem Zielhost.
Mit `--apply`, als Root auf dem Proxmox-Knoten, prüft er zusätzlich den Host und
erstellt eine **ausgeschaltete** VM:

```bash
bash proxmox-import.sh \
  --storage local-lvm --assets ./build-virtual --apply
```

Die tatsächlich gewählte VMID steht am Ende der Ausgabe, zusammen mit den
passenden `qm config`, `qm start` und `qm terminal`-Befehlen. Mit `--vmid 991`
lässt sich weiterhin eine Wunsch-ID angeben: Ist sie belegt, nimmt der Importer
automatisch die nächste von Proxmox gemeldete freie ID. `--vmid auto` entspricht
dem Standard. API-Fehler werden als solche gemeldet; eine ungültige Antwort
wird nicht als belegte ID behandelt. Eine Abfrage reserviert die ID noch nicht:
Bei einem gleichzeitigen Import schützt `qm create` vorhandene Gäste; bei einer
Kollision den Import erneut ausführen.

Es werden immer alle 14 Karten angelegt. `--port N=BRIDGE` weist einzelne Karten
zu; ohne jede `--port`-Angabe bleiben alle Karten ohne Bridge. Die Zuordnung
kann anschließend in Proxmox geändert werden. Host-Bridges werden weder
erstellt noch umkonfiguriert. Soll die Zuordnung bereits beim Import erfolgen,
beispielsweise `--port 8=vmbr1 --port 0=vmbr2` ergänzen; die Bridge-Namen müssen
auf dem eigenen Knoten vorhanden sein.

**Alle 14 Karten und ihre vom Importer vergebenen MAC-Adressen beibehalten.**
Nicht benötigte Karten getrennt lassen, statt sie zu löschen. Der Gast ordnet
`eth0` bis `eth13` anhand des zusammenhängenden MAC-Blocks zu, auch wenn Proxmox
die PCI-Geräte anders aufzählt. Fehlende Karten oder geänderte MAC-Adressen
können den Start verhindern. In Proxmox nur die gewünschte Bridge und den
Linkzustand ändern; MACs nicht automatisch neu erzeugen lassen.

| Proxmox-Karte | Gast-Interface | Anfängliche Rolle |
| --- | --- | --- |
| `net0` bis `net7` | `eth0` bis `eth7` | Gemeinsames LAN `br0` |
| `net8` | `eth8` | WAN |
| `net9` bis `net11` | `eth9` bis `eth11` | Gemeinsames LAN `br0` |
| `net12` | `eth12` | WAN2 |
| `net13` | `eth13` | Gemeinsames LAN `br0` |

Die Bridge ist frei wählbar; die Bridge-Zuweisung ändert diese anfängliche
WAN-/LAN-Rolle nicht. Weitere LAN-Ports sind zunächst Mitglieder desselben
LANs, keine getrennten Firewallzonen. Änderungen durch spätere
UniFi-Provisionierung sind noch zu prüfen.

Standardmäßig sind **alle Links getrennt**, auch bei zugewiesener Bridge.
In Proxmox bei den gewünschten Karten „Link down“ deaktivieren. Alternativ
verbindet `--connect` beim Import alle zugewiesenen Karten; nicht zugewiesene
Karten bleiben getrennt. Für den ersten Start separate Test-Bridges verwenden,
da der originale Dienst im LAN einen DHCP-Server startet.

Danach ausdrücklich starten; `991` durch die vom Importer ausgegebene VMID ersetzen:

```bash
qm start 991
qm terminal 991
```

Das virtuelle Profil startet standardmäßig das originale Systemd-System.
Nach dem Dienststart ist die anfängliche LAN-Adresse `192.168.1.1/24`; ein
Client am zugewiesenen LAN-Port kann die Core-Oberfläche unter
`https://192.168.1.1` aufrufen. **Vor dem Einrichtungsassistenten auf die
Bereitschaft von Network warten.** Eine erreichbare Core-Seite allein reicht
dafür nicht. Vor der Ersteinrichtung lässt sich vom LAN aus ohne Anmeldung
`https://192.168.1.1/api/apps` öffnen. Im Array `controllers` muss der Eintrag
mit `name: "network"` sowohl `isRunning: true` als auch
`info.isReadyForSetup: true` melden. Solange der Eintrag fehlt oder nicht bereit
ist, weiter warten; kein wiederholtes Absenden der Einrichtung.
Die native Einrichtung mit lokalem Besitzerkonto und die anschließend
erzeugte Gateway-Konfiguration wurden über die originale Setup-API geprüft.
`--boot-mode shell` erstellt stattdessen eine VM mit lokaler Diagnose-Shell,
ohne gestartete Gateway-Dienste.

Voreinstellung beim Import: 8 GiB RAM, vier emulierte Kerne. Anpassung über
`--memory MIB` und `--cores N`. Genügend RAM für Host und Gast einplanen:
Host-Swapping hat lokale Tests stark verlangsamt. Mehr emulierte Kerne ersetzen
keine Hardwarebeschleunigung.
Für langsame TCG-Starts sind die Startzeitlimits von UniFi Network und RabbitMQ
auf 3600 Sekunden, von UniFi Core und der FreeRADIUS-DH-Erzeugung auf 600 Sekunden
erweitert. Die lokale TLS-Initialisierung erhält ebenfalls 600 Sekunden.
Diese Wartezeiten sind keine Zusage, dass sämtliche Dienste erfolgreich starten.
Ein Java-Wrapper ersetzt außerdem die originale C2-Einstellung durch C1,
um den Start unter TCG zu erleichtern. Das virtuelle Profil startet Network
standardmäßig über einen entpackten, hashgeprüften Klassenpfad (`flat`).
Ein früherer Start erreichte die originale `READY`-Meldung, bevor ein physischer
PHY-Diagnosehook den Kernel abstürzen ließ. Mit dessen gezielter Sperre wurden
im R3/R4-Forschungsgast anschließend `READY` und ein erfolgreicher später
Systemstart beobachtet. Mit R5 sind inzwischen auch die originale Einrichtung
und IPv4-Pakettests erfolgreich. Der dokumentierte Serverlauf verwendet
8 GiB RAM und sechs Kerne; diese Konfiguration lässt sich mit `--cores 6`
wählen. Ein Durchsatzgewinn oder KVM-Beschleunigung wird damit nicht behauptet.

Der Knoten benötigt ARM64-QEMU sowie eine Proxmox-Version, die `--cpu max`
für ARM-VMs berücksichtigt. Der Importer prüft den von `qm` erzeugten Aufruf
auf CPU, `virt`/GICv3, direkten Kernelstart und deaktiviertes KVM. Bei einem
Fehler kann eine teilweise angelegte, ausgeschaltete VM zurückbleiben; das
Skript meldet die betroffenen Ressourcen und löscht sie nicht automatisch.

## Lokaler Start und Boot-Selbsttest

Unter Linux/WSL aus dem Projektordner:

```bash
python3 run-lab.py --assets build-virtual --mode selftest
python3 run-lab.py --assets build-virtual --snapshot
python3 run-lab.py --assets build-virtual --mode shell --snapshot
```

Für das virtuelle Profil wählt der Runner automatisch 14 Karten und, ohne
`--mode`, den Modus `systemd`. Lokal gelten standardmäßig 4 GiB RAM und zwei
Kerne; `--memory` und `--cores` ändern diese Werte. Der Runner aktiviert
VirtIO-Speicherrückgabe für freie Gastseiten. Unter WSL die Abbilder für den Test
auf ein natives Linux-Dateisystem kopieren und `--assets` auf dieses Verzeichnis
setzen; der fehlgeschlagene `/mnt/c`-Lauf ist oben dokumentiert.

Alle lokalen Ports hängen an getrennten internen QEMU-Hubs ohne Host- oder
Internetzugang. Dieser Runner stellt die Weboberfläche nicht im Host-Browser
bereit. In der Diagnose-Shell beendet `/bin/busybox poweroff -f` den Gast;
QEMU lässt sich außerdem mit `Ctrl+A`, danach `X` verlassen.

Der Selbsttest prüft Kernelstart, Firmwareversion, erwartete VirtIO-Ports,
schreibgeschützte SquashFS, ext4-Zustandsplatte und Schreib-/Lesezugriff im
Overlay. Exitcode 0 erfordert PASS-Marker, reguläres QEMU-Ende und keine erkannten
fatalen Meldungen, einschließlich `SQUASHFS error:`. Das Protokoll wird live
standardmäßig nach `build-virtual/selftest.log` geschrieben; `--log DATEI` ändert
das Ziel. Systemd, Webeinrichtung und Paketweiterleitung sind nicht Teil dieses
Tests.

Der Selbsttest verwirft Plattenänderungen automatisch; bei anderen Modi tut
dies `--snapshot`. Ohne diese Option bleiben Einstellungen auf `state.qcow2`
erhalten. Der Proxmox-Importer prüft auch deren ursprünglichen Manifest-Hash.
Zum Import deshalb ein frisches Paket oder eines mit ausschließlich verworfenen
Teständerungen verwenden. MAC-Adressen nach der ersten persistenten Einrichtung
beibehalten: Die virtuelle Identität ist an den angelegten MAC-Block gebunden.

## Isolierte IPv4-Pakettests

Der eigene Testrunner startet eine VM mit verworfenen Zustandsänderungen und
verbindet ausschließlich LAN-Port 0 und WAN-Port 8 mit lokalen Testpartnern.
Er verwendet weder Host-Bridges noch TAP-Geräte oder Internetzugriff.

Mit der vorhandenen Gastkonfiguration:

```bash
python3 validate-network.py --assets build-virtual \
  --output validation-runs/factory-01 --timeout 600
```

Die originale Konfiguration vor der Einrichtung blockiert die WAN-Weiterleitung.
Ein dabei scheiternder NAT-Test bedeutet deshalb nicht automatisch, dass die
Linux-Paketweiterleitung defekt ist. Für einen getrennten Test der
Paketverarbeitung lässt sich eine ausdrücklich temporäre Testregelmenge laden:

```bash
python3 validate-network.py --assets build-virtual \
  --output validation-runs/dataplane-01 --timeout 600 --test-policy
```

**`--test-policy` ersetzt keine Einrichtung oder Provisionierung über UniFi.**
Es erlaubt im verworfenen Snapshot IPv4-Verkehr vom LAN zum WAN und zugehörige
Antworten, während neue WAN-zu-LAN-Verbindungen blockiert bleiben. Normale
Starts behalten die originale Konfiguration für die Ersteinrichtung.

Geprüft werden LAN-/WAN-DHCP, LAN-Gateway-Ping, ausgehendes ICMP mit NAT,
Rückweg und das Blockieren unaufgeforderter ICMP-Pakete vom WAN. Ein zusätzlicher
erfolgreicher NAT-Rundlauf verhindert, dass eine stehengebliebene VM allein
durch ausbleibende Antworten den Blockiertest besteht. Nicht geprüft werden
damit DNS, TCP-/UDP-Weiterleitung, IPv6, Internetzugang oder Durchsatz.

Jeder neue Ausgabeordner enthält `report.json`, `serial.log`, `qemu.log`,
`command.json` und `packets.pcap`. Der Bericht nennt die verwendete Regelmenge
und kennzeichnet `unifi_ui_provisioning_tested` ausdrücklich als `false`.
Der mitgelieferte [Paketprüfbericht vom 9. Oktober](verification/network-coldboot/report.json)
enthält den bestandenen Kaltstartlauf des aktuellen Builds mit allen sechs
Prüfungen, acht blockierten WAN-Testpaketen, keinem ins LAN durchgelassenen
Testpaket und einem erfolgreichen NAT-Rundlauf nach dem letzten Blockiertest.

## Anpassungen und Betrieb

| Bestandteil | Aufgabe |
| --- | --- |
| `firmware.py`, `fit.py` | Firmwarecontainer und FIT prüfen und extrahieren |
| `build.py`, `build.ps1` | Profil wählen, Platten und Hashmanifest bauen |
| `guest-lab-init.sh`, `initramfs.py` | Initramfs-Einstieg ersetzen und Overlay einhängen |
| `virtualization/hal_guest.py`, `hal_eeprom.py` | Lokale virtuelle Boarddaten für die originalen HAL-Module bereitstellen |
| `virtualization/patch_cpss.py`, `network.py` | Abhängigkeiten vom fehlenden Switch-ASIC anpassen und VirtIO-Ports zuordnen |
| `virtualization/patch_controller.py` | Zehn physische Switch-Zuordnungen im Beast-Portmodell anpassen und den Gerätecache nach authentifizierten AES-GCM-Inform-Nachrichten abgleichen |
| `virtualization/controller_guest.py` | Geprüftes Controllerarchiv atomar installieren; den exakt bekannten vorherigen Overlay-Stand aus der Originalfirmware aktualisieren |
| `virtualization/controller_flat.py`, `java-tcg.sh` | Hashgeprüften Controllercache erzeugen und die originale Anwendung mit C1 über einen entpackten Klassenpfad starten |
| `virtualization/freeradius_dh.py` | Öffentliche DH-Parameter prüfen und bei Bedarf atomar erzeugen |
| `virtualization/freeradius_cert.py` | Fehlendes lokales TLS-Paar vor FreeRADIUS mit der Originalvorlage erzeugen und bestehende gültige Dateien erhalten |
| `virtualization/late_boot.py` | Nur den hashgeprüften physischen PHY-Diagnosehook ersetzen und seine Kernel-Modulsperre verlangen |
| `virtualization/boot.sh` | Anpassungen vor dem originalen Systemstart anwenden |
| `run-lab.py` | Isolierter lokaler Start und Boot-Selbsttest |
| `proxmox-import.sh` | Geprüfter Import mit frei zugewiesenen Bridges |
| `validate-network.py`, `validation/` | Separate IPv4-Pakettests und Protokolle |

Gebootet wird mit QEMUs `virt`-DTB, CPU `max`, GICv3 und TCG. Vier
boardgebundene Kernel-Initialisierungen werden per Bootparameter übersprungen.
Die originalen HAL-Module lesen lokal erzeugte virtuelle EEPROM-Metadaten;
Gerätezugangsdaten werden dabei nicht erzeugt oder kopiert. Der gezielt
angepasste UDAPI-Dienst nutzt Linux-Interfaces statt des fehlenden CPSS-ASICs.
Marvell-Hardware-Offload steht nicht zur Verfügung. Die Konvertierung der
anfänglichen Boardkonfiguration wird durch einen zweiten, hashgebundenen Patch
im originalen Network-Controller ergänzt: Nur die zehn Beast-Ports `eth2` bis
`eth11` verwenden dort den bereits vorhandenen Helfer für Ports ohne Switch.
Diese Portanpassung lässt die Portmodelle anderer Geräte unverändert;
Methodensignaturen und Bytecodelängen bleiben erhalten.
Ein erfolgreicher Archivtest bestätigt noch keine vollständige
Switch-/VLAN-Provisionierung; diese Laufzeitprüfung bleibt offen.

Ein weiterer hashgebundener Controllerpatch gleicht nach jeder erfolgreich
authentifizierten AES-GCM-Inform-Nachricht den vollständigen Gerätecache über
den originalen Setter ab. Hintergrund sind auseinanderlaufende Controllercaches,
bei denen der originale Dienst wiederholt die Verschlüsselungskonfiguration
sendet und die weitere Provisionierung nicht erreicht. Die originale AES-GCM-
Erkennung sowie Entschlüsselungs- und Authentisierungsprüfungen bleiben erhalten.
Die zusätzliche Invalidierung des kleinen Gerätecaches betrifft **alle
authentifizierten AES-GCM-Geräte** und kann zusätzliche Datenbankzugriffe
verursachen. Verbindungszustand, Adoption und Einrichtungsbereitschaft werden
durch den Patch nicht erzwungen.

Bei einem bereits benutzten Zustandsabbild erkennt der Installationshelfer
ausschließlich den per SHA256 festgelegten vorherigen Controllerstand mit der
Beast-Portanpassung (R3/R4). Er erzeugt das neue Archiv erneut aus der
hashgeprüften Originaldatei im schreibgeschützten SquashFS auf `/dev/vda`;
umgeleitete Pfade oder darübergelegte Mounts werden abgelehnt. Nur `ace.jar`
wird atomar ersetzt; Konfigurationsdaten liegen weiter im bisherigen
Zustandsabbild. Der [Migrationsbericht](verification/controller-migration/report.json)
bestätigt den Installationspfad im Gast, noch nicht das Verhalten bestehender
Einstellungen in der gestarteten Anwendung.
Ein unbekanntes Controllerarchiv führt zum Startabbruch. Diese gezielte
Aktualisierung ist kein allgemeines Firmware- oder Anwendungsupdateverfahren.

Für den Network-Start legt ein Root-Helfer einen Cache unter
`/var/cache/udm-virtual/controller-flat/` an. Er entpackt das bereits geprüfte
Controllerarchiv, erhält die Bibliotheken und die Reihenfolge des originalen
Klassenpfads und startet die originale `com.ubnt.ace.BootLauncher`-Klasse.
Dadurch entstehen keine weiteren Bytecodeänderungen. Der Cache ist an den
Archivhash gebunden, wird erst vollständig geprüft veröffentlicht und ist für
den Dienst nicht beschreibbar. Vor der Wiederverwendung werden Dateibestand,
Größen, Rechte und SHA256 erneut geprüft; ein beschädigter Cache führt zum
Startabbruch. Build und Cache-Erstellung führen keine Java-Anwendung auf dem
Host aus. Das virtuelle Profil wählt diesen Startweg standardmäßig.

Beim Kaltstart blockierte außerdem die originale FreeRADIUS-DH-Erzeugung den
abhängigen UDAPI-Dienst: Ihr 20-Sekunden-Limit hinterließ eine leere Datei, die
der ursprüngliche Helfer beim nächsten Start allein wegen ihrer Existenz
akzeptierte. Der virtuelle Helfer prüft vorhandene Parameter mit OpenSSL und
erzeugt bei Bedarf neue mit denselben Originalargumenten (`-dsaparam`, 2048 Bit).
Er ersetzt die Zieldatei erst nach erfolgreicher Erzeugung und Prüfung im selben
Verzeichnis, setzt öffentliche Dateirechte `0644` und bereinigt temporäre Dateien
bei Fehlern oder Abbruchsignalen. Das Startzeitlimit beträgt 600 Sekunden;
die originale Abhängigkeit des UDAPI-Dienstes bleibt bestehen. Im Build werden
keine DH-Parameter erzeugt.

Im Firmware-Update fehlen zudem die lokalen Snakeoil-TLS-Dateien, die das
Paket `ssl-cert` normalerweise bei seiner Einrichtung erstellt. Ohne sie
scheiterte die originale FreeRADIUS-Konfigurationsprüfung fortlaufend.
Eine separate Root-Unit erzeugt das Paar vor FreeRADIUS mit der Originalvorlage,
RSA mit 2048 Bit, SHA256 und 3650 Tagen Gültigkeit. Ein gültiges vorhandenes
Paar bleibt unverändert. Fehlt nur das Zertifikat, wird der vorhandene gültige
Schlüssel wiederverwendet. Nichtleere ungültige oder unpassende Dateien werden
erhalten und als Fehler gemeldet. Neue Dateien werden erst nach Prüfung
veröffentlicht; der Schlüssel erhält `0640` und `root:ssl-cert`, das öffentliche
Zertifikat `0644`. Das ist ein lokales selbstsigniertes Dienstzertifikat,
keine Herstelleridentität. Im Build werden keine privaten Schlüssel erzeugt.
Das serielle Protokoll des neuen Kaltstart-Pakettests bestätigt den erfolgreichen
Abschluss dieser Initialisierungs-Unit. Die Prüfung eines bereits vorhandenen
Paars und ein anschließend aktiver FreeRADIUS-Dienst wurden zusätzlich im
R3/R4-Forschungsgast beobachtet.

Nach dem ersten erfolgreichen Network-Start erreichte das System außerdem
einen zuvor noch nicht ausgeführten Boot-Hook: `01-phy-diag-wa` lädt
`phy_diag` für die physischen RJ45-PHYs. Dessen CN10K-Firmwareaufruf verursachte
in QEMU einen Kernelabsturz. Deshalb enthalten alle lokalen und Proxmox-
Startbefehle jetzt `module_blacklist=phy_diag`. Das virtuelle Profil verlangt
diese Sperre und ersetzt ausschließlich den anhand seines Hashes erkannten
Hook durch eine Meldung ohne Hardwarezugriff. Alle übrigen Boot-Hooks bleiben
erhalten. Im R3/R4-Forschungsgast wurden sowohl die verweigerte Modulladung mit
`modprobe --ignore-install phy_diag` als auch der fehlerfreie Ersatzhook
nachgewiesen. Vorhandene ältere VM-Konfigurationen benötigen ebenfalls den
neuen Kernelparameter; die aktualisierten Skripte ändern sie nicht nachträglich.

Die physische Geräteattestierung des UDAPI-Dienstes prüft außerdem
Manufacturing-Daten im EEPROM und blockiert bei Fehler `A12` auch
Konfigurationsänderungen. Dieser Fehler wurde über die originale API
nachgewiesen. Das virtuelle Profil deaktiviert deshalb ausdrücklich diesen
physischen Prüfpfad in der exakt bekannten Firmware. **Die VM besteht damit
keine Herstellerattestierung.** Es werden keine Herstellersignaturen oder
Zertifikate zur Geräteattestierung erzeugt; die Benutzeranmeldung wird durch diesen Patch nicht
geändert. Anschließend hat die originale Konfigurations-API die Testkonfiguration
akzeptiert; Einrichtung und Provisionierung über die Oberfläche sind noch offen.

Das bisherige reine Bootlabor bleibt über `--profile lab` verfügbar. Es ist
auch die Voreinstellung von `build.py` und `build.ps1`; für das virtuelle
Gateway daher immer ausdrücklich `virtual` wählen. Beim Laborprofil startet
der lokale Runner standardmäßig eine Shell mit zwei Karten, und der
Proxmox-Importer erwartet zwei bis 14 `--bridge NAME`-Angaben in Portreihenfolge.

**Firmware- und Anwendungsupdates nicht ungeprüft ausführen.** Die Anpassungen
sind hashgebunden und werden durch einen Build nicht automatisch auf andere
Versionen übertragen. Reguläre UDM-Updates erwarten zudem die originale
Partitionierung. Automatische Updates vor dauerhaftem Betrieb in den originalen
Einstellungen kontrollieren; kein Updateverfahren wurde für diese VM validiert.

Kernel, Initramfs und Manifest liegen auf Proxmox unter
`/var/lib/vz/snippets/udm-beast-VMID/`. Diese Dateien müssen separat von den
VM-Platten gesichert und vor einer Migration auf denselben Pfad des Zielknotens
kopiert werden. HA, Migration und Wiederherstellung sind noch nicht praktisch
geprüft.

Tests des Toolcodes:

```bash
python3 -m unittest discover -s tests -v
```

Aktueller Testlauf: unter [Linux](verification/tool-tests-linux.log) 209 Fälle,
davon 203 bestanden und sechs übersprungen; unter
[Windows](verification/tool-tests-windows.log) 209 Fälle, davon 141 bestanden
und 68 wegen Plattformvoraussetzungen übersprungen. Keine fehlgeschlagenen Fälle.

Die Proxmox-Tests simulieren `qm` und Storage-APIs; sie ersetzen keinen echten
Proxmox-Import. Firmware, VM-Abbilder und Arbeitsartefakte bleiben lokal und
sind durch `.gitignore` vom Quellcode getrennt.
