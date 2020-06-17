# Endgerätemonitoring

Für das detaillierte Monitoring von Endgeräten, welches über das Netzwerk alleine nicht abgebildet werden kann, ist das Security-Tool Wazuh in die BOX4security integriert. Dieses Tool greift über Clientbasierte Verbindungen direkt auf Hosts zu. Mit Wazuh kann folgendes realisiert werden:

* [Logsammlung](#logsammlung)
* [Monitoring der Änderung von Dateien](#monitoring-der-änderung-von-dateien)
* [Systeminventar](#systeminventar)
* [Schwachstellenanalyse](#schwachstellenanalyse)
* [Sicherheitsrichtlinien](#sicherheitsrichtlinien)
* [Reaktion auf Vorfälle (Incident Response)](#reaktion-auf-vorfälle-incident-response)

Wazuh funktioniert dabei technisch durch zwei Komponenten. Zum einen gibt es den wazuh-manager, welcher auf der BOX4security installiert ist. Dieser Manager übernimmt die zentrale Datenverwaltung. Des Weiteren gibt es noch die Clients. Auf diesen wird eine Software installiert, welche das Sammeln von Daten übernimmt. Diese gesammelten Daten werden sicher zum wazuh-manager übertragen und dort ausgewertet und visualisiert. Die Visualisierung wird mithilfe eines [Kibana Plugins](#wazuh-plugin-oberfläche) realisiert.

## Wazuh Plugin Oberfläche

In diesem Abschnitt wird die Oberfläche von Wazuh erläutert. Diese ist unter *SIEM->Endgeräte* zu erreichen. In dieser Dokumentation werden nur die wichtigsten Funktionen behandelt. Dieses Plugin ist der zentrale Ort für Wazuh. Es werden Sicherheitsinformationen der Clients sowie Alarme grafisch dargestellt. Des Weiteren ist auch das Management der Clients sowie der Wazuh Software über diesen Manager möglich.

### Overview

In diesem zentralen Tab können alle sicherheitsrelevanten Informationen abgerufen werden. Ein Filtern nach einer bestimmten Regel oder einem Client ist in allen Oberflächen möglich durch Klicken auf den Client beziehungsweise die Regel und Auswählen des '+' Symbols.

#### Security events

Hier sind die relevantesten Alarme aller Wazuh Endgeräte aufgeführt. Ein Alarm wird in Wazuh immer genau dann produziert, wenn eine zugehörige [Regel](#regeln) ausgelöst wird. Auf der oberen Hälfte des Fensters finden sich grafische Informationen zur Häufigkeit sowie der Verteilung der Alarme. Auf der unteren Seite findet sich eine detaillierte Zusammenfassung der Alarme. Dort kann der Schweregrad des Alarms, eine Beschreibung der gebrochenen Regel und die Häufigkeit des Alarms gesehen werden.

#### Integrity Monitoring

In Wazuh ist es möglich Dateien auf [Veränderung zu Überwachen](#monitoring-der-änderung-von-dateien). In diesem Fenster findet sich eine Übersicht dieser Informationen sowie zugehörige Alarme.

#### Policy Monitoring

Hier befindet sich eine Auswertung der [Sicherheitspolicies](#sicherheitspolicies). Damit hier Daten angezeigt werden muss mindestens ein Client entsprechend konfiguriert sein.

#### System Auditing

Die Auswertung der [Bewertung der Systemkonfiguration](#bewertung-der-systemkonfiguration) ist hier zu finden.

#### Vulnerabilities

Eine Übersicht der [Schwachstellen](#schwachstellenanalyse) auf den Endgeräten. Damit hier Daten angezeigt werden muss mindestens ein Client entsprechend konfiguriert sein.

#### Compliances

Wazuh beinhaltet ein vordefiniertes Regelwerk, um Endgeräte auf die Konformität mit verschiedenen Richtlinien zu prüfen. Für Deutschland beziehungsweise Europa ist die Datengrundschutzverordnung von hoher Bedeutung. Wazuh versucht durch dieses Modul dabei zu helfen die Datengrundschutzverordnung zu erfüllen sowie mögliche Verstöße zu erkennen. Durch verschiedene Komponenten von Wazuh wie beispielsweise das [Dateimonitoring](#monitoring-der-änderung-von-dateien) sammelt Wazuh Daten. Diese Daten werden vom wazuh-manager anhand von einem durch Wazuh gepflegten Regelwerk analysiert.

Die Ausgabe dieses Regelwerks kann über den Reiter GDPR erreicht werden. Dort werden oben auf der Seite die für die Clients zutreffenden Wazuh Regeln angezeigt. Diese können sich je nachdem welche Regeln erfüllt sind ändern. Wenn eine Regel angezeigt wird, dann bedeutet dies nicht automatisch, dass genau diese Anforderung der Datengrundschutzverordnung nicht erfüllt ist. Es ist lediglich ein Hinweis, dass Handlungsbedarf bestehen kann. So ist beispielsweise das Löschen einer Datei ein Kennzeichen für eine Regel der Datengrundschutzverordnung da die Forderung nach Verfügbarkeit von Daten durch das Löschen beeinträchtigt sein kann.

Ebenfalls gibt es seitens Wazuh eine englische detaillierte [Dokumentation](https://wazuh.com/resources/Wazuh_GDPR_White_Paper.pdf) zu der Funktion. In diesem Dokument wird ebenfalls die genaue Bedeutung der Regeln sowie die Zugehörigkeit der von Wazuh geschriebenen Regeln zu den Richtlinien der Datengrundschutzverordnung beschrieben.


### Management

Hier befinden sich die Tools, um das Regelwerk von Wazuh zu betrachten und Konfigurationen der Endgeräte anzupassen.

#### Ruleset

Hier können die Regeln von Wazuh gefunden werden. Es ist möglich Regeln zu betrachten, modifizieren und eigene Regeln hinzuzufügen. Eine genaue Beschreibung ist in [Regeln](#regeln) zu finden.

#### Groups

Auf Clients installierte Wazuh Software kann hier in Gruppen organisiert werden. Dabei kann die Konfiguration der Clients hier durchgeführt werden. Eine detaillierte Anleitung ist unter [Konfigurieren der Nutzer](#konfigurieren-der-nutzer) zu finden.


#### Configuration

Hier ist die Konfiguration des wazuh-managers auf der BOX4security möglich. Dies ist für einige Features notwendig und wird an diesen Stellen referenziert.

### Agents

Unter diesem Tab ist initial die Anleitung zur Installation eines Clients auf einem Endgerät zu finden. Die Installation wird auch unter [Clientbasierte Installation](#clientbasierte-installation) erklärt. Nachdem dies einmalig ausgeführt wurde, ist hier eine Übersicht der Clients mit Wazuh Software zu finden. Des Weiteren können individuelle Informationen über den ausgewählten Client wie das [Inventar](#systeminventar) oder die [Systembwertung](#bewertung-der-systemkonfiguration) hier gefunden werden. Diese Informationen sind über das individuelle Dashboard zu erreichen, welches durch Klicken auf den Namen eines Clients angezeigt wird.

---
## Installation von Wazuh

Wazuh selbst ist komplett fertig konfiguriert mit der Installation der BOX4security. Für die Kommunikation von Wazuh mit Clients ist es lediglich notwendig, dass die BOX4security mit Clients auf den folgenden Ports kommunizieren kann:

* `1514 TCP+UDP` - Datenaustausch zwischen wazuh-manager und Agenten
* `1515 TCP` - Registrierungen der Agenten

### Clientbasierte Installation

Das clientbasierte Monitoring erfordert die Installation eines eigenen Wazuh Clients sowie die Zuordnung dieses Clients zu dem passenden wazuh-manager, welcher auf der BOX4security installiert ist. Die Installation dieser Software ist typischerweise aus dem Internet durchzuführen. Die folgenden Blöcke enthalten die Kommandozeileneingaben, welche das Installieren sowie zuordnen des Clients zum wazuh-manager automatisch ausführen. Um Geräten im Netzwerk ohne Internetverbindung ebenfalls die Installation zu ermöglichen sind auf der BOX4security die notwendigen Installationsdateien hinterlegt.

Bei der Installation muss 'BOX_IP' durch die tatsächliche IP Ihrer BOX4security ersetzt werden.
#### Client aus dem Internet herunterladen

RedHat/CentOS: `sudo WAZUH_MANAGER='BOX_IP' yum install https://packages.wazuh.com/3.x/yum/wazuh-agent-3.12.1-1.x86_64.rpm`\
Debian/Ubuntu: `curl -so wazuh-agent.deb https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-agent/wazuh-agent_3.12.1-1_amd64.deb && sudo WAZUH_MANAGER='BOX_IP' dpkg -i ./wazuh-agent.deb`\
Windows: `Invoke-WebRequest -Uri https://packages.wazuh.com/3.x/windows/wazuh-agent-3.12.1-1.msi -OutFile wazuh-agent.msi; ./wazuh-agent.msi /q WAZUH_MANAGER='BOX_IP' WAZUH_REGISTRATION_SERVER='BOX_IP'`\
MacOS: `curl -so wazuh-agent.pkg https://packages.wazuh.com/3.x/osx/wazuh-agent-3.12.1-1.pkg && sudo launchctl setenv WAZUH_MANAGER 'BOX_IP' && sudo installer -pkg ./wazuh-agent.pkg -target /`


#### Client direkt von der BOX4security herunterladen

Unter Windows und RedHat/CentOS kann es sein, dass die Zertifikatsverifikation fehlschlägt. Unter Windows kann dies umgangen werden indem eine PowerShell geöffnet wird und folgender Befehl eingegeben wird:

```
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
Dies verändert jedoch das komplette Verhalten zur Zertifikatsverifikation und sollte nach der installation wieder auf `false` gesetzt werden.

Unter RedHat/CentOS muss in der yum Konfiguration unter `/etc/yum.conf` folgendes geändert werden:
```
sslverify=false
```
Diese Änderung ist ebenfalls für alle Pakete, welche mit yum installiert werden und sollte nach der installation auf `true` gesetzt werden.

RedHat/CentOS: `sudo WAZUH_MANAGER='BOX_IP' yum install https://BOX_IP/wazuh/redhat_centos-wazuh-agent.rpm`\
Debian/Ubuntu: `curl -k -so wazuh-agent.deb https://BOX_IP/wazuh/debian_ubuntu-wazuh-agent.deb && sudo WAZUH_MANAGER='BOX_IP' dpkg -i ./wazuh-agent.deb`\
Windows: `Invoke-WebRequest -Uri https://BOX_IP/wazuh/windows-wazuh-agent.msi -OutFile wazuh-agent.msi; ./wazuh-agent.msi /q WAZUH_MANAGER='BOX_IP' WAZUH_REGISTRATION_SERVER='BOX_IP'`\
MacOS: `curl -k -so wazuh-agent.pkg https://BOX_IP/wazuh/macos-wazuh-agent.pkg && sudo launchctl setenv WAZUH_MANAGER 'BOX_IP' && sudo installer -pkg ./wazuh-agent.pkg -target /`

---

### Konfigurieren der Nutzer

Standardmäßig sammeln Wazuh Clients nur eingeschränkte Datenmengen und nicht alle Module sind aktiviert. Eine Anpassung dieser Einstellungen muss über eine individuelle Konfiguration der Clients durchgeführt werden. Es gibt zwei verschiedene Möglichkeiten diese anzupassen. In dieser Dokumentation wird das Gruppenbasierte Konfigurieren detailliert behandelt. Alternativ ist das direkte Bearbeiten der Konfigurationsdatei `agent.conf` auf den Clients möglich. Diese Datei ist Standardmäßig unter folgenden Pfaden zu finden:\
Windows: `C:\Program Files (x86)\ossec-agent\ossec.conf`\
Linux: `/var/ossec/etc/ossec.conf`\
Der globale Tag dieser XML Konfiguration ist `<ossec_config>` und alle Konfigurationen müssen unter diesem Tag eingefügt werden.

Für alle Optionen bei den gruppenbasiertes Konfigurieren möglich ist, sollte es aufgrund der folgenden Eigenschaften verwendet werden:

* Identische Konfigurationen auf verschiedenen Systemen
* Schnelles anpassen der Konfiguration durch Gruppenwechsel
* Direktes ändern der Konfiguration im Wazuh Kibana Plugin
* Globales Regelwerk, welches lokale Vorkonfiguration von Wazuh erweitert und modifiziert


Die Oberfläche zum Konfigurationsmanagement ist unter *Endgeräte->Management->Groups* zu finden. Über das `+` Symbol neben der Überschrift `Groups` können neue Gruppen hinzugefügt werden. Die Konfiguration der neuen Gruppe kann anschließend unter der Tabellenspalte Actions und der neuen Gruppe bearbeitet werden. Das Bearbeiten einer bestehenden Gruppe kann unter *Endgeräte->Management->Groups->GRUPPENNAME->Content->Edit group configuration* durchgeführt werden.

 Alle XML Tags, welche zur Konfiguration notwendig sind und im Laufe dieses Dokuments erklärt werden unter dem `<agent_config>` Tag eingefügt werden. Ebenfalls ist es möglich in einer Gruppe Konfiguration für verschiedene Betriebssysteme vorzunehmen. Dies ist wie folgt im XML Dokument zu kennzeichnen:

 ```
 <agent_config os="Windows">
 ...
 <agent_config os=”Linux”>

 ```
Eine detaillierte Anleitung ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/centralized-configuration.html#options) zu finden.

Die Zugehörigkeit von Clients zu Gruppen ist per *Endgeräte->Management->Groups->GRUPPENNAME->Add or remove Agents* zu erreichen.

Eine Beispielkonfiguration für Windows und Linux kann ebenfalls in der Dokumentation gefunden werden.
---

## Logsammlung

Wazuh kann als Zentrale Stelle für das Sammeln von Logs einzelner Systeme verwendet werden. Dabei werden die Logs auf den Clients nur weitergeleitet und auf dem wazuh-manager analysiert. Die Auswertung der Logs wird mit individuellen Regeln durchgeführt und anhand dieser Regeln werden Alarme erstellt. Das Betrachten einzelner Logdateien ohne Filtern ist jedoch nicht möglich. Der XML Tag 'logfile' signalisiert, dass es sich um ein Log handelt. Es kann mehrere Tags in einer Konfiguration geben. Innerhalb dieses Tags wird über 'loglocation' der Speicherort und über 'logformat' das Format angegeben.

### Linux
Logs können mit folgendem XML Code gesammelt werden:

'''
<localfile>
<location>/var/log/messages</location>
<log_format>syslog</log_format>
</localfile>
'''

### Windows

Das Loggen von Ereignissen unter Windows wird über verschiedene 'eventlogs' realisiert. Eventlogs gibt es bei jeder Windows Version. Die gesammelten Informationen sind auf 'System', 'Application' und 'Security' limitiert. Diese Werte können bei 'loglocation' eingetragen werden:
'''
<localfile>
<location>Security</location>
<log_format>eventlog</log_format>
</localfile>
'''
Seit Windows Vista gibt es zusätzlich 'eventchannel'. Diese Loggmethode ist ausführlicher. Dabei kann ein Wert aus [dieser Tabelle](https://documentation.wazuh.com/3.12/user-manual/capabilities/log-data-collection/how-to-collect-wlogs.html#available-channels-and-providers) als 'logchannel' eingesetzt werden:
'''
<localfile>
<location>Microsoft-Windows-PrintService/Operational</location>
<log_format>eventchannel</log_format>
</localfile>
'''
Für das Sammeln weiterer Logs kann das Tool *Sysmon* verwendet werden. Eine genaue Anleitung zu Einrichtung ist in einem [Blogeintrag](https://wazuh.com/blog/how-to-collect-windows-events-with-wazuh/) von Wazuh zu finden.

Ebenfalls können konkrete Logdateien mit demselben Schema wie unter Linux gesammelt werden:
'''
<localfile>
<location>C:\myapp\example.log</location>
<log_format>syslog</log_format>
</localfile>
'''
### Remote Geräte

Um von Geräten ohne Clients Logs zu sammeln, kann Wazuh Logdateien über einen Benutzerdefinierten Port empfangen. Dafür muss in der wazuh-manager Konfiguration folgendes hinzugefügt werden:

'''
<ossec_config>
<remote>
<connection>syslog</connection>
<port>513</port>
<protocol>udp</protocol>
<allowed-ips>192.168.2.0/24</allowed-ips>
</remote>
</ossec_config>
'''
Diese Konfigurationsdatei vom wazuh-manager kann über *Endgeräte->Management->Configuration->Edit configuration* erreicht werden.

### Ausgabe von Befehlen überwachen

Es ist möglich die Ausgabe von Befehlen für die Kommandozeile zu überwachen. Dabei führt der Agent auf dem installierten System einen Befehl aus. Damit er dies tun kann, muss dies vorher spezifisch erlaubt werden. Dafür muss in der Datei `/var/ossec/etc/internal_options.conf` (Windows: `C:\Program Files (x86)\ossec-agent\internal_options.con`) folgendes gesetzt werden:

```
logcollector.remote_commands=1
```
Im Anschluss muss der wazuh-agent neu gestartet werden:

```
# echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
# systemctl restart wazuh-agent
```
Im Anschluss daran kann mit einem entsprechenden XML Block die Kommandozeilenausgabe eines Befehls überwacht werden. Die Frequenz gibt dabei die Abstände zwischen den Ausführungen in Sekunden an:

```
<localfile>
     <log_format>full_command</log_format>
     <command>lsblk</command>
     <frequency>120</frequency>
</localfile>
```

Eine Auswertung der Ausgabe des Befehls ist mithilfe von [Regeln](#regeln) möglich.


## Monitoring der Änderung von Dateien

Durch den Vergleich von kryptografischen Checksummen kann festgestellt werden, ob Dateien oder Ordner verändert wurden.

Die Dateiüberwachung kann über die [Gruppenkonfiguration](#konfigurieren-der-nutzer) eingestellt werdem. Pfade werden Standardmäßig in dem Block <directories> angegeben und per Komma getrennt. In dem XML Tag können dabei verschiedene Konfigurationen vorgenommen werden. Um verschiedene Optionen für unterschiedliche Pfade zu verwenden, können Pfade in verschiedenen XML Blöcken angegeben werden. Eine vollständige Liste der Optionen ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/syscheck.html#directories) zu finden. Die wichtigsten Konfigurationen sind:

| Beschreibung                                                                                                        | Code                   |
|---------------------------------------------------------------------------------------------------------------------|------------------------|
| Es werden zusätzlich neben Inhalt auch Metadaten überwacht (Besitzer, Größe, Änderungsdatum, etc.)                   | `check_all="yes"`      |
| Es wird die genaue Änderung an der Datei dokumentiert. Dieses Feature ist aktuell auf Textdateien limitiert         | `report_changes="yes"` |
| Änderungen werden in Echtzeit überwacht. Dieses Feature ist auf Ordner limitiert und funktioniert nicht bei Dateien | `realtime="yes"`       |                                                                                         

Beispiel dieser Optionen:
```
<syscheck>
  <directories>/usr/bin,/usr/sbin</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc</directories>
</syscheck>
```
Zusätzlich können über weitere XML Tags innerhalb des `<syscheck>` Tags Einstellungen vorgenommen werden. Eine genaue Beschreibung ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/syscheck.html#disabled) zu finden. Die wichtigsten Einstellungen dabei sind:

| Beschreibung                                                          | XML code             | Beispiel                                                                           |
|-----------------------------------------------------------------------|----------------------|------------------------------------------------------------------------------------|
| Wie oft der Check auf veränderung durchgeführt wird (in sekunden)     | `<frequency>`        | `<frequency>36000</frequency>`                                                     |
| Zu welcher Uhrzeit auf Veränderung geprüft wird                       | `<scan_time>`        | `<scan_time>10pm</scan_time>`                                                      |
| An welchen Tagen auf Veränderung geprüft wird                         | `<scan_day>`         | `<scan_day>saturday</scan_day>`                                                    |
| Beim anlegen von neuen Dateien wird ein Alert gesendet                              | `<alert_new_files>`  | `<alert_new_files>yes</alert_new_files>`                                           |
| Ordner/Dateien, welche ignoriert werden sollen. Ein Eintrag pro Zeile | `<ignore>`           | `<ignore>/root/dir</ignore>`                                                       |
| Einträge in der Windows Registry die überwacht werden sollen          | `<windows_registry>` | `<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>` |
| Einträge in der Windows Registry die nicht überwacht werden sollen    | `<registry_ignore>`  | `<registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>`    |

Beispielkonfiguration:
```
<syscheck>
  <alert_new_files>yes</alert_new_files>
  <scan_time>10pm</scan_time>
  <scan_day>saturday</scan_day>
  <ignore>/root/dir</ignore>
  <ignore>/etc/passwd</ignore>
  <directories>/usr/bin,/usr/sbin</directories>
  <directories report_changes="yes">/var/log</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc</directories>
</syscheck>
```


## Systeminventar

Dieses Modul kann über den Client detaillierte Informationen sammeln. Welche Informationen genau abgerufen werden können und Beispielwerte können der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/capabilities/syscollector.html#available-scans) entnommen werden. Dieses Feature ist per default aktiviert und erfodert keine Konfiguration. Das Modul kann nur über die lokale Konfigurationsdatei verändert werden. In [Konfigurieren der Nutzer](#konfigurieren-der-nutzer) ist eine passende Anleitung zu finden. In der lokalen Datei kann folgende XML Struktur bearbeitet werden:

```
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
</wodle>
```

Die Option bei Ports sorgt dafür, dass nur offene Ports überwacht werden. Die Werte können individuell deaktiviert und aktiviert werden. Eine detaillierte Auflistung der Konfigurationsmöglichkeiten ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.9/user-manual/reference/ossec-conf/wodle-syscollector.html) zu finden.

## Schwachstellenanalyse

Bekannte Schwachstellen (CVEs) von installierten Programmen können vom Client an den wazuh-manager gemeldet werden. Die Quelle der CVEs ist unterschiedlich je nach Betriebssystem und kann [hier](https://documentation.wazuh.com/3.12/user-manual/capabilities/vulnerability-detection/compatibility_matrix.html) gefunden werden. Bevor eine Schwachstellenanalyse durchgeführt werden kann, muss [Systeminventar](#systeminventar) aktiviert sein. Dies ist jedoch Standardmäßig aktiviert. Dadurch senden die Clients das Systeminventar an den wazuh-manager. Dieser speichert die Daten lokal und analysiert Sie auf Schwachstellen. Daher muss das Modul in der Konfigurationsdatei des wazuh-managers aktiviert werden. Diese Konfigurationsdatei kann über *Endgeräte->Management->Configuration->Edit configuration* erreicht werden. Dort muss der folgende XML Block unter `<ossec_config>` eingefügt werden:

```
<vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>

    <provider name="canonical">
        <enabled>yes</enabled>
        <os>trusty</os>
        <os>xenial</os>
        <os>bionic</os>
        <update_interval>1h</update_interval>
    </provider>

    <provider name="debian">
        <enabled>yes</enabled>
        <os>wheezy</os>
        <os>stretch</os>
        <os>jessie</os>
        <os>buster</os>
        <update_interval>1h</update_interval>
    </provider>

    <provider name="redhat">
        <enabled>yes</enabled>
        <update_from_year>2010</update_from_year>
        <update_interval>1h</update_interval>
    </provider>

    <provider name="nvd">
        <enabled>yes</enabled>
        <update_from_year>2010</update_from_year>
        <update_interval>1h</update_interval>
    </provider>

</vulnerability-detector>
```

Die Option `ignore_time` bestimmt dabei wie lange gefundene Schwachstellen nicht doppelt gemeldet werden und `interval` ist der Abstand zwischen Scans. Eine detaillierte Auflistung der Konfigurationsmöglichkeiten ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/vuln-detector.html) zu finden.



## Sicherheitsrichtlinien


### Bewertung der Systemkonfiguration

Ein System zu sichern bedeutet oftmals auch die Angriffsvektoren zu minimieren. Genau dies kann mit dem Feature Security Configuration Assessment (SCA) realisiert werden. Auf den Clients werden durch die Wazuh Software Scans durchgeführt. Diese scans werden anhand von vordefinierten Richtlinien untersucht und es wird ein Resultat für den Scan ausgegeben. Dabei kann der Scan 'passed', 'failed' oder 'not applicable' sein, je nachdem welche Anforderungen erfüllt bzw. nicht erfüllt sind. Dieses Feature ist per default aktiviert und erfordert keine Konfiguration.

Die Ansicht zu diesem Feature kann unter *Endgeräte->Agents->AGENT->Security configuration assessment* gefunden werden.

Es ist ebenfalls möglich eigene Regeln für die Systemkonfiguration zu erstellen. Dies kann [hier](https://documentation.wazuh.com/3.12/user-manual/capabilities/sec-config-assessment/creating_custom_policies.html) nachgelesen werden.

### Sicherheitspolicies

Die Sicherstellung, dass Clients zu vorgegeben Sicherheitsrichtlinien konform sind realisiert Wazuh durch separate Dienste.

#### OpenSCAP

Dies ist eine direkte Anbindung von [OpenSCAP](https://www.open-scap.org/) an Wazuh. OpenSCAP ermöglicht Systeme auf Compliance, Schwachstellen und spezielle Anforderungen zu untersuchen. Dieses Tool muss auf dem Client neben dem Wazuh Client separiert installiert werden.

RPM-Distributionen:
```
yum install openscap-scanner
```
Debian-Distributionen:
```
apt-get install libopenscap8 xsltproc
```

Wazuh bietet für [gänge Linux Distributionen](https://documentation.wazuh.com/3.12/user-manual/capabilities/policy-monitoring/openscap/how-it-works.html#default-policies) vordefinierte policies an.

Damit der Wazuh Client mit OpenSCAP kommuniziert muss in der Konfiguration für diesen Client noch folgendes ergänzt werden:

```
<wodle name="open-scap">
  <timeout>1800</timeout>
  <interval>1d</interval>
  <scan-on-start>yes</scan-on-start>
  <content type="xccdf" path="/var/ossec/wodles/oscap/content"/>
</wodle>
```
Dabei können `content type` sowie `path` durch passende Werte aus der [Tabelle](https://documentation.wazuh.com/3.12/user-manual/capabilities/policy-monitoring/openscap/how-it-works.html#default-policies) ersetzt werden. Die Standardmäßigen Werte sind jedoch in den meisten Situationen passend. Weitere Informationen über die Konfigurationen sind [hier](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/wodle-openscap.html#wodle-openscap) nachzulesen.
#### CIS-CAT

Center for Internet Security (CIS) ist eine Organisation zur Bekämpfung von Cyber-Bedrohungen. CIS-CAT gibt es in verschiedenen Versionen. Diese Integration zu nutzen erfordert CIS-CAT Pro. Diese muss käuflich [auf der offiziellen Wesbite](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/) erworben werden. Eine Anleitung zur anschließenden Installation findet sich [hier](https://documentation.wazuh.com/3.12/user-manual/capabilities/policy-monitoring/ciscat/ciscat.html).

## Reaktion auf Vorfälle (Incident Response)

Aktives reagieren aufgrund bestimmter Faktoren realisiert Wazuh durch das Ausführen von vordefinierten Skripten auf dem betroffenen System. Dabei wird der Auslöser vom wazuh-manager gefunden. Dieser sendet anschließend an den Client die Aufforderung ein Skript auszuführen. Technisch besteht dieser Vorgang aus zwei Teilen. Es gibt ein Kommando, welches ein konkretes Skript oder einen Befehl zum Ausführen beinhaltet. Dieser Teil agiert direkt auf dem Client. Zum Auslösen dieses Kommandos gibt es noch einen Reaktionsteil. Dieser beinhaltet die konkrete Regel zu Auslösung sowie den Ort der Ausführung. Es ist beispielsweise möglich ein Kommando direkt auf dem Agenten laufen zu lassen, welcher dieses Event auslöste, aber auch auf allen Geräten mit einem Wazuh Client.

Für den ersten Teil muss ein `<command>` XML Tag verwendet werden. Eine genaue Anleitung dafür ist [hier](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/commands.html#reference-ossec-commands) nachzulesen. Eine Beispielkonfiguration kann so aussehen:

```
<command>
  <name>password_reveal</name>
  <executable>reveal.sh</executable>
  <extra_args>cat /etc/passwd</extra_args>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

Der zweite Teil erfordert das definieren von mindestens einem `active-response` XML Tag. Die genaue Bedeuetung der Felder ist [hier](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/active-response.html) zu finden. Die `active-response` kann dabei sowohl in der Konfiguration vom Client (über Gruppen) oder in der Manager Konfiguration definiert werden. Empfohlen ist jedoch dies in der Manager Konfiguration durchzuführen, da so direkt für alle Agenten ein `active-response` definiert werden kann. Ein Beispiel kann dabei so aussehen:

```
<active-response>
    <command>password_reveal</command>
    <location>local</location>
    <rules_id>1000</rules_id>
 </active-response>
```
Wazuh bietet einige bereits [vordefinierte Skripte](https://documentation.wazuh.com/3.12/user-manual/capabilities/active-response/how-it-works.html#default-active-response-scripts) an.

----

## Regeln

Regeln sind in Wazuh das Zentrale Werkzeug zur Bewertung eines Ereignisses. Regeln werden dabei in verschiedene Schweregrade eingeteilt ([0 bis 16](https://documentation.wazuh.com/3.12/user-manual/ruleset/rules-classification.html)). Anhand von Verstößen gegen diesen vordefinierten Regeln werden Alarme generiert und visualisiert. Wazuh bietet eine Vielzahl von [vordefinierten Regelkategorien](https://www.wazuh.com/resources/Wazuh_Ruleset.pdf) an.

Regeln sind in den meisten Fällen dadurch definiert, dass ein spezifizierter Wert in einer Datei gefunden wird. Damit spezielle Dateitypen wie JSON, welcher oftmals für Logdateien verwendet wird, auch sinnvoll interpretiert werden können gibt es [Decoder](https://documentation.wazuh.com/3.9/user-manual/ruleset/ruleset-xml-syntax/decoders.html). Alternativ zu diesen Decodern kann man auch mit RegEx Ausdrücken Dateien untersuchen.

Das Erstellen von Regeln sowie das Anpassen von bereits vorhandenen Regeln ist [in dieser Dokumentation](https://documentation.wazuh.com/3.12/user-manual/ruleset/custom.html) genau beschrieben.
