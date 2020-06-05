# Endgerätemonitoring

Für das detaillierte Monitoring von Endgeräten, welches über das Netzwerk alleine nicht abgebildet werden kann, ist das Security-Tool Wazuh in die Box4Security integriert. Dieses Tool greift über Clientbasierte und Clientlose Verbindungen direkt auf Hosts zu. Mit Wazuh kann folgendes realisiert werden:

* [Logsammlung](#logsammlung)
* [Systeminventar](#systeminventar)
* [Schwachstellenanalyse](#schwachstellenanalyse)
* [Intrusion Detection](#intrusion-detection)
* [Monitoring der Änderung von Dateien (File Integrity)](#-monitoring-der-änderung-von-dateien-(file-integrity))
* [Bewertung der Systemkonfiguration](#bewertung-der-systemkonfiguration)
* [Reaktion auf Vorfälle (Incident Response)](#reaktion-auf-vorfälle-(incident-response))
* [Compliance Monitoring](#compliance-monitoring)

---
## Installation von Wazuh

- Port öffnen auf Firewall

#### Clientlose Installation

Monitoring von Geräten ohne einen Client zu installieren ist über eine SSH Verbindung möglich. Damit können Geräte, wie beispielsweise Router oder Switches überwacht werden.

`TODO: erfordert zugriff auf commandline des wazuh-managers`

Der folgende Aufruf auf der Commandline erlaubt das Hinzufügen eines Clients. Bei Cisco Geräten sollte die Option `[enablepass]` zusätzlich verwendet werden.\
`/var/ossec/agentless/register_host.sh add root@example_address.com example_password [enablepass]`

Da es bei einer Clientlosen Installation keine lokale Konfigurationsdatei gibt, wird die Überwachung in einer Datei im Wazuh-manager eingestellt. Diese Konfigurationsdatei kann über *Endgeräte->Management->Configuration->Edit configuration* erreicht werden. Dort muss der folgende XML Block unter `<ossec_config>` eingefügt werden:

```
<type>ssh_integrity_check_linux</type>
<frequency>300</frequency>
<host>name@adress</host>
<state>periodic</state>
<arguments>/bin /etc/ /sbin</arguments>
```

Die Bedeutung der verschiedenen Felder sowie Beispielkonfigurationen kann [der offiziellen Dokumenation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/agentless.html#reference-ossec-agentless) entnommen werden.

Die englische Dokumentation kann [hier](https://documentation.wazuh.com/3.12/user-manual/capabilities/agentless-monitoring/how-it-works.html) nachgelesen werden.

#### Clientbasierte Installation

Das Clientbasierte monitoring erfordert die Installation eines eigenen Wazuh Clients sowie die Zuordnung dieses Clients zu dem passenden Wazuh-manager, welcher auf der Box4Security installiert ist. Die Installation dieser Software ist typischerweise aus dem Internet durchzuführen. Um Geräten im Netzwerk ohne Internetverbindung ebenfalls die Installation zu ermöglichen sind auf der Box4Security die notwendigen Installationsdateien hinterlegt.

Bei der Installation muss `BOX_IP` durch die tatsächliche IP Ihrer Box4Security ersetzt werden.
##### Client aus dem Internet herunterladen

RedHat/CentOS: sudo `WAZUH_MANAGER='BOX_IP' yum install https://packages.wazuh.com/3.x/yum/wazuh-agent-3.12.1-1.x86_64.rpm`\
Debian/Ubuntu: `curl -so wazuh-agent.deb https://packages.wazuh.com/3.x/apt/pool/main/w/wazuh-agent/wazuh-agent_3.12.1-1_amd64.deb && sudo WAZUH_MANAGER='BOX_IP' dpkg -i ./wazuh-agent.deb`\
Windows: `Invoke-WebRequest -Uri https://packages.wazuh.com/3.x/windows/wazuh-agent-3.12.1-1.msi -OutFile wazuh-agent.msi; ./wazuh-agent.msi /q WAZUH_MANAGER='BOX_IP' WAZUH_REGISTRATION_SERVER='BOX_IP'`\
MacOS: `curl -so wazuh-agent.pkg https://packages.wazuh.com/3.x/osx/wazuh-agent-3.12.1-1.pkg && sudo launchctl setenv WAZUH_MANAGER 'BOX_IP' && sudo installer -pkg ./wazuh-agent.pkg -target /`


##### Client direkt von der Box4Security herunterladen

`TODO: URLs zum herunterladen angeben; `
---

## Konfigurieren der Nutzer

Standardmäßig sammeln Wazuh Clients nur eingeschränkte Datenmengen und nicht alle Module sind aktiviert. Diese Anpassung muss über eine individuelle Konfiguration der Clients durchgeführt werden. Die Konfigurationsdateien sind dabei auf dem Client gespeichert. Es gibt zwei verschiedene Möglichkeiten diese anzupassen. In dieser Dokumentation wird nur das Gruppenbasierte Konfigurieren behandelt. Alternativ ist das direkte Bearbeiten der Konfigurationsdatei `agent.conf` auf den Clientgeräten möglich. Diese Datei ist Standardmäßig unter folgenden Pfaden zu finden:\
Windows: `C:\Program Files (x86)\ossec-agent\ossec.conf`\
Linux: `/var/ossec/etc/ossec.conf`\
Der globale Tag dieser lokalen Konfiguration ist `<ossec_config>` und alle Konfigurationen müssen unter diesem Tag vorgenommen werden.

Für alle Optionen bei den Gruppenbasiertes Konfigurieren möglich ist, sollte es aufgrund der folgenden Eigenschaften verwendet werden:

* Identische Konfigurationen auf verschiedenen Systemen
* Schnelles ändern der Konfiguration durch Gruppenwechsel
* Direktes ändern der Konfiguration im Wazuh Kibana Plugin
* Globales Regelnwerk, weldches lokale Konfigurationen "überschreibt"


Die Oberfläche zum Konfigurationsmanagement ist unter *Endgeräte->Management->Groups* zu finden. Über das `+` Symbol neben der Überschrift `Groups` können neue Gruppen hinzugefügt werden. Die Konfiguration der neuen Gruppe kann anschließend unter der Tabellenspalte Actions und der neuen Gruppe bearbeitet werden. Das Bearbeiten einer bestehenden Gruppe kann unter *Endgeräte->Management->Groups->GRUPPENNAME->Content->Edit group configuration* durchgeführt werden.

 Alle XML Tags, welche zur Konfiguration notwendig sind und im Laufe dieses Dokuments erklärt werden unter der `<agent_config>` Ebene eingefügt werden.

Die Zugehörigkeit von Clients zu Gruppen ist per *Endgeräte->Management->Groups->GRUPPENNAME->Add or remove Agents* zu erreichen.


`TODO: Beispielconfigs erstellen und hochladen`
---
## Logsammlung

Wazuh kann als Zentrale für das Sammeln von Logs einzelner Systeme verwendet werden. Dabei werden die Logs auf den Clients nur weitergeleitet und auf dem wazuh-manager analysiert. Die Auswertung der Logs wird mit individuellen Regeln durchgeführt und anhand dieser Regeln werden Alarme erstellt. Der XML Tag `logfile` signalisiert, dass es sich um ein Log handelt. Es kann mehrere Tags in einer Konfiguration geben. Innerhalb dieses Tags wird über `loglocation` der Speicherort und über `logformat` das Format angegeben.


### Linux
Logs können mit folgendem XML Code gesammelt werden:

```
<localfile>
  <location>/var/log/messages</location>
  <log_format>syslog</log_format>
</localfile>
```

### Windows

Das Loggen von Ereignissen unter Windows wird über verschiedene `eventlogs` realisiert. Eventlogs gibt es bei jeder Windows Version. Die gesammelten Informationen werden auf `System`, `Application` und `Security` limitiert. Diese Werte können bei `loglocation` eingetragen werden:
```
<localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
</localfile>
```
Seit Windows Vista gibt es zusätzlich `eventchannel`. Diese Logginmethode ist ausführlicher. Dabei kann ein Wert aus [dieser Tabelle](https://documentation.wazuh.com/3.12/user-manual/capabilities/log-data-collection/how-to-collect-wlogs.html#available-channels-and-providers) als `logchannel` eingesetzt werden:
```
<localfile>
    <location>Microsoft-Windows-PrintService/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```
Für das Sammeln weiterer Logs kann das Tool *Sysmon* verwendet werden. Eine genaue Anleitung zu Einreichtung ist in einem [Blogeintrag](https://wazuh.com/blog/how-to-collect-windows-events-with-wazuh/) von Wazuh zu finden.


Ebenfalls können konkrete Logdateien mit demselben Schema wie unter Linux gesammelt werden:
```
<localfile>
  <location>C:\myapp\example.log</location>
  <log_format>syslog</log_format>
</localfile>
```
### Remote Geräte

Um von Geräten ohne Clients Logs zu sammeln, kann Wazuh Logdateien über einen Benutzerdefinierten Port empfangen. Dafür muss in der wazuh-manager Konfiguration folgendes hinzugefügt werden:

```
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>513</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.2.0/24</allowed-ips>
  </remote>
</ossec_config>
```
Wie dies durchgeführt wird ist [hier](#clientlose-installation) nachzulesen.

### Ausgabe von Befehlen überwachen

Es ist möglich die Ausgabe von commandline Befehlen zu überwachen. Dabei führt der Agent auf dem installierten System ein command aus. Damit er dies tun kann, muss dies vorher spezifisch erlaubt werden. Dafür muss in der Datei `/var/ossec/etc/internal_options.conf` (Windows: `C:\Program Files (x86)\ossec-agent\internal_options.con`) folgendes gesetzt werden:

```
logcollector.remote_commands=1
```
Im Anschluss muss der wazuh-agent neu gestartet werden:

```
# echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
# systemctl restart wazuh-agent
```
Im Anschluss daran kann mit einem entsprechenden XML Block die commandline Ausgabe eines Kommandos überwacht werden. Die Frequenz gibt dabei die Abstände zwischen den Ausführungen in Sekunden an:

```
<localfile>
     <log_format>full_command</log_format>
     <command>lsblk</command>
     <frequency>120</frequency>
</localfile>
```

Eine Auswertung der Ausgabe der Kommandos ist mithilfe von [Regeln](#regeln) möglich.

## Systeminventar

Dieses Modul kann über den Client detaillierte Informationen sammeln. Welche Informationen genau abgerufen werden können und Beispielwerte können der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/capabilities/syscollector.html#available-scans) entnommen werden. Das Modul kann nur über die lokale Konfigurationsdatei aktiviert werden. In [Konfigurieren der Nutzer](#konfigurieren-der-nutzer) ist eine passende Anleitung zu finden. In der lokalen Datei ist folgende XML Struktur hinzuzufügen:

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

Bekannte Schwachstellen (CVEs) von installierten Programmen können an den wazuh-manager weitergeleitet werden. Die Quelle der CVEs ist unterschiedlich je nach Betriebssystem und kann [hier](https://documentation.wazuh.com/3.12/user-manual/capabilities/vulnerability-detection/compatibility_matrix.html) gefunden werden. Bevor eine Schwachstellenanalyse durchgeführt werden kann, muss [Systeminventar](#systeminventar) eingerichtet und aktiviert werden. Dadurch senden die Clients das Systeminventar and den wazuh-manager. Dieser speichert die Daten lokal und analysiert Sie auf Schwachstellen. Daher muss das Modul in der Konfigurationsdatei des wazuh-managers aktiviert werden. Diese Konfigurationsdatei kann über *Endgeräte->Management->Configuration->Edit configuration* erreicht werden. Dort muss der folgende XML Block unter `<ossec_config>` eingefügt werden:

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

Die Option `ignore_time` bestimmt dabei wie lange gefundene Schwachstellen nicht doppelt reported werden und `interval` ist der Abstand zwischen Schwachstellenscans. Eine detaillierte Auflistung der Konfigurationsmöglichkeiten ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/vuln-detector.html) zu finden.

## Intrusion Detection

## Monitoring der Änderung von Dateien (File Integrity)

Durch den Vergleich von kryptographischen Checksummen kann festgestellt werden, wann Dateien verändert werden.

Die Dateiüberwachung wird über die [Gruppenkonfiguration](#konfigurieren-der-nutzer) eingestellt. Pfade werden Standardmäßig in dem Block <directories> angegeben und per Komma getrennt. In dem XML Tag können dabei verschiedene Konfigurationen vorgenommen werden. Um verschiedene Optionen für unterschiedliche Pfade zu verwenden können Pfade in verschiedenen XML Blöcken angegeben werden. Eine vollständige Liste der Optionen ist in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/syscheck.html#directories) zu finden. Die wichtigsten Konfigurationen sind:

| Beschreibung                                                                                                        | Code                   |
|---------------------------------------------------------------------------------------------------------------------|------------------------|
| Es werden zusätzlich neben Inhalt auch Metadaten überwacht(Besitzer, Größe, Änderungsdatum, etc.)                   | `check_all="yes"`      |
| Es wird die genaue Änderung an der Datei dokumentiert. Dieses Feature ist aktuell auf Textdateien limitiert         | `report_changes="yes"` |
| Änderungen werden in Echtzeit überwacht. Dieses Feature ist auf Ordner limitiert und funktioniert nicht bei Dateien | `realtime="yes"`       |                                                                                         

Beispiel dieser Optionen:
```
<syscheck>
  <directories>/usr/bin,/usr/sbin</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc</directories>
</syscheck>
```
Zusätzlich können über weitere XML Tags innerhalb des `<syscheck>` Tags Einstellungen vorgenommen werden. Eine genaue Beschreibung ist in der in der [Wazuh Dokumentation](https://documentation.wazuh.com/3.12/user-manual/reference/ossec-conf/syscheck.html#disabled) zu finden. Die wichtigsten Einstellungen dabei sind:

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

## Bewertung der Systemkonfiguration

## Reaktion auf Vorfälle (Incident Response)

## Compliance Monitoring


----

## Regeln
