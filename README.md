# atv-vpn-switch

Image: `ghcr.io/marc0902/atv-vpn-switch:latest` (linux/arm64, linux/amd64)

Docker-Container für den Raspberry Pi (arm64, auch amd64). Über eine Webseite schaltest du um, ob **ein einzelnes Gerät** (z. B. ein Apple TV) normal oder über einen **Mullvad-WireGuard-Tunnel nach Albanien** ins Internet geht. Damit läuft YouTube auf dem Apple TV mit albanischer IP, also ohne Werbung.

Alle anderen Geräte im Heimnetz, der Pi selbst und AdGuard Home bleiben unberührt.

## 1. Funktionsweise

```
                       Modus "Deutschland" (Standard)
 ┌──────────┐  Router=Pi  ┌──────────────────────┐  NAT (eth0)  ┌──────────┐
 │ Apple TV │ ──────────► │  Raspberry Pi        │ ───────────► │ Fritzbox │ ──► Internet (DE)
 │ ATV_IP   │             │  atv-vpn-switch      │              └──────────┘
 └──────────┘             │  (network_mode:host) │
                          │                      │  wg-atv      ┌──────────┐
                          │                      │ ═══════════► │ Mullvad  │ ──► Internet (AL)
                          └──────────────────────┘  (Tunnel)    │ Tirana   │
                       Modus "Albanien"                         └──────────┘
```

- Am Apple TV ist der **Pi als Router** eingetragen. Der Pi leitet den Verkehr weiter und maskiert ihn (NAT), damit die Antworten wieder über den Pi zurückkommen.
- **Deutschland:** Der Verkehr geht über die normale LAN-Schnittstelle zur Fritzbox.
- **Albanien:** Die Policy-Routing-Regel `from ATV_IP lookup 51820` (Priorität 200) schickt den Verkehr in die Tunnel-Tabelle und damit durch WireGuard. Diese Regel ist der eigentliche Schalter.
- **Immer am Tunnel vorbei:** Ziele im Heimnetz (`LAN_CIDR`, Priorität 100) und Docker-Netze `172.16.0.0/12` (Priorität 101). Dadurch funktioniert DNS auch mit einem AdGuard-Container im Bridge-Netzwerk.
- **Kill-Switch:** In der Tunnel-Tabelle steht zusätzlich `blackhole default metric 1000`. Fällt der Tunnel aus, wird der Verkehr verworfen, statt mit deutscher IP rauszugehen.
- **Nach jedem Start ist „Deutschland“ aktiv.** Der zuletzt gewählte Server wird in `config/state.json` gespeichert, der Modus nicht.
- Beim Beenden (SIGTERM/SIGINT) werden alle Regeln, Routen, iptables-Einträge und die WireGuard-Schnittstelle entfernt. Beim Start werden eventuelle Altlasten vorher gelöscht.
- Docker setzt die FORWARD-Policy auf DROP. Deshalb trägt der Container Regeln in `DOCKER-USER` ein. Das iptables-Backend (nft oder legacy) erkennt er automatisch.
- Der Pi schickt dem Apple TV keine ICMP-Redirects. Sonst würde das Apple TV direkt die Fritzbox nutzen.

## 2. Mullvad-Konfiguration erzeugen

1. Bei Mullvad anmelden → **WireGuard-Konfigurationsgenerator** (`mullvad.net/de/account/wireguard-config`).
2. Plattform **Linux**, Schlüssel erzeugen bzw. auswählen.
3. Land **Albanien**, Stadt **Tirana**, **alle Server** wählen.
4. Als **ZIP** herunterladen. Darin liegen Dateien wie `al-tia-wg-001.conf` bis `al-tia-wg-004.conf`.
5. Server einspielen, auf eine von zwei Arten:
   - **Weboberfläche:** Bereich „Server hinzufügen“ → ZIP auswählen → *Hochladen*. Einzelne `.conf`-Dateien gehen genauso. Alternativ den Inhalt einer `.conf` einfügen.
   - **Per SSH:** die `.conf`-Dateien in den Ordner `servers/` legen, z. B. `/home/<benutzer>/atv-vpn/config/servers/`, danach *Neu einlesen* klicken (oder die Seite neu laden).

Danach kannst du in der Oberfläche jederzeit mit *Verwenden* den Server wechseln oder Dateien bearbeiten. Ein Neubau des Images ist nie nötig. Gelesen werden nur `PrivateKey`, `Address` (IPv4), `PublicKey` und `Endpoint`. `DNS`, `AllowedIPs` und IPv6 werden bewusst ignoriert. Fehlerhafte Dateien erscheinen in der Liste als „fehlerhaft“. Hochgeladene Dateien bekommen die Rechte `600`, der Private Key wird nie im Klartext angezeigt.

> Die `.conf`-Dateien enthalten deinen privaten Schlüssel und gehören **nie** in ein Git-Repository.

## 3. Stack in Portainer anlegen

Vorher auf dem Pi den Konfigurationsordner anlegen:

```bash
mkdir -p /home/<benutzer>/atv-vpn/config/servers
```

**Variante A, Web-Editor:** *Portainer → Stacks → Add stack → Web editor*. Den Inhalt von [`docker-compose.yml`](docker-compose.yml) einfügen.

**Variante B, Repository:** *Portainer → Stacks → Add stack → Repository*, URL dieses Repos, Compose-Pfad `docker-compose.yml`.

Dann unter **Environment variables** die Werte eintragen (Vorlage: [`stack.env.example`](stack.env.example)):

| Variable | Pflicht | Standard | Bedeutung |
|---|---|---|---|
| `ATV_IP` | ja | – | feste IPv4 des Apple TV |
| `LAN_CIDR` | | `192.168.178.0/24` | Heimnetz |
| `LAN_IF` | | automatisch | LAN-Schnittstelle des Pi, z. B. `eth0` |
| `CONFIG_PATH` | | `/home/pi/atv-vpn/config` | Ordner auf dem Pi für `/config` |
| `WEB_PORT` | | `8099` | Port der Weboberfläche |
| `WEB_PASSWORD` | | leer | Passwort (Basic Auth, Benutzername beliebig) |
| `KILLSWITCH` | | `true` | Kill-Switch im Modus Albanien |
| `AUTO_RESET_TIME` | | `03:00` | tägliches Zurücksetzen, leer = aus |
| `TZ` | | `Europe/Berlin` | Zeitzone |
| `AUTO_FAILOVER` | | `false` | Serverwechsel bei > 3 min ohne Handshake |
| `WG_TABLE` | | `51820` | Routingtabelle |
| `WG_PRIVATE_KEY`, `WG_ADDRESS`, `WG_PEER_PUBLIC_KEY`, `WG_ENDPOINT` | | leer | Fallback, solange in `servers/` keine `.conf` liegt |

Das Passwort gehört nur in die Portainer-Variablen, nicht in die `docker-compose.yml`. Sonderzeichen wie `!` sind dort unproblematisch. Nur ein `$` müsste als `$$` geschrieben werden.

Der Container braucht `network_mode: host` und `NET_ADMIN`/`NET_RAW`, aber kein `privileged`. Auf dem Host muss `net.ipv4.ip_forward = 1` sein. Docker setzt das normalerweise schon. Andernfalls bricht der Container mit einer klaren Meldung ab.

## 4. Fritzbox

*Heimnetz → Netzwerk → Netzwerkverbindungen →* Apple TV bearbeiten → **„Diesem Netzwerkgerät immer die gleiche IPv4-Adresse zuweisen“** aktivieren. Diese Adresse ist `ATV_IP`.

## 5. Apple TV

*Einstellungen → Netzwerk →* (LAN/WLAN) → **IP konfigurieren: Manuell**

- IP-Adresse: `ATV_IP`
- Teilnetzmaske: `255.255.255.0`
- Router: **IP des Pi**
- DNS: **manuell**, IP der Fritzbox oder des Pi (AdGuard)

## 6. AdGuard Home: IPv6 für das Apple TV unterbinden

Das Apple TV holt sich per Router Advertisement eine IPv6-Adresse von der Fritzbox. YouTube würde dann über IPv6 **direkt an der Fritzbox vorbei mit deutscher IP** laufen. Deshalb in AdGuard Home keine AAAA-Antworten an das Apple TV ausliefern:

*Filter → Benutzerdefinierte Filterregeln:*

```
/.*/$dnstype=AAAA,client=<ATV_IP>
```

Alternativ global: *Einstellungen → DNS-Einstellungen → „Auflösung von IPv6-Adressen deaktivieren“*. Das gilt dann aber für alle Geräte.

Wenn das Apple TV die Fritzbox als DNS nutzt, gilt das nicht. Dann musst du IPv6 in der Fritzbox für das Gerät abschalten oder AdGuard als DNS verwenden.

## 7. Test

1. `http://<IP des Pi>:8099` öffnen. Der Status zeigt „🇩🇪 Deutschland (normal)“.
2. Am Apple TV muss das Internet funktionieren, mit deutscher IP.
3. Auf **„Auf 🇦🇱 Albanien umschalten“** tippen. Der Tunnel sollte „verbunden“ zeigen.
4. **YouTube-App neu starten** und unter *Einstellungen → Standort* prüfen: **Albanien**.

Für Automationen (z. B. ioBroker) gibt es eine API: `POST /on`, `POST /off`, `POST /toggle` (mit `Accept: application/json` gibt es JSON statt Redirect), `GET /api/status`, `GET /api/servers`, `GET /healthz`.

## 8. Automatisches Zurücksetzen um 03:00 Uhr

Ein Hintergrund-Thread im Container prüft laufend die Uhrzeit. Ist um **03:00 Uhr (Europe/Berlin, mit Sommer-/Winterzeit)** „Albanien“ aktiv, schaltet er automatisch auf „Deutschland“ zurück und schreibt das ins Log. Im Modus Albanien zeigt die Oberfläche den Hinweis „Wird automatisch um 03:00 Uhr zurückgesetzt“.

- **Uhrzeit ändern:** `AUTO_RESET_TIME=05:30` im Stack setzen und den Stack aktualisieren.
- **Abschalten:** `AUTO_RESET_TIME` auf einen **leeren Wert** setzen. Die Variable muss dabei vorhanden, aber leer sein.
- **Zeitzone:** `TZ`, Standard `Europe/Berlin`.

## 9. Fehlerbehebung

**Apple TV hat kein Internet**
- Container-Logs in Portainer prüfen. Fehlende Variablen und Probleme beim Start werden dort klar gemeldet.
- Auf dem Pi:
  ```bash
  ip rule show                  # 100/101 immer, 200 nur im Modus Albanien
  ip route show table 51820     # default dev wg-atv + blackhole default metric 1000
  sudo wg show                  # latest handshake sollte jünger als 3 min sein
  sudo iptables -L DOCKER-USER -n -v
  ```
- Ist der Tunnel nicht verbunden und der Kill-Switch an, hat das Apple TV im Modus Albanien absichtlich kein Internet. Dann auf „Deutschland“ schalten oder einen anderen Server wählen.
- Kommen im Modus Albanien keine Antworten an und meldet das Log `rp_filter ist strikt`: `sudo sysctl -w net.ipv4.conf.all.rp_filter=2` (dauerhaft in `/etc/sysctl.d/`).

**Pi ist aus oder wird gewartet**
Am Apple TV *IP konfigurieren* auf **Automatisch** stellen. Dann nutzt es wieder direkt die Fritzbox.

**Mullvad-Server blockiert oder YouTube verlangt eine Bot-Prüfung**
In der Oberfläche unter „Server“ einen anderen Tirana-Server mit *Verwenden* wählen. Der Wechsel passiert ohne Neustart, der Modus bleibt erhalten. Danach die YouTube-App neu starten. Mit `AUTO_FAILOVER=true` wechselt der Container automatisch, wenn der aktive Server länger als 3 Minuten keinen Handshake hat.

## 10. Sicherheitshinweis

**Port 8099 niemals in der Fritzbox nach außen freigeben.** Die Oberfläche ist für das Heimnetz gedacht. Setze zusätzlich `WEB_PASSWORD`. Die `.conf`-Dateien enthalten private Schlüssel. Der Ordner `config/` gehört deshalb nicht in Backups, die du teilst, und nicht in Git.

## Entwicklung

```bash
pip install pytest
pytest
```

Die Tests prüfen die erzeugten Befehle mit einem gemockten Command-Runner und brauchen kein Root. Die GitHub Action führt sie vor jedem Image-Build aus und baut dann `linux/amd64` und `linux/arm64` nach GHCR.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
