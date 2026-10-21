# LanScanner v1.3.2 — Network Scanner Portatile per Windows

**LanScanner** è uno strumento leggero, veloce e moderno per la scansione ed esplorazione degli host attivi sulla rete locale (LAN IPv4).

Realizzato in Python con interfaccia grafica **PySide6 (Qt 6)** e design **Material 3 Expressive**.

---

## ⬇️ Novità v1.3.2

- **Aggiornamento automatico**: quando esce una nuova versione, "Aggiorna e riavvia" scarica `LanScanner.exe` dalla release GitHub, ne verifica dimensione e SHA-256, sostituisce l'exe in uso e riavvia l'app. Il file della versione precedente viene cancellato al primo avvio successivo.
- **Dispositivi nuovi**: dopo la prima scansione l'app ricorda i MAC visti; quelli mai visti prima compaiono in grassetto con "🆕 Nuovo" (Strumenti → Azzera elenco dispositivi conosciuti per ripartire).
- **Ordinamento**: clic sulle intestazioni della tabella; IP e latenza ordinati in modo numerico.
- **Esporta Report PDF** diretto (orizzontale A4), anche dal menu contestuale; la stampa è ora orizzontale.
- **Traceroute**: mostra anche gli hop che non rispondono e risolve i nomi senza rallentare il percorso.
- **Calcolatore subnet**: wildcard, tipo di indirizzo (privato, loopback, APIPA, multicast), /31 e /32 corretti; nessun blocco con reti grandi (prima `/8` bloccava la finestra per ~10 s, anche solo digitandola nel campo IP).
- **Wake-on-LAN** inviato da ogni scheda di rete, sia in broadcast sia sulla subnet, porte 9 e 7.
- **SSH** con richiesta del nome utente (ricordato) e avviso se il client OpenSSH non è installato.
- **Ping continuo** con latenza minima e massima; le risposte sotto il millisecondo compaiono come "<1 ms".
- Ctrl+R durante una scansione non ne avvia una seconda (prima la tabella si riempiva di righe doppie); "Interrompi" non lascia più hostname a "...".
- "MAC su più IP" segnalato solo se gli IP con lo stesso MAC rispondono entrambi al ping. Un IP rimasto solo nella cache ARP con il MAC di un host attivo è indicato come "IP precedente di …" (tipico cambio di indirizzo DHCP), non più come conflitto.

## 🔧 Novità v1.3.1 (correzioni)

- Scansione porte personalizzata e "Analizza Dettagliatamente" ora mostrano i risultati (prima restavano su "in corso...").
- Nome mDNS (`.local`) letto correttamente dalla risposta DNS (prima poteva comparire un ottetto dell'IP, es. `10.local`).
- Risoluzione dei nomi in parallelo: su una LAN con molti dispositivi senza nome DNS passa da minuti a pochi secondi.
- "Interrompi" ferma subito la scansione; il ping continuo si ferma davvero alla chiusura della finestra.
- Intervallo proposto in base alla subnet mask reale della scheda (non più sempre /24); rilevamento schede indipendente dalla lingua di Windows.
- Database produttori con i blocchi MA-M e MA-S (prefissi /28 e /36): produttore corretto per molti dispositivi IoT.
- Avviso "MAC su più IP" per possibili conflitti; stato "Solo ARP (no ping)" per i dispositivi presenti solo nella cache ARP.
- Report HTML e stampa: intestazione della tabella corretta e dati di rete escapati.
- Eseguibile compilato senza UPX per ridurre i falsi positivi degli antivirus.

## 🎨 Caratteristiche Principali

- **Interfaccia Grafica Material 3 Expressive**:
  - TopBar moderna con logo icona, chip versione, pulsanti ad azione rapida e badge sviluppatore.
  - **Commutazione Temi Dinamica**: Tema **Chiaro (☀️)**, **Scuro (🌙)** e **Automatico (💻)** sincronizzato con le impostazioni di sistema di Windows.
- **Scansione ICMP Nativa ad Altissima Velocità**:
  - Utilizzo diretto delle API native di Windows (`IcmpSendEcho` via `ctypes`) per una velocità fino a 10 volte superiore.
  - Rilevamento automatico della subnet locale ed avviso di eventuali MAC duplicati su più IP.
  - **Supporto Notazione CIDR e Calcolatore Subnet**: Inserimento diretto di notazioni come `192.168.1.0/24` e strumento di calcolo subnet integrato.
- **Service Discovery & Protocolli Avanzati**:
  - **Risoluzione mDNS / Bonjour (`.local`)** e **SSDP / UPnP Multicast Probe** per identificare automaticamente Smart TV, NAS Synology/QNAP, dispositivi IoT e stampanti.
  - Lookup istantaneo dei produttori hardware (Vendor) tramite database IEEE OUI integrato (compresso zlib).
- **Diagnostica & Strumenti Integrati**:
  - **Custom Port Scanner & Banner Grabbing**: Scansione di range di porte personalizzabili con lettura delle intestazioni di risposta dei servizi (HTTP, SSH, ecc.).
  - **Rilevatore Rotta Traceroute**: Visualizzazione grafica del percorso di rete hop-by-hop.
  - **Note Utente Personalizzate**: Possibilità di assegnare etichette e note agli indirizzi IP/MAC salvate localmente.
  - Sondaggio NetBIOS (`nbtstat -A`), Ping Continuo RTT con statistiche, avvio RDP, SSH, SMB, HTTP/HTTPS e pacchetti **Wake-on-LAN (WoL)**.
- **Esportazione Multi-Formato & Stampa**:
  - Esportazione dei risultati in **CSV** (con UTF-8 BOM compatibile con Excel), **JSON** e **Report HTML Interattivo** con barra di ricerca integrata.
  - Generazione e stampa di report cartacei o PDF.

---

## 🚀 Compilazione Eseguibile Portatile & Installer

### 1. Requisiti di Sviluppo
```bash
pip install -r requirements.txt
```

### 2. Test
```bash
pip install -r requirements-dev.txt
python -m pytest -q tests
```

### 3. Generazione dell'Eseguibile Portatile (.exe)
Per generare l'eseguibile standalone portatile `dist/LanScanner.exe`:
```bash
python build_exe.py
```

### 4. Generazione dell'Installer Windows (Inno Setup)
Compilando lo script `installer.iss` tramite [Inno Setup](https://jrsoftware.org/isinfo.php), verrà generato l'installatore guidato in italiano `dist/LanScanner_Setup.exe`.

L'eseguibile e l'installer si pubblicano come asset delle [Release GitHub](https://github.com/vincenzocuria/LanScannerPortable/releases), non nel repository. Ogni release deve allegare **`LanScanner.exe`** e **`LanScanner_Setup.exe`** con questi nomi esatti: li usano l'aggiornamento automatico dell'app e i pulsanti "Scarica Portable" e "Scarica Installer" di [vcuria.app](https://vcuria.app/apps/lan-scanner) (link `releases/latest/download/<nome>`).

### 5. Aggiornamento del database produttori
```bash
python regen_oui_vendor.py
```

---

## 👨‍💻 Autore & Crediti

- **Autore**: Vincenzo Curia ([vcuria.app](https://vcuria.app))
- **Azienda**: NGV Group S.R.L.
- **Database Vendor OUI**: Derivato dal file `manuf` del progetto Wireshark.
- **Licenza**: Software gratuito per uso personale e commerciale.
