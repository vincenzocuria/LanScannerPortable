# LanScanner v1.3.0 — Network Scanner Portatile per Windows

**LanScanner** è uno strumento leggero, veloce e moderno per la scansione ed esplorazione degli host attivi sulla rete locale (LAN IPv4).

Realizzato in Python con interfaccia grafica **PySide6 (Qt 6)** e design **Material 3 Expressive**.

---

## 🎨 Caratteristiche Principali (v1.3.0)

- **Interfaccia Grafica Material 3 Expressive**:
  - TopBar moderna con logo icona, chip versione, pulsanti ad azione rapida e badge sviluppatore.
  - **Commutazione Temi Dinamica**: Tema **Chiaro (☀️)**, **Scuro (🌙)** e **Automatico (💻)** sincronizzato con le impostazioni di sistema di Windows.
- **Scansione ICMP Nativa ad Altissima Velocità**:
  - Utilizzo diretto delle API native di Windows (`IcmpSendEcho` via `ctypes`) per una velocità fino a 10 volte superiore.
  - Rilevamento automatico della subnet locale ed avviso di eventuali conflitti IP / MAC duplicati.
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

### 2. Generazione dell'Eseguibile Portatile (.exe)
Per generare l'eseguibile standalone portatile `dist/LanScanner.exe`:
```bash
python build_exe.py
```

### 3. Generazione dell'Installer Windows (Inno Setup)
Compilando lo script `installer.iss` tramite [Inno Setup](https://jrsoftware.org/isinfo.php), verrà generato l'installatore guidato in italiano `dist/LanScanner_Setup_v1.3.0.exe`.

---

## 👨‍💻 Autore & Crediti

- **Autore**: Vincenzo Curia ([vcuria.app](https://vcuria.app))
- **Azienda**: NGV Group S.R.L.
- **Database Vendor OUI**: Derivato dal file `manuf` del progetto Wireshark.
- **Licenza**: Software gratuito per uso personale e commerciale.
