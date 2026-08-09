# LanScanner — Network Scanner Portatile per Windows

**LanScanner** è uno strumento leggero, veloce e moderno per la scansione ed esplorazione degli host attivi sulla rete locale (LAN IPv4).

Realizzato in Python con interfaccia grafica **PySide6 (Qt 6)** e design **Material 3 Expressive**.

---

## 🎨 Caratteristiche Principali

- **Interfaccia Grafica Material 3 Expressive**:
  - TopBar moderna con logo icona, chip versione, pulsanti ad azione rapida e badge sviluppatore.
  - **Commutazione Temi Dinamica**: Tema **Chiaro (☀️)**, **Scuro (🌙)** e **Automatico (💻)** sincronizzato con le impostazioni di sistema di Windows.
- **Scansione LAN Multithreaded ad Alta Velocità**:
  - Rilevamento automatico subnet locale.
  - Scansione parallela mediante socket ping / ICMP con avanzamento in tempo reale.
- **Identificazione Dispositivi & Vendor OUI**:
  - Estrazione automatica della tabella ARP di Windows.
  - Lookup istantaneo dei produttori hardware (Vendor) tramite database IEEE OUI integrato (compresso zlib).
  - Risoluzione Hostname (Reverse DNS) e indizio tipologia dispositivo (PC, Mobile, VM, IoT, Stampante).
- **Analisi Dettagliata Dispositivo**:
  - Sondaggio NetBIOS (`nbtstat -A`).
  - Scansione rapida delle porte TCP comuni (HTTP, HTTPS, SMB, SSH, RTSP, JetDirect).
  - Copia automatica del report di diagnosi.
- **Ricerca Aggiornamenti integrata**:
  - Thread in background che interroga le API di GitHub Releases per notificare la disponibilità di nuove versioni.
- **Esportazione & Stampa**:
  - Esportazione dei risultati in formato **CSV** (con codifica UTF-8 BOM compatibile con Microsoft Excel).
  - Generazione e stampa di report cartacei o PDF.
- **File & Intervalli Recenti**:
  - Salvataggio automatico degli ultimi intervalli IP scansionati tramite `QSettings`.

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
Compilando lo script `installer.iss` tramite [Inno Setup](https://jrsoftware.org/isinfo.php), verrà generato l'installatore guidato in italiano `dist/LanScanner_Setup_v1.2.0.exe`.

---

## 👨‍💻 Autore & Crediti

- **Autore**: Vincenzo Curia ([vcuria.app](https://vcuria.app))
- **Azienda**: NGV Group S.R.L.
- **Database Vendor OUI**: Derivato dal file `manuf` del progetto Wireshark.
- **Licenza**: Software gratuito per uso personale e commerciale.
