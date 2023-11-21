# Python toolkit ethisch hacken

## Inleiding

Om kennis te maken met meerdere aspecten van pentesting, heb ik een tool gemaakt met een groot gamma aan verschillende scans en aanvallen. We spreken over de volgende functionaliteiten:

- Reconaissance, zowel netwerk als web
- Man In The Middle
- Denail of Service

## Installatievereisten

Vooraleer deze toolkit gebruikt kan worden, moeten er eerst enkele acties uitgevoerd worden.

### Installeer de nodige pakketten

Sommige python libraries, hebben onderliggende systeempakketten nodig. Installeer daarom de volgende pakketten:

- Nmap (voor nmap scans)
- Libnetfilter_queue (voor DNS spoofer)
- Airmon-ng (voor alle modules die sniffing mode nodig hebben)
- Python versie 3.11.X

### Python environment

Om conflicten te vermijden met andere python pakketten, gebruikt deze toolkit een virtuele omgeving. Deze omgeving moet zich in de root folder van het project bevinden.

Voer daarom het volgende commando uit in de root folder om deze omgeving op te zetten: `python3 -m venv .venv`

Om de nodige libraries in de virtuele omgeving toe te voegen, voer dan respectievelijk de volgende commandos uit : `source .venv/bin/activate` en `pip install -r requirements.txt`.

Je virtuele omgeving is nu gereed.

## Scope

### Framework

Mijn focus tijdens het project was om zo veel mogelijk aspecten van pentesting te ontdekken. Daarom heb ik minder tijd gestoken in compatibiliteit en is mijn framework tool gemaakt om op Linux te draaien. In sommige gevallen moet de Xterm geïnstalleerd zijn, aangezien deze tools best apart functioneren. Uiteraard kan in de toekomst ondersteuning voor andere besturingssystemen toegevoegd worden.

Hieronder kan u een oplijsting vinden van alle modules en hun compatibiliteit.

> Ik heb compatibiliteit enkel gebaseerd op de inhoud van de scripts en hoe deze worden geactiveerd door het framework.
> Ik had jammer genoeg niet de tijd om dit actief te testen. Mijn excuses hiervoor.

Matrix wanneer framework wordt gebruikt

| Module                | OS                  | Xterm needed |
| --------------------- | ------------------- | ------------ |
| Deauth attack         | Linux               | No           |
| HTTP dos master       | Linux               | No           |
| HTTP dos bot          | Linux,Windows, Mac  | No           |
| DHCP Starvation       | Linux               | Yes          |
| MITM (+DNS spoof)     | Linux               | Yes          |
| BSSID scanner         | Linux               | Yes          |
| Robot.txt brute force | Linux, Windows, Mac | No           |
| Scapy scans           | Linux               | No           |
| Nmap scans            | Linux               | No           |
| XSS aanval            | Linux, Windows, Mac | No           |

### Scripts

Alle scripts die deel uitmaken van het framework werken volgens de onderstaande principes:

1. Alle scripts kunnen zelfstandig uitgevoerd worden met Python
2. Wanneer scripts output geven, wordt dit altijd in JSON naar een bestand weggeschreven

Matrix wanneer scipts rechtstreeks via Python worden gestart

| Module                | OS                  | Xterm needed |
| --------------------- | ------------------- | ------------ |
| Deauth attack         | Linux               | No           |
| HTTP dos master       | Linux, Windows, Mac | No           |
| HTTP dos bot          | Linux, Windows, Mac | No           |
| DHCP starvation       | Linux               | No           |
| MITM (+DNS spoof)     | Linux               | Yes          |
| BSSID scanner         | Linux               | No           |
| Robot.txt brute force | Linux, Windows, Mac | No           |
| Scapy scans           | Linux, Windows, Mac | No           |
| Nmap scans            | Linux, Windows, Mac | No           |
| XSS aanval            | Linux, Windows, Mac | No           |
