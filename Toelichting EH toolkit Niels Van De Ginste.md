Github repository: [https://github.com/nvdg2/toolkitEH](https://github.com/nvdg2/toolkitEH)

## Inleiding

Om kennis te maken met meerdere aspecten van pentesting, heb ik een tool gemaakt met een groot gamma aan verschillende scans en aanvallen. We spreken over de volgende functionaliteiten:

- Reconnaissance, zowel op netwerken als webapplicaties
- Man In The Middle
- Denail of Service
- BSSID scanning

## Scope

### Framework

Mijn focus tijdens het project was om zo veel mogelijk aspecten van pentesting te ontdekken. Daarom heb ik minder tijd gestoken in compatibiliteit en is mijn framework tool gemaakt om op Linux te draaien. In sommige gevallen moet de Xterm geïnstalleerd zijn om sommige script zelfstandig te laten draaien. Uiteraard kan in de toekomst ondersteuning voor andere besturingssystemen toegevoegd worden.

Hieronder kan u een oplijsting vinden van alle modules (scripts) en welke vereisten deze modules nodig hebben. 

Matrix wanneer Flask framework wordt gebruikt

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

> **Alle scripts** die deel uitmaken van het framework werken volgens de onderstaande principes:

1. De scripts kunnen **zelfstandig uitgevoerd worden** met Python
2. Wanneer scripts output geven, **wordt dit in JSON** naar een bestand weggeschreven

Deze twee principes maken het mogelijk om verder te werken met specifieke modules indien dit gewenst is. De JSON output maakt het mogelijk om meerdere modules op een gestandaardiseerde manier met elkaar samen te laten werken.

Hieronder vindt u opnieuw een matrix in verband met compatibiliteit, maar nu wanneer de scripts zelfstandig worden uitgevoerd

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

> [!note] Ik heb de twee compatibiliteitstabellen opgemaakt op basis van de codelijnen in de scripts. 

## Benodigde derde partij software

De onderstaande derde partij software moet geïnstalleerd zijn om mijn framework te kunnen gebruiken. Libnetfilter_queue en nmap moeten tevens geïnstalleerd zijn voordat een Python environment wordt aangemaakt.

- Nmap (voor nmap scans)
- Libnetfilter_queue (voor DNS spoofer)
- Airmon-ng (voor alle modules die sniffing mode nodig hebben)
- Python versie 3.11.X (algemeen draaien van scripts)

## Opstarten van applicatie

Om de applicatie te starten, voer je de volgende stappen uit:

1. Installeer de derde partij software beschreven in de voorgaande stap
2. Download de code van de volgende [repo](https://github.com/nvdg2/toolkitEH)
3. Ga naar de root folder
4. Creëer een python environment met het volgende commando

```bash
python3 -m venv .venv && 
```

5. Installeer de nodige packages met het volgende commando:

```bash
pip3 install -r requirements.txt
```

6. Voer het volgende commando uit om Flask te vertellen welke bestanden deze moet gebruiken:

```bash
export FLASK_APP=.
```

7. Start tot slot de applicatie via het volgende commando:

```bash
flask run
```

## Geleerde lessen

Ik vond dit een zeer fijn project om aan te werken. De vrijheid die ik kreeg, gaf de  de mogelijkheid om van veel soorten ethische hacking aspecten te proeven: van reconnaissance naar DDOS naar een "simpele" BSSID scanner.

Het was heel leerrijk en heb vooral veel bijgeleerd over het creëren van netwerkpakketten met behulp van Scapy. Dit was uitdagend, maar heel interessant !

Samengevat: een opdracht om naar terug te kijken !
