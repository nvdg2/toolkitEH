# Python toolkit ethisch hacken

## Installatievereisten

Vooraleer deze toolkit gebruikt kan worden, moeten er eerst enkele acties uitgevoerd worden.

### Installeer de nodige pakketten

Sommige python libraries, hebben onderliggende systeempakketten nodig. Installeer daarom de volgende pakketten:

- nmap
- libnetfilter_queue

### Python environment

Om conflicten te vermijden met andere python pakketten, gebruikt deze toolkit een virtuele omgeving. Deze omgeving moet zich in de root folder van het project bevinden.

Voer daarom het volgende commando uit in de root folder om deze omgeving op te zetten: `python3 -m venv .venv`

Om de nodige libraries in de virtuele omgeving toe te voegen, voer dan respectievelijk de volgende commandos uit : `source .venv/bin/activate` en `pip install -r requirements.txt`.

Je virtuele omgeving is nu gereed.

## Opmerking ivm Man In The Middle component

Wanneer de MITM functionaliteit wordt opgeroepen, starten externe terminals, zodat alle output gestructureerd weergegeven kan worden. Hiervoor worden Xterm terminals gebruikt. 

>Dit betekent dat enkel gebruikers met het X display system (Linux) de MITM component kunnen runnen.

