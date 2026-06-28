# Network Traffic Analyzer

Jednoduchý terminálový nástroj na sledovanie sieťovej prevádzky v reálnom čase. Projekt je postavený na Pythone a knižnici Scapy, takže je vhodný hlavne na učenie, školské/lab prostredie a rýchle lokálne testy.

Nie je to enterprise IDS. Je to malý packet analyzer, ktorý ti ukáže, čo približne tečie cez vybrané sieťové rozhranie.

## Čo vie

- 🔎 výber sieťového rozhrania
- 📦 live zachytávanie paketov cez Scapy
- 🎯 filtre typu `tcp`, `udp`, `port 53`, `tcp and port 443`
- 🌐 rozpoznanie bežných protokolov ako DNS, HTTP, HTTPS/TLS, SSH, ARP, ICMP
- 🧾 uloženie čitateľného výstupu do súboru
- 📊 jednoduché štatistiky podľa protokolov
- ⚙️ interaktívne ovládanie aj CLI argumenty

## Inštalácia

Odporúčam použiť virtuálne prostredie. Vyhneš sa problémom so systémovým Pythonom a `sudo`.

```bash
git clone https://github.com/mazanivan/network-traffic-analyzer.git
cd network-traffic-analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

Ak nechceš inštalovať projekt ako príkaz, stačí aj:

```bash
pip install -r requirements.txt
```

## Spustenie

Najjednoduchšie:

```bash
sudo -E nta
```

Alebo priamo cez Python:

```bash
sudo -E python3 nta.py
```

`sudo -E` je dôležité, keď používaš virtuálne prostredie. Zachová tvoje premenné prostredia, takže Python nájde balíčky nainštalované vo `.venv`.

## Príklady

Vypísať dostupné rozhrania:

```bash
sudo -E nta --list-interfaces
```

Zachytiť 20 DNS paketov na rozhraní `wlan0`:

```bash
sudo -E nta -i wlan0 -c 20 -f "port 53"
```

Zachytiť HTTPS/TLS prevádzku a uložiť výstup aj so štatistikou:

```bash
sudo -E nta -i wlan0 -c 50 -f "tcp port 443" -o captures/https.txt --stats
```

Ak nevieš názov rozhrania, môžeš použiť aj číslo zo zoznamu:

```bash
sudo -E nta -i 1 -c 10
```

## Poznámky

- Na Linuxe potrebuješ práva na packet capture, preto sa program typicky spúšťa cez `sudo`.
- Filtre sú BPF filtre, rovnaký štýl ako pri `tcpdump`.
- Pri neobmedzenom zachytávaní ho zastavíš cez `Ctrl+C`.
- Výstup je textový, nie PCAP. Na PCAP export by bolo treba doplniť samostatné ukladanie paketov.

## Ukážka výstupu

```text
[19:49:15] HTTPS/TLS Client Hello (TCP PA) | 192.168.1.148:53228 -> 20.189.173.15:443 | Encrypted | size: 512 bytes
[19:49:16] DNS Query (UDP port 53) | 192.168.1.148 -> 192.168.1.1 | domain: example.com.
[19:49:17] ARP Request | Who has 192.168.1.1? Tell 192.168.1.148 | size: 42 bytes
```

Viac je v `examples/sample-output.txt`.

## Súbory

- `nta.py` - hlavný program
- `requirements.txt` - jednoduchý zoznam balíčkov
- `pyproject.toml` - inštalácia projektu a príkaz `nta`
- `examples/sample-output.txt` - krátka ukážka výstupu

## Autor

[@mazanivan](https://github.com/mazanivan)
