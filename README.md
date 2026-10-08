# ftie-threat-engine1

# FTIE v11.0 - Threat Intelligence Engine

Autorski, skalowalny framework analityczny przeznaczony do identyfikacji oraz neutralizacji zagrożeń typu CIB (Coordinated Inauthentic Behavior) i złośliwych sieci botów (phishing).

## Architektura projektu
- **Dynamiczne ładowanie wskaźników (IOC):** Domeny phishingowe są odczytywane z zewnętrznego pliku konfiguracyjnego (`domains.txt`), co pozwala na płynną skalowalność i obsługę setek lub tysięcy adresów bez modyfikacji kodu źródłowego.
- **Audyt kryptograficzny:** Każdy raport z analizy wektora zagrożenia jest zabezpieczany i weryfikowany za pomocą sygnatury **HMAC-SHA256**.
- **Optymalizacja wydajności:** Wykorzystanie struktur typu `set` zapewnia natychmiastowe przeszukiwanie baz domen w czasie rzeczywistym.

## Struktura repozytorium
- `engine.py` – główny silnik oceniający zagrożenia i generujący raporty audytowe.
- `domains.txt` – zewnętrzna baza wskaźników zagrożeń (IOC).

## Uruchomienie lokalne
Upewnij się, że oba pliki (`engine.py` oraz `domains.txt`) znajdują się w tym samym folderze, a następnie uruchom skrypt w terminalu:

```bash
python engine.py
