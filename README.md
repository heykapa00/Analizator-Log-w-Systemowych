# Analizator Logów Systemowych

Prosty, ale skuteczny skrypt w Pythonie do analizy logów systemowych pod kątem bezpieczeństwa.

**Cel projektu:**
Wykrywanie nieudanych prób logowania, identyfikacja podejrzanych adresów IP oraz generowanie automatycznego raportu bezpieczeństwa.

### Funkcjonalności
- Parsowanie logów z pliku CSV (np. eksport z Windows Event Viewer)
- Wykrywanie nieudanych logowań (Event ID 4625)
- Liczenie prób na IP i użytkownika
- Automatyczne alerty przy >5 próbach z jednego IP
- Generowanie czytelnego raportu TXT

### Technologie
- Python 3
- csv, collections, datetime

### Jak uruchomić
```bash
python analyzer.py
