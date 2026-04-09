"""
Analizator Logów Systemowych
Prosty skrypt do wykrywania podejrzanych aktywności w logach (głównie nieudane logowania)
"""

import csv
from collections import Counter
from datetime import datetime


def analyze_failed_logins(csv_file: str):
    failed_attempts = []

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Szukamy nieudanych logowań (możesz dostosować kolumny do swojego pliku)
            message = row.get('Message', '').lower()
            if any(keyword in message for keyword in ['failed', 'nieudane', 'logon failure', '0x18']):
                attempt = {
                    'time': row.get('TimeCreated', ''),
                    'user': row.get('TargetUserName', row.get('User', 'N/A')),
                    'ip': row.get('IpAddress', row.get('SourceNetworkAddress', 'N/A')),
                    'event_id': row.get('EventID', 'N/A')
                }
                failed_attempts.append(attempt)

    # Liczenie prób
    ip_count = Counter(attempt['ip'] for attempt in failed_attempts)
    user_count = Counter(attempt['user'] for attempt in failed_attempts)

    # Generowanie raportu
    print("\n=== RAPORT BEZPIECZEŃSTWA - ANALIZATOR LOGÓW ===\n")
    print(f"Łączna liczba nieudanych logowań: {len(failed_attempts)}\n")

    print("TOP 5 IP z największą liczbą prób:")
    for ip, count in ip_count.most_common(5):
        status = "⚠️ ALERT" if count > 5 else ""
        print(f"  {ip:15} → {count:3} prób {status}")

    print("\nNajczęściej atakowane konta:")
    for user, count in user_count.most_common(5):
        print(f"  {user:15} → {count:3} prób")

    # Zapis raportu do pliku
    with open('raport_bezpieczenstwa.txt', 'w', encoding='utf-8') as f:
        f.write("RAPORT BEZPIECZEŃSTWA - Analizator Logów\n")
        f.write(f"Data wygenerowania: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"Nieudane logowania: {len(failed_attempts)}\n\n")
        f.write("TOP IP:\n")
        for ip, count in ip_count.most_common():
            f.write(f"{ip} → {count} prób\n")

    print("\n✅ Raport zapisany do pliku: raport_bezpieczenstwa.txt")


# === UŻYCIE ===
if __name__ == "__main__":
    # Podaj ścieżkę do swojego pliku CSV z logami
    analyze_failed_logins('sample_logs.csv')