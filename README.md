# Opis Projektu

Aplikacja umożliwia zalogowanemu użytkownikowi przechowywanie notatek tekstowych. Funkcjonalności obejmują:

- Zaznaczanie niektórych notatek jako zaszyfrowane, co wymaga podania tajnego hasła do ich odszyfrowania.
- Rejestrację i logowanie z wykorzystaniem:
  - Hasła.
  - Drugiego składnika weryfikacyjnego opartego na algorytmie TOTP (Time-Based One-Time Password).
- Udostępnianie notatek w dwóch trybach:
  - Wybranym użytkownikom.
  - Publicznie.
- Podpisywanie notatek w sposób umożliwiający weryfikację autora.
- Podstawowe formatowanie notatek, takie jak:
  - Dodawanie pogrubienia tekstu.
  - Wstawianie obrazka z zewnętrznego serwisu.
  - Dodawanie odnośników.
  - Kursywa wybranego słowa.
  - Nagłówki o wybranych poziomach (1-5).

---

## Moduł uwierzytelniania

Moduł uwierzytelniania realizuje następujące wymagania:

1. **Walidacja danych wejściowych**:
   - Z negatywnym nastawieniem, aby zabezpieczyć aplikację przed atakami.

2. **Ochrona przed atakami typu brute-force**:
   - Limity prób logowania.
   - Dodanie opóźnień między kolejnymi próbami.

3. **Bezpieczeństwo haseł**:
   - Ograniczone informowanie o błędach (np. brak szczegółowych informacji o przyczynie odmowy logowania).
   - Bezpieczne przechowywanie haseł:
     - Kryptograficzne funkcje mieszające.
     - Wykorzystanie soli.
     - Wielokrotne haszowanie.
   - Kontrola siły hasła w celu edukacji użytkownika o wymaganiach bezpieczeństwa.

4. **Zarządzanie dostępem**:
   - Precyzyjna kontrola uprawnień użytkowników do zasobów.

---

## Wymagania

### Główne wymagania:
1. **Skonteneryzowanie aplikacji za pomocą Docker**:
   - Uruchamianie za pomocą:
     - `$ docker-compose up --build`

2. **Baza danych**:
   - Obsługa bazy danych SQL (np. SQLite).

3. **Serwer produkcyjny**:
   - Wykorzystanie produkcyjnego serwera WWW (np. nginx). Niedozwolone jest korzystanie z wbudowanych serwerów deweloperskich.

4. **Bezpieczne połączenie**:
   - Wszystkie dane przesyłane między aplikacją a użytkownikiem muszą być szyfrowane (SSL/TLS).

5. **Walidacja danych wejściowych**:
   - Walidacja z negatywnym nastawieniem.

6. **Weryfikacja dostępu użytkownika**:
   - Sprawdzanie poprawności dostępu do zasobów.

7. **Bezpieczeństwo logowania**:
   - Weryfikacja liczby nieudanych prób logowania.
   - Kontrola jakości hasła (np. analiza entropii).
   - Dodanie opóźnień podczas logowania.

8. **Znajomość implementacji**:
   - Dokładna wiedza na temat wykorzystanych modułów i szkieletów aplikacji.

---

## Elementy dodatkowe

- Zabezpieczenie przed Cross-Site Request Forgery (CSRF).
- Wykorzystanie honeypots.

---
