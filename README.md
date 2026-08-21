# 🔒 ECC File Encryptor

Zaawansowany program do szyfrowania i deszyfrowania plików wszystkich typów, oparty na kryptografii krzywych eliptycznych (ECC) z graficznym interfejsem użytkownika.

## Schemat kryptograficzny

| Warstwa | Algorytm | Opis |
|---|---|---|
| Wymiana kluczy | **ECDH X25519** | Szybka, bezpieczna wymiana klucza |
| Tryb paranoidalny | **X25519 + P-521** | Podwójna krzywa eliptyczna |
| Szyfrowanie treści | **AES-256-GCM** | Szyfrowanie authenticated encryption |
| Wyprowadzanie klucza | **HKDF-SHA-512** | Bezpieczna derywacja klucza sesji |
| Podpis cyfrowy | **Ed25519** | Weryfikacja autentyczności pliku |
| Ochrona kluczy | **Argon2id + AES-256-GCM** | Bezpieczne przechowywanie kluczy |

## Funkcje

- 🔐 **Szyfrowanie ECIES** – hybrydowe szyfrowanie dla dowolnych plików
- 👥 **Multi-odbiorca** – jeden plik zaszyfrowany dla wielu kluczy jednocześnie
- 🛡️ **Tryb paranoidalny** – podwójna krzywa (X25519 + P-521)
- ✍️ **Podpisy Ed25519** – weryfikacja autora i integralności
- 🔑 **Menedżer kluczy** – generowanie, import/export PEM, Argon2id
- 📁 **Foldery** – automatyczne zipowanie i szyfrowanie całych katalogów
- 🔥 **Bezpieczne usuwanie** – shredding oryginalnych plików (3 przejścia)
- 📋 **Historia operacji** – log wszystkich operacji kryptograficznych
- 🖥️ **Nowoczesny GUI** – ciemny motyw CustomTkinter

## Instalacja

```bash
pip install -r requirements.txt
```

### Wymagania

- Python 3.11+
- `cryptography >= 42.0.0`
- `customtkinter >= 5.2.2`
- `argon2-cffi >= 23.1.0`
- `Pillow >= 10.0.0`

## Uruchomienie

```bash
python main.py
```

## Format pliku `.ecc`

Zaszyfrowane pliki mają rozszerzenie `.ecc` i zawierają:

```
[8 B]  Magic bytes: ECCRYPT\x00
[1 B]  Wersja
[1 B]  Flagi (paranoidalny, podpisany)
[1 B]  Liczba odbiorców
[2 B]  Długość nazwy pliku
[N B]  Oryginalna nazwa pliku (UTF-8)
[32 B] Salt HKDF
[12 B] IV AES-GCM
--- blok odbiorcy (powtarzany) ---
[32 B] Efemeralny klucz X25519
[67 B] Efemeralny klucz P-521 (tryb paranoidalny)
[60 B] Zaszyfrowany klucz sesji
--- dane ---
[M B]  Szyfrogram AES-256-GCM
--- jeśli podpisany ---
[32 B] Klucz publiczny Ed25519 podpisującego
[64 B] Podpis Ed25519
```

## Bezpieczeństwo

> ⚠️ **UWAGA**: Katalog `keys/` zawiera klucze prywatne i jest wykluczony z repozytorium `.gitignore`. Nigdy nie commituj kluczy prywatnych!

- Klucze prywatne są zawsze szyfrowane Argon2id + AES-256-GCM
- Integralność pliku jest weryfikowana przez tag GCM (128-bit)
- Nagłówek pliku jest chroniony AAD (Authenticated Associated Data)

## Licencja

MIT
