from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from datetime import datetime


# Funkcja generująca skrót dokumentu przy użyciu SHA256
def generuj_sha256(document_text):
    sha256 = SHA256.new()
    sha256.update(document_text.encode("utf-8"))
    return sha256


# Podpisanie skrótu dokumentu kluczem prywatnym (RSA)
def podpisz_dokument(document_text, private_key):
    skrót = generuj_sha256(document_text)
    rsa_private_key = RSA.import_key(private_key)
    podpis = pkcs1_15.new(rsa_private_key).sign(skrót)
    return podpis


# Weryfikacja podpisu przy pomocy klucza publicznego
def weryfikuj_podpis(document_text, podpis, public_key):
    skrót = generuj_sha256(document_text)
    rsa_public_key = RSA.import_key(public_key)
    try:
        pkcs1_15.new(rsa_public_key).verify(skrót, podpis)
        print("Podpis jest prawidłowy.")
    except (ValueError, TypeError):
        print("Podpis jest nieprawidłowy.")


# Pobranie kluczy
private_key = open("private.pem").read()
public_key = open("public.pem").read()

# Przykład dokumentu
document = "Przykładowa treść dokumentu o numerze dwa"

# Początek pomiaru
start_time = datetime.now()

# Generowanie podpisu
podpis = podpisz_dokument(document, private_key)
print(f"Podpis dokumentu: {podpis.hex()}")

# Weryfikacja podpisu
weryfikuj_podpis(document, podpis, public_key)

# Koniec pomiaru
end_time = datetime.now()

# Czas wykonania
execution_time = end_time - start_time
print(f"Czas wykonania: {execution_time}")
