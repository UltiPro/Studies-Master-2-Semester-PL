from Crypto.PublicKey import RSA
from datetime import datetime


# Generowanie pary kluczy (publiczny i prywatny)
def generuj_klucze():
    klucz = RSA.generate(2048)
    private_key = klucz.export_key()
    public_key = klucz.publickey().export_key()
    return private_key, public_key


# Początek pomiaru
start_time = datetime.now()

private_key, public_key = generuj_klucze()

# Koniec pomiaru
end_time = datetime.now()

# Czas wykonania
execution_time = end_time - start_time
print(f"Czas wykonania: {execution_time}")


# Zapis kluczy do plików
with open("private.pem", "wb") as f:
    f.write(private_key)
with open("public.pem", "wb") as f:
    f.write(public_key)
