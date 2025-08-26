import tkinter as tk
from tkinter import messagebox
import secrets
import string
import hashlib

# Alfabeto usado para gerar criptografia falsa
ALPHABET = string.ascii_letters + string.digits + string.punctuation

# Chaves globais
PUBLIC_KEY = None
PRIVATE_KEY = None
original_hash = None

def generate_keys():
    """Gera um par de chaves aleatórias."""
    alphabet = string.ascii_letters + string.digits
    public_key = "PUB_" + secrets.token_hex(8)
    private_key = "PRIV_" + secrets.token_hex(16)
    return public_key, private_key


def fake_encrypt(plaintext: str) -> str:
    """Simula a criptografia gerando texto aleatório do mesmo tamanho."""
    return "".join(secrets.choice(ALPHABET) for _ in range(len(plaintext)))


def fake_decrypt(ciphertext: str, key: str, original: str) -> str:
    """Simula a descriptografia retornando a mensagem original."""
    if key == PRIVATE_KEY:
        return original
    else:
        return "Chave privada inválida!"


def encrypt_message():
    msg = entry_message.get()
    if not msg:
        messagebox.showwarning("Aviso", "Digite uma mensagem primeiro!")
        return
    if len(msg) > 128:
        messagebox.showwarning("Aviso", "A mensagem deve ter no máximo 128 caracteres!")
        return

    encrypted = fake_encrypt(msg)
    output_encrypted.set(encrypted)
    output_public.set(PUBLIC_KEY)
    output_private.set(PRIVATE_KEY)

    global original_message
    original_message = msg


def decrypt_message():
    key = entry_key.get()
    if not key:
        messagebox.showwarning("Aviso", "Digite a chave privada para descriptografar!")
        return

    decrypted = fake_decrypt(output_encrypted.get(), key, original_message)
    messagebox.showinfo("Resultado", f"Mensagem descriptografada: {decrypted}")


# Interface principal
root = tk.Tk()
root.title("Protótipo PGP - Criptografia Didática")

# Mensagem
tk.Label(root, text="Digite sua mensagem (máx. 128 caracteres):").pack()
entry_message = tk.Entry(root, width=50)
entry_message.pack()

# Botão criptografar
tk.Button(root, text="Criptografar", command=encrypt_message).pack(pady=5)

# Resultados
output_encrypted = tk.StringVar()
output_public = tk.StringVar()
output_private = tk.StringVar()

tk.Label(root, text="Mensagem Criptografada:").pack()
tk.Entry(root, textvariable=output_encrypted, width=50, state="readonly").pack()

tk.Label(root, text="Chave Pública:").pack()
tk.Entry(root, textvariable=output_public, width=50, state="readonly").pack()

tk.Label(root, text="Chave Privada:").pack()
tk.Entry(root, textvariable=output_private, width=50, state="readonly").pack()

# Campo chave privada
tk.Label(root, text="Digite a chave privada para descriptografar:").pack()
entry_key = tk.Entry(root, width=50)
entry_key.pack()

# Botão descriptografar
tk.Button(root, text="Descriptografar", command=decrypt_message).pack(pady=5)

# Botão sair
tk.Button(root, text="Sair", command=root.quit).pack(pady=5)

root.mainloop()
