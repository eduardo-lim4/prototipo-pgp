import tkinter as tk
from tkinter import messagebox, filedialog
import secrets
import string
import hashlib

# Alfabeto usado para gerar criptografia falsa
ALPHABET = string.ascii_letters + string.digits + string.punctuation

# Chaves e dados globais
PUBLIC_KEY = None
PRIVATE_KEY = None
original_hash = None

def generate_keys():
    """Gera um par de chaves aleatórias."""
    alphabet = string.ascii_letters + string.digits
    public_key = "PUB_" + secrets.token_hex(8)
    private_key = "PRIV_" + secrets.token_hex(16)
    return public_key, private_key

def generate_hash(message: str) -> str:
    """Gera um hash SHA-256 da mensagem original."""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

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
    global PUBLIC_KEY, PRIVATE_KEY, original_hash

    msg = entry_message.get()
    if not msg:
        messagebox.showwarning("Aviso", "Digite uma mensagem primeiro!")
        return
    if len(msg) > 128:
        messagebox.showwarning("Aviso", "A mensagem deve ter no máximo 128 caracteres!")
        return

    PUBLIC_KEY, PRIVATE_KEY = generate_keys()
    encrypted = fake_encrypt(msg)
    original_message.set(msg)
    original_hash = generate_hash(msg)

    output_encrypted.set(encrypted)
    output_public.set(PUBLIC_KEY)
    output_private.set(PRIVATE_KEY)

def decrypt_message():
    key = entry_key.get()
    if not key:
        messagebox.showwarning("Aviso", "Digite a chave privada para descriptografar!")
        return

    decrypted = fake_decrypt(output_encrypted.get(), key, original_message.get())
    if decrypted == "Chave privada inválida!":
        messagebox.showerror("Erro", decrypted)
        return

    hash_check = generate_hash(decrypted)
    if hash_check == original_hash:
        messagebox.showinfo("Resultado", f"Mensagem descriptografada: {decrypted}\nIntegridade: OK ✅")
    else:
        messagebox.showwarning("Alerta", "Mensagem foi alterada! ❌ Integridade comprometida.")

def import_txt():
    """Carrega um arquivo TXT e coloca o conteúdo no campo de mensagem."""
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filepath:
        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read().strip()
            entry_message.delete(0, tk.END)
            entry_message.insert(0, content)

def save_encrypted_txt():
    """Salva a mensagem criptografada em um arquivo TXT."""
    encrypted = output_encrypted.get()
    if not encrypted:
        messagebox.showwarning("Aviso", "Nenhuma mensagem criptografada para salvar!")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text Files", "*.txt")])
    if filepath:
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(encrypted)
        messagebox.showinfo("Sucesso", f"Mensagem criptografada salva em:\n{filepath}")

def import_encrypted_txt():
    """Carrega um arquivo TXT criptografado para tentar descriptografar."""
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filepath:
        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read().strip()
            output_encrypted.set(content)

# Interface principal
root = tk.Tk()
root.title("Protótipo PGP - Criptografia Didática")
original_message = tk.StringVar()

# Mensagem
tk.Label(root, text="Digite sua mensagem (máx. 128 caracteres):").pack()
entry_message = tk.Entry(root, width=50)
entry_message.pack()

# Botões de arquivo
frame_files = tk.Frame(root)
frame_files.pack(pady=5)
tk.Button(frame_files, text="Importar TXT", command=import_txt).grid(row=0, column=0, padx=5)
tk.Button(frame_files, text="Salvar Criptografia em TXT", command=save_encrypted_txt).grid(row=0, column=1, padx=5)
tk.Button(frame_files, text="Importar TXT Criptografado", command=import_encrypted_txt).grid(row=0, column=2, padx=5)

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
