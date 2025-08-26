# Importação de bibliotecas
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
import secrets
import string
import hashlib

# Alfabeto usado para gerar criptografia falsa
ALPHABET = string.ascii_letters + string.digits + string.punctuation

# Variáveis globais para armazenar as chaves e o hash da mensagem original
PUBLIC_KEY = None
PRIVATE_KEY = None
original_hash = None

# ---- Funções de Lógica Criptográfica ----
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

# ---- Funções de Interface e Ação ----
def encrypt_message():
    """Executa a criptografia da mensagem digitada e atualiza os campos da interface."""
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
    output_hash.set(original_hash)

    output_encrypted.set(encrypted)
    output_public.set(PUBLIC_KEY)
    output_private.set(PRIVATE_KEY)

def decrypt_message():
    """Executa a tentativa de descriptografia e verifica a integridade da mensagem."""
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
            entry_message.delete(0, ttk.END)
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

# ---- Interface Gráfica com ttkbootstrap ----

# Inicializa a Interface com um tema escuro
style = Style(theme="darkly")
root = style.master
root.title("Protótipo PGP - Criptografia Simulada")

# Variável para armazenar a mensagem original
original_message = ttk.StringVar()

# Campo de entrada para a mensagem
ttk.Label(root, text="Digite sua mensagem (máx. 128 caracteres):").pack(pady=5)
entry_message = ttk.Entry(root, width=50)
entry_message.pack()

# Botões para importar e salvar arquivos .txt
frame_files = ttk.Frame(root)
frame_files.pack(pady=10)
ttk.Button(frame_files, text="Importar TXT", command=import_txt, bootstyle="info-outline").grid(row=0, column=0, padx=5)
ttk.Button(frame_files, text="Salvar Criptografia em TXT", command=save_encrypted_txt, bootstyle="info-outline").grid(row=0, column=1, padx=5)


# Botão para criptografar a mensagem
ttk.Button(root, text="Criptografar", command=encrypt_message, bootstyle="sucess").pack(pady=10)

# Variáveis para exibir os resultados
output_encrypted = ttk.StringVar()
output_public = ttk.StringVar()
output_private = ttk.StringVar()
output_hash = ttk.StringVar()

# Campo da mensagem criptografada (somente leitura)
ttk.Label(root, text="Mensagem Criptografada:").pack()
ttk.Entry(root, textvariable=output_encrypted, width=50, state="readonly").pack()

# Campo da chave pública (copiável para melhor eficiência, mas não é permitido editar o conteúdo)
ttk.Label(root, text="Chave Pública:").pack()
entry_public = ttk.Entry(root, textvariable=output_public, width=50, state="normal")
entry_public.pack()
entry_public.bind("<Key>", lambda e: "break")

# Função para bloquear edição mas permitir copiar/colar
def bloquear_edicao(event):
    # Permite Ctrl+C, Ctrl+X, Ctrl+V, Ctrl+A
    if event.state & 0x4 and event.keysym.lower() in ["c", "x", "v", "a"]:
        return
    return "break"

# Campo da chave privada (copiável para melhor eficiência, mas não é permitido editar o conteúdo)
ttk.Label(root, text="Chave Privada:").pack()
entry_private = ttk.Entry(root, textvariable=output_private, width=50, state="normal")
entry_private.pack()
entry_private.bind("<Key>", bloquear_edicao)

# Campo do Hash SHA-256 da mensagem original
ttk.Label(root, text="Hash SHA-256 da Mensagem:").pack()
entry_hash = ttk.Entry(root, textvariable=output_hash, width=50, state="normal")
entry_hash.pack()
entry_hash.bind("<Key>", bloquear_edicao)

# Campo para digitar a chave privada e tentar descriptografar
ttk.Label(root, text="Digite a chave privada para descriptografar:").pack()
entry_key = ttk.Entry(root, width=50)
entry_key.pack()

# Botão descriptografar
ttk.Button(root, text="Descriptografar", command=decrypt_message, bootstyle="warning").pack(pady=10)

# Botão sair
ttk.Button(root, text="Sair", command=root.quit, bootstyle="danger").pack(pady=5)

# Inicia o loop principal da interface
root.mainloop()


