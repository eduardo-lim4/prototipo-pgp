"""
Protótipo didático de criptografia no estilo PGP (Pretty Good Privacy).


Este programa não implementa criptografia real, apenas simula o fluxo
básico de criptografia e descriptografia com chaves pública e privada,
para fins didáticos.


Fluxo:
1. Usuário digita uma frase (até 128 caracteres).
2. Programa gera um texto aleatório do mesmo tamanho simulando um ciphertext.
3. Exibe chaves pública e privada (predefinidas).
4. Pergunta se o usuário deseja descriptografar.
5. Caso sim, solicita a chave privada. Se correta, revela a mensagem original.


Notas:
- Esse protótipo não deve ser usado em cenários reais de segurança.
- Objetivo: demonstrar de forma simplificada o funcionamento do PGP.
"""

# Importação de Bibliotecas
from __future__ import annotations
import secrets
import string

# Chaves predefinidas 
PUBLIC_KEY = "PGP-DEMO-PUBLIC-KEY-123456" # Chave pública (pode ser compartilhada)
PRIVATE_KEY = "PGP-DEMO-PRIVATE-KEY-654321" # Chave privada (deve ser mantida em segredo)

# Limite máximo de caracteres da mensagem
MAX_LEN = 128
# Alfabeto usado para gerar o texto "criptografado"
ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "

def solicitar_frase(max_len: int = MAX_LEN) -> str:
    """Solicita uma frase ao usuário, garantindo que respeite o limite.


    Parameters
    ----------
    max_len : int, optional
    Número máximo de caracteres permitidos (default = 128).


    Returns
    -------
    str
    A frase digitada pelo usuário.
    """
    while True:
        frase = input(f"Digite uma frase (máx. {max_len} caracteres): ").strip()
        
        if not frase:
            print("A frase não pode ser vazia. Tente novamente.\n")
            continue

        if len(frase) > max_len:
            print(f"A frase tem {len(frase)} caracteres (o limite é {max_len}). Tente novamente.\n")
            continue

        return frase
    
def fake_encrypt(plaintext: str) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(len(plaintext)))

    """Simula a criptografia gerando texto aleatório do mesmo tamanho.


    Parameters
    ----------
    plaintext : str
    Mensagem original fornecida pelo usuário.


    Returns
    -------
    str
    Texto aleatório que simula um ciphertext.
    """

def mostrar_chaves() -> None:
    """Exibe as chaves pública e privada predefinidas.


    Notes
    -----
    Em um sistema real, a chave privada nunca seria exibida.
    """
    print("\n=== Chaves do Usuário (DEMO - estilo PGP) ===")
    print(f"Chave pública: {PUBLIC_KEY}")
    print(f"Chave privada: {PRIVATE_KEY}")
    print("(Guarde a privada com segurança. Nesta demo, ambas estão visíveis.)\n")

def deseja_descriptografar() -> bool:
    """Pergunta ao usuário se deseja descriptografar a mensagem.


    Returns
    -------
    bool
    True se o usuário respondeu afirmativamente, False caso contrário.
    """
    resp = input("Deseja descriptografar a mensagem? (sim/não): ").strip().lower()
    return resp in {"s", "sim", "y", "yes"}

def verificar_chave_privada() -> bool:
    """Verifica se a chave privada fornecida pelo usuário é válida.


    Returns
    -------
    bool
    True se a chave fornecida corresponde à chave privada correta.
    """
    tentativa = input("Digite sua chave privada: ").strip()
    return tentativa == PRIVATE_KEY

def main() -> None:
    """Executa o fluxo principal da simulação PGP.


    Etapas:
    1. Solicita frase do usuário.
    2. Gera e exibe o ciphertext simulado.
    3. Exibe as chaves pública e privada.
    4. Pergunta se deseja descriptografar.
    5. Se a chave privada correta for informada, revela a mensagem.
    """
    print("=== Protótipo de Criptografia estilo PGP (Simulação) ===\n")

    # 1) Entrada e armazenamento da mensagem
    mensagem = solicitar_frase()

    # 2) "Criptografia" visual (gera texto aleatório no lugar da mensagem)
    ciphertext = fake_encrypt(mensagem)
    print("\nMensagem armazenada com sucesso.")
    print("Ciphertext (simulado):")
    print(ciphertext)

    # 3) Exibir chaves predefinidas
    mostrar_chaves()

    # 4) Perguntar se o usuário deseja descriptografar
    if deseja_descriptografar():
        if verificar_chave_privada():
            print("\nChave privada correta. Mensagem original:")
            print(mensagem)
        else:
            print("\nChave privada incorreta. Acesso negado.")
    else:
        print("\nOk! Encerrando o programa.")

        # Executa o programa se o arquivo for rodado diretamente
if __name__ == "__main__":
    main()
