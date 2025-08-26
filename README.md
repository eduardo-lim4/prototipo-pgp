# Protótipo de Criptografia PGP em Python

Este projeto é um **protótipo didático** que simula, de forma simplificada, o funcionamento do **PGP (Pretty Good Privacy)**.  
Ele foi desenvolvido em Python para fins acadêmicos, com o objetivo de demonstrar a lógica de criptografia e descriptografia baseada em chaves pública e privada, além de introduzir
noções de integridade de dados.

---

## 🎯 Objetivo
- Simular a lógica do PGP em um ambiente interativo.
- Permitir que o usuário:

    Digite uma mensagem (até 128 caracteres).

    Veja sua mensagem "criptografada" (texto aleatório gerado).

    Receba uma chave pública e uma chave privada simuladas.

    Tente descriptografar a mensagem utilizando a chave privada correta.

    Verifique a integridade da mensagem por meio de um hash SHA-256.

    Importe/exporte mensagens e criptografias via arquivos .txt.

---

## 🧠 Funcionalidades

    Simulação de Criptografia PGP com geração de chaves aleatórias.

    Verificador de Integridade baseado em hash SHA-256.

    Importação e Exportação de Arquivos .txt com mensagens e criptografias.

    Interface Gráfica com Tkinter para facilitar a interação.

    Validação de Chave Privada para garantir acesso autorizado à mensagem.

---

## ⚙️ Tecnologias Utilizadas
- **Python 3.x** 
- Módulos padrão da biblioteca Python:
  - `string`
  - `secrets`
  - `tkinter`
  - `hashlib`

> Nenhuma biblioteca externa é necessária.

---

## 🚀 Como Executar
1. Certifique-se de ter o **Python 3** instalado.
2. Clone este repositório ou baixe os arquivos .py.
3. No terminal, execute o arquivo desejado:

python prototipo_pgp.py # Versão Terminal

python prototipo_pgp_interface.py # Versão Gráfica Inicial

python prototipo_pgp_interface_v2.py  # Versão gráfica com verificador de integridade e suporte a arquivos

---

## 📌 Exemplo de Uso (Interface Gráfica)
    Digite uma mensagem no campo indicado.

    Clique em Criptografar.

    Visualize a mensagem criptografada e as chaves geradas.

    Digite a chave privada e clique em Descriptografar.

    O programa exibirá a mensagem original e informará se a integridade foi mantida ou comprometida.
