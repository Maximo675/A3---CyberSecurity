Sistema de Gerenciamento de Doações

Este repositório contém o projeto desenvolvido para a disciplina de Segurança e Sistemas Operacionais.
O objetivo é implementar um sistema simples de gerenciamento de doações utilizando Flask, SQLite e boas práticas de segurança.

Funcionalidades:

- Sistema de login (admin e voluntário)
- Cadastro de voluntários (somente admin)
- Registro de doações (somente voluntário)
- Listagem das doações registradas
- Controle de sessão com Flask
- Hash seguro de senhas (bcrypt)
- Validação de dados e prevenção de erros comuns
- Registro de logs de segurança

Tecnologias Utilizadas:

- Python 3
- Flask
- Flask-Bcrypt
- Flask-SQLAlchemy
- SQLite
- HTML / Jinja2 / Bootstrap

Como executar o projeto (modo seguro):

1. Crie um ambiente virtual e instale as dependências:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Defina variáveis de ambiente obrigatórias (ex.: em `.env`):
   - SECRET_KEY: chave secreta forte (obrigatório)
   - ADMIN_USER: nome do usuário admin (opcional)
   - ADMIN_PASS: senha do admin (obrigatório para `create-admin`)

   Exemplo (PowerShell):
   ```powershell
   $env:SECRET_KEY = 'uma_chave_secreta_muito_forte'
   $env:ADMIN_USER = 'admin'
   $env:ADMIN_PASS = 'UmaSenhaForte!123'
   ```

3. Crie o admin (após definir as variáveis):
   ```powershell
   flask create-admin
   ```

4. Inicie o servidor em modo desenvolvimento (apenas para teste local):
   ```powershell
   $env:FLASK_DEBUG = 'true'
   python app.py
   ```

5. Em produção, garanta que `FLASK_DEBUG` não esteja ativado e execute com WSGI (gunicorn/uwsgi) e HTTPS.
   
Estrutura do Projeto

/instance
  └── doacoes_app.db       # Banco de dados

/templates
  ├── base.html
  ├── index.html
  ├── login.html
  ├── nova_doacao.html
  └── register_voluntario.html

app.py                      # Arquivo principal
security.log                # Logs de segurança

*Observação

Este projeto foi desenvolvido exclusivamente para fins acadêmicos, com foco em princípios de segurança, não sendo recomendado para uso em produção sem ajustes adicionais.
