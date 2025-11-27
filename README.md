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

6. Atualizando o banco de dados (novo modelo de transactions):
   - Se estiver usando o banco SQLite de desenvolvimento (`instance/doacoes_app.db`), delete o arquivo e reinicie a aplicação para recriar as tabelas com o novo modelo `Transaction`.
   - Em produção, use uma ferramenta de migração (Alembic/Flask-Migrate) para aplicar mudanças no schema sem perder dados.
   
Database migrations (Flask-Migrate)
---------------------------------
1) Install migration tool (already added to requirements):

```
pip install Flask-Migrate
```

2) Initialize migrations (only once):

```
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

3) For subsequent schema changes, use `flask db migrate` and `flask db upgrade`.
 
Testing and CI
--------------
Run tests locally with pytest (from project root, with venv active):

```powershell
& ".\venv\Scripts\python.exe" -m pytest -q
```

The CI pipeline (`.github/workflows/ci.yml`) runs `pip-audit`, `bandit`, and `pytest` for each push and PR to `main`.
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

PIX Sandbox e Testes de Pagamento
---------------------------------
Para testar o fluxo PIX em modo de desenvolvimento, siga estes passos:

- Gere um PIX no formulário de pagamentos (somente disponível para voluntários logados).
- A aplicação criará uma transação pendente e irá redirecionar para a página de detalhes da transação com o QR Code.
- Para simular a confirmação de pagamento (somente para testes), clique no botão "Simular Pagamento (Dev)" — isso fará uma requisição interna de webhook para atualizar o status da transação.

Webhook para Confirmação de Pagamento
-------------------------------------
Um endpoint foi adicionado para simular as confirmações que um gateway de pagamento enviaria, em ambiente real:

POST /webhook/payment

Payload JSON esperado: {"tx_id": "<tx-id>", "status": "confirmed"}

O endpoint verifica opcionalmente o header `X-WEBHOOK-SECRET` (configure a variável de ambiente `PAYMENT_WEBHOOK_SECRET` em produção) para validar a origem da requisição.

Importante: Em ambientes de produção, substitua completamente o módulo `pagamentos.py` por integrações com um gateway de pagamentos real e NUNCA armazene dados sensíveis do cartão em texto puro.
