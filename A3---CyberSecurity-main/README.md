# A3 - Gerenciador de Doações (Projeto ACADEMICO)

Resumo:
- Projeto desenvolvido para fins educacionais (A3: Segurança de Sistemas).
- Implementa autenticação, roles (admin/voluntario), CRUD de doações e uma camada de pagamento simulada (PIX/cartão).

Requisitos Rápidos:
- Python 3.10+ (recomendado 3.11+)
- Instale dependências em um ambiente virtual: `python -m venv .venv` + `pip install -r requirements.txt`

Como rodar (local / dev):
1) Ative o ambiente virtual (Windows PowerShell):
```powershell
cd C:\Users\maxim\Downloads\A3---CyberSecurity-main\A3---CyberSecurity-main
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2) Configure o banco de dados (primeira vez):
```powershell
# Criar tabelas e usuários de teste
.\.venv\Scripts\python.exe -c "import app as appmod; app=appmod.app; db=appmod.db; User=appmod.User; bcrypt=appmod.bcrypt; app.app_context().push(); db.create_all(); u1=User(username='max', password_hash=bcrypt.generate_password_hash('rb123456').decode(), role='user'); u2=User(username='admin', password_hash=bcrypt.generate_password_hash('admin123').decode(), role='admin'); db.session.add_all([u1,u2]); db.session.commit(); print('Usuários criados: max/rb123456 (user) e admin/admin123 (admin)')"
```
3) Rode o servidor:
```powershell
$env:FLASK_DEBUG = 'true'
python app.py
```
4) Acesse em: `http://127.0.0.1:5000`

**Credenciais de teste:**
- Usuário: `max` / Senha: `rb123456` (role: user)
- Usuário: `admin` / Senha: `admin123` (role: admin)

## Cadastro de Novos Voluntários

O sistema agora permite que novos voluntários se cadastrem diretamente, sem necessidade do admin criar manualmente:

1. **Auto-cadastro**: Na página de login, clique em "Criar Conta de Voluntário"
2. **Aprovação**: O cadastro fica com status `pending` até que um administrador aprove
3. **Painel Admin**: Administradores veem o botão "Aprovar Cadastros" no menu para revisar e aprovar/rejeitar
4. **Login**: Apenas usuários com status `active` conseguem fazer login

**Fluxo de aprovação:**
- Novos cadastros → Status `pending` → Admin aprova → Status `active` → Usuário pode fazer login
- Admin pode rejeitar cadastros → Status `rejected` → Usuário não pode fazer login

Arquitetura e organização:
- `app.py` - Aplicação Flask principal
- `templates/` - Templates Jinja2 canônicos
- `static/` - CSS/JS/Assets
- `pagamentos_gateway.py` - Adapter de gateway (Sandbox + stubs para provedores)
- `legacy/` - Arquivos duplicados / versões antigas preservadas (arquivados)

Observações de segurança e manutenção:
- Não comite ambientes virtuais (`venv/`, `.venv/`) - já listados em `.gitignore`.
- Não armazene segredos no repositório; use `.env` e ferramentas de segredo para produção.
- Em produção use WSGI (gunicorn/uwsgi), HTTPS e um banco real; trate dados de cartão via tokenizador de um provedor confiável.
 - Desenvolvimento local: mantenha `FORCE_HTTPS=false`, `STRICT_HSTS=false`, `SESSION_COOKIE_SECURE=false` e acesse via `http://127.0.0.1:5000`.
 - Produção: habilite `FORCE_HTTPS=true`, `STRICT_HSTS=true`, `SESSION_COOKIE_SECURE=true` e `CSP_MODE=strict`, com assets locais.

Testes e CI:
- Rodar testes locais: `python -m pytest -q` (com venv ativo).
- CI executa bandit, pip-audit e pytest para validação.

Perfis de ambiente:
- Dev: arquivo `.env` incluído com defaults seguros para localhost.
- Prod: arquivo `.env.prod.example` com valores recomendados; copie e preencha com segredos reais.

Se você deseja que eu consolide os arquivos duplicados automaticamente (mover para `legacy/`, atualizar `.gitignore`, remover `venv/` do controle de versão), diga "Sim" e eu aplico as mudanças seguras no repositório.

Obrigado — vamos limpar e melhorar a base do projeto passo a passo.
Este projeto foi desenvolvido para a disciplina de Segurança e Sitemas Computacionais, como avaliação da A3.
O sistema implementa um Gerenciador de Doações com login seguro, diferentes níveis de acesso e módulo de pagamento simulado (PIX e Cartão).

A aplicação foi construída utilizando:

- Python + Flask
- HTML + Bootstrap
- SQLite

<<<<<<< HEAD
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



Controle de Acesso:

Admin:
- Acessa todas as funções
- Cadastra novos voluntários
- Visualiza todas as doações

Voluntário:
- Registra novas doações
- Visualiza doações
- Acessa módulo de pagamento

Gerenciamento de Doações
- Registrar novo item doado


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
=======
Campos:
- Tipo
- Quantidade
- Responsável (automático pelo login)

Listagem com:
- ID
- Tipo
- Quantidade
- Registrado por

Módulo de Pagamento (Simulado)

Inclui dois fluxos:
- PIX (simulado)
Gera:
- TxID
- QR Code (fake)
- Mensagem de sucesso

Cartão (simulado)
- Validação mínima
Gera:
- TxID
- Status aprovado / erro simulado

Importante: Nenhum dado real de cartão é armazenado.

Interface

- Baseada em Bootstrap
- Navbar adaptável (mobile)
- Layout padronizado em base.html

Templates:
- index
- login
- registro de voluntário
- nova doação
- pagamento

Estrutura de Pastas

/
│── app.py
│── requirements.txt
│── security.log
│── instance/
│      └── doacoes_app.db
│── templates/
       ├── base.html
       ├── index.html
       ├── login.html
       ├── nova_doacao.html
       ├── pagamento.html
       └── register_voluntario.html

Segurança Implementada (OWASP Top 10)
       
| OWASP                        | Implementação                                    |
| ---------------------------- | ------------------------------------------------ |
| A02 – Cryptographic Failures | Hash seguro (bcrypt), .env, SECRET_KEY           |
| A03 – Injection              | Validações, conversões seguras, sanitização      |
| A04 – Insecure Design        | Controle de sessão por função (admin/voluntário) |
| A09 – Logging                | Logs para logins, erros, tentativas suspeitas    |
| Outros                       | Proteção de rotas com decorators                 |




