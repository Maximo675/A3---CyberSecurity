# A3 - Gerenciador de Doações (Projeto ACADEMICO)

Resumo:
- Projeto desenvolvido para fins educacionais (A3: Segurança de Sistemas).
- Implementa autenticação, roles (admin/voluntario), CRUD de doações e uma camada de pagamento simulada (PIX/cartão).

Requisitos Rápidos:
- Python 3.10+ (recomendado 3.11+)
- Instale dependências em um ambiente virtual: `python -m venv .venv` + `pip install -r requirements.txt`

Como rodar (local / dev):
1) Ative o ambiente virtual (Windows PowerShell):
```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2) Configure variáveis de ambiente (ex.: `SECRET_KEY`, `ADMIN_PASS`) — veja `.env.example`.
3) Crie o admin: `flask create-admin` (requer `ADMIN_PASS`)
4) Rode o app: `python app.py` (ou `FLASK_DEBUG=true python app.py` para dev)

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

Testes e CI:
- Rodar testes locais: `python -m pytest -q` (com venv ativo).
- CI executa bandit, pip-audit e pytest para validação.

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
=======
Boas práticas de segurança:

- Hash de senha (bcrypt)
- Controle de sessão
- Controle de acesso por função (admin/voluntário)
- Validações de entrada (OWASP A03)
- Proteção contra endpoint overrides (A04)
- Logging centralizado (A09)
- Separação de templates e instância do banco

Funcionalidades Principais

Autenticação:

- Login com validação segura
- Logout
- Senhas armazenadas com hash bcrypt
- Controle de tentativas inválidas
>>>>>>> cda3a807b2b4935d14ac6d647479cf4c5d983c88

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

<<<<<<< HEAD
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


Como Executar o Projeto Localmente
1 - Instale o Python

2 - Instale as dependências

No terminal, rode:
pip install -r requirements.txt

3 - Rode o app
python app.py

4 - Acesse no navegador:
http://127.0.0.1:5000


Criando o usuário administrador

Antes de usar o sistema, execute:
flask create-admin

Criará:

- Usuário: admin

- Senha: SenhaForte123

Depois você pode adicionar voluntários pelo próprio sistema.
>>>>>>> cda3a807b2b4935d14ac6d647479cf4c5d983c88
