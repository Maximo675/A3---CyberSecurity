Este projeto foi desenvolvido para a disciplina de Segurança e Sitemas Computacionais, como avaliação da A3.
O sistema implementa um Gerenciador de Doações com login seguro, diferentes níveis de acesso e módulo de pagamento simulado (PIX e Cartão).

A aplicação foi construída utilizando:

- Python + Flask
- HTML + Bootstrap
- SQLite

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
