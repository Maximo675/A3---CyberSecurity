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

Como executar o projeto:

1. Instale as dependências:
   bash
   pip install flask flask_sqlalchemy flask_bcrypt python-dotenv

2. Execute o script para criar o admin (opcional):
   bash
   flask create-admin

3. Inicie o servidor:
   bash
   python app.py

4. Acesse no navegador:
   http://127.0.0.1:5000/
   
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
