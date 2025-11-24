import os
import logging
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps

# ----------------------------------------------------------------------
# 1. CONFIGURAÇÃO DE SEGURANÇA E LOGGING (A09)
# ----------------------------------------------------------------------

# Configuração do Logger para arquivo e console (A09)
LOG_FILE = 'security.log' # Nome do arquivo de log
logging.basicConfig(
    level=logging.INFO, # Nível mínimo a ser registrado
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),  # Grava logs em um arquivo para auditoria
        logging.StreamHandler()         # Mostra logs no console (terminal)
    ]
)
# Objeto logger que será usado em toda a aplicação (A09)
logger = logging.getLogger(__name__)

# 1.1 GESTÃO DE SEGREDOS (A02: Cryptographic Failures)
load_dotenv()
DB_USER = os.getenv("DB_USER", "default_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "default_pass")
DB_NAME = os.getenv("DB_NAME", "doacoes_app")
SECRET_KEY = os.getenv("SECRET_KEY", "SUA_CHAVE_SECRETA_PADRAO")

# Configuração da aplicação Flask
app = Flask(__name__)

# Configurações do Flask e DB
app.config['SECRET_KEY'] = SECRET_KEY # Chave para sessões (A02)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # Inicializa o Bcrypt para hashing seguro de senhas (A02)

Failed_Login_Attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutos

# ----------------------------------------------------------------------
# 2. FUNÇÕES DE SEGURANÇA (A02 e A04)
# ----------------------------------------------------------------------

def set_password(password):
    """Cria o hash seguro da senha antes de armazenar (A02)."""
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(password_hash, password):
    """Verifica se a senha fornecida corresponde ao hash armazenado (A02)."""
    return bcrypt.check_password_hash(password_hash, password)

def role_required(role):
    """Decorator para exigir login e checar permissão (A04: Insecure Design)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login')) # Se não está logado
            
            # Checa se o role do usuário é igual ao role exigido pela rota
            if session.get('user_role') != role:
                logger.error(f"Acesso NEGADO. Usuário ID {session.get('user_id')} tentou acessar área de {role}") # Log (A09)
                return "Acesso negado. Permissão insuficiente.", 403 
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----------------------------------------------------------------------
# 3. MODELOS DE DADOS
# ----------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Armazena o hash (A02)
    role = db.Column(db.String(20), nullable=False, default='voluntario') # admin, voluntario (A04)
    
    donations = db.relationship('Doacao', backref='registrador', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Doacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(80), nullable=False) 
    quantidade = db.Column(db.Integer, nullable=False)
    # Relação com a tabela User (A04)
    voluntario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 

    def __repr__(self):
        return f'<Doacao {self.tipo}>'

# Cria o banco de dados e as tabelas (Execute isso após rodar as instalações!)
with app.app_context():
    db.create_all()


# ----------------------------------------------------------------------
# 4. ROTAS DE AUTENTICAÇÃO E ADMINISTRAÇÃO (A04)
# ----------------------------------------------------------------------

@app.cli.command("create-admin") 
def create_admin():
    """Comando para criar um usuário administrador inicial."""
    admin_username = os.getenv("ADMIN_USER", "admin") 
    admin_password = os.getenv("ADMIN_PASS", "SenhaForte123") 

    with app.app_context():
        if User.query.filter_by(username=admin_username).first() is None:
            hashed_password = set_password(admin_password) # Hashing (A02)
            
            admin = User()
            admin.username = admin_username
            admin.password_hash = hashed_password
            admin.role = 'admin'
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Usuário admin '{admin_username}' criado com sucesso.") # Log (A09)
        else:
            print(f"Usuário admin '{admin_username}' já existe.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password(user.password_hash, password):
            # Login BEM-SUCEDIDO
            session['logged_in'] = True
            session['user_id'] = user.id
            session['user_role'] = user.role
            logger.info(f"Login BEM-SUCEDIDO. Usuário ID: {user.id}, Role: {user.role}") # Log (A09)
            return redirect(url_for('index'))
        else:
            # Login MAL-SUCEDIDO
            logger.warning(f"Login MAL-SUCEDIDO. Tentativa com usuário: {username}") # Log (A09)
            return "Credenciais inválidas ou usuário não encontrado.", 401
            
    return """
        <h2>Login</h2>
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Entrar">
        </form>
        <p>Use: admin / SenhaForte123 (Após rodar 'flask create-admin')</p>
        <p>Ou acesse <a href="/register_voluntario">Registrar Voluntário</a> (se for admin)</p>
    """

@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    session.clear()
    logger.info(f"Logout realizado para o Usuário ID: {user_id}") # Log (A09)
    return redirect(url_for('index'))

@app.route('/register_voluntario', methods=['GET', 'POST'])
@role_required('admin') # APENAS ADMIN PODE ACESSAR (A04)
def register_voluntario():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'voluntario')
        
        # 1. Validação de dados de entrada (A03)
        if not username or not password or len(password) < 8:
            return "Nome de usuário e senha (mínimo 8 caracteres) são obrigatórios.", 400

        if User.query.filter_by(username=username).first():
            return "Nome de usuário já existe.", 400

        # 2. Hashing Seguro (A02)
        hashed_password = set_password(password)
        
        new_user = User()
        new_user.username = username
        new_user.password_hash = hashed_password
        new_user.role = role

        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"Novo usuário criado por Admin (ID: {session.get('user_id')}). Username: {username}, Role: {role}") # Log (A09)
        return f"Voluntário/Usuário {username} criado com sucesso!", 201

    return f"""
        <h2>Registrar Novo Voluntário (Apenas Admin)</h2>
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required minlength="8"><br>
            Role (admin/voluntario): <input type="text" name="role" value="voluntario"><br>
            <input type="submit" value="Registrar">
        </form>
    """

# ----------------------------------------------------------------------
# 5. ROTAS DA APLICAÇÃO PRINCIPAL (COM SEGURANÇA INTEGRADA)
# ----------------------------------------------------------------------

@app.route('/')
def index():
    is_logged_in = session.get('logged_in', False)
    user_role = session.get('user_role', 'Convidado')
    
    # Consulta segura (A03)
    doacoes = Doacao.query.all() 
    
    return f"""
        <h1>Bem-vindo ao Gerenciamento de Doações</h1>
        <p>Status: Logado como {user_role} ({'Online' if is_logged_in else 'Offline'})</p>
        <p>Total de itens registrados: {len(doacoes)}</p>
        <p><a href="/login">Login</a> | <a href="/logout">Logout</a></p>
        {'<p><a href="/nova_doacao">Registrar Nova Doação</a></p>' if is_logged_in else '<p>Faça login para registrar doações.</p>'}
        {'<p><a href="/register_voluntario">Gerenciar Usuários (Admin)</a></p>' if user_role == 'admin' else ''}
    """

@app.route('/nova_doacao', methods=['GET', 'POST'])
@role_required('voluntario') # Protegido pelo Design Seguro (A04)
def nova_doacao():
    if request.method == 'POST':
        tipo = request.form.get('tipo')
        quantidade_str = request.form.get('quantidade')

        # 1. VERIFICAÇÃO DE EXISTÊNCIA (Obrigatório para A03)
        if not tipo or not quantidade_str:
            return "Erro: Tipo e Quantidade são campos obrigatórios.", 400

        # 2. CONVERSÃO SEGURA (A03)
        try:
            quantidade = int(quantidade_str) 
        except ValueError:
            logger.warning(f"Tentativa de registro de doação com quantidade inválida: {quantidade_str}") # Log (A09)
            return "Quantidade deve ser um número inteiro válido.", 400

        # 3. VERIFICAÇÃO DE CONTEÚDO (A03)
        if not (1 < len(tipo) < 80) or ('<' in tipo or '>' in tipo):
            logger.warning(f"Tentativa de registro de doação com tipo suspeito: {tipo}") # Log (A09)
            return "Tipo de doação inválido.", 400

        # --- FIM DA VALIDAÇÃO ---

        user_id = session.get('user_id') 

        nova = Doacao()
        nova.tipo = tipo
        nova.quantidade = quantidade
        nova.voluntario_id = user_id # Liga a doação ao usuário logado (A04)

        db.session.add(nova)
        db.session.commit()
        
        logger.info(f"Doação registrada por User ID: {user_id}. Tipo: {tipo}.") # Log (A09)
        return redirect(url_for('index'))

    return """
        <h2>Registrar Nova Doação</h2>
        <form method="post">
            <label>Tipo:</label><input type="text" name="tipo" required><br>
            <label>Quantidade:</label><input type="number" name="quantidade" required min="1"><br>
            <input type="submit" value="Registrar Doação">
        </form>
    """


if __name__ == '__main__':
    # É fundamental rodar a aplicação em modo debug=False em produção.
    # Usamos debug=True apenas para desenvolvimento.
    app.run(debug=True)