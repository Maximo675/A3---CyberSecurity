import os
import logging
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, session, render_template, flash
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
            session['logged_in'] = True
            session['user_id'] = user.id
            session['user_role'] = user.role
            logger.info(f"Login BEM-SUCEDIDO. Usuário ID: {user.id}, Role: {user.role}")
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"Login MAL-SUCEDIDO. Tentativa com usuário: {username}")
            flash('Credenciais inválidas ou usuário não encontrado.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')




@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    session.clear()
    logger.info(f"Logout realizado para o Usuário ID: {user_id}")
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('index'))


@app.route('/register_voluntario', methods=['GET', 'POST'])
@role_required('admin')
def register_voluntario():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'voluntario')

        if not username or not password or len(password) < 8:
            flash("Nome de usuário e senha (mínimo 8 caracteres) são obrigatórios.", "warning")
            return redirect(url_for('register_voluntario'))

        if User.query.filter_by(username=username).first():
            flash("Nome de usuário já existe.", "danger")
            return redirect(url_for('register_voluntario'))

        hashed_password = set_password(password)

        new_user = User(
            username=username,
            password_hash=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        logger.info(
            f"Novo usuário criado por Admin (ID: {session.get('user_id')}). "
            f"Username: {username}, Role: {role}"
        )
        flash(f"Usuário {username} criado com sucesso!", "success")
        return redirect(url_for('index'))

    return render_template('register_voluntario.html')


# ----------------------------------------------------------------------
# 5. ROTAS DA APLICAÇÃO PRINCIPAL (COM SEGURANÇA INTEGRADA)
# ----------------------------------------------------------------------

@app.route('/')
def index():
    is_logged_in = session.get('logged_in', False)
    user_role = session.get('user_role', 'Convidado')
    doacoes = Doacao.query.all()

    return render_template(
        'index.html',
        is_logged_in=is_logged_in,
        user_role=user_role,
        doacoes=doacoes
    )





@app.route('/nova_doacao', methods=['GET', 'POST'])
@role_required('voluntario')
def nova_doacao():
    if request.method == 'POST':
        tipo = request.form.get('tipo')
        quantidade_str = request.form.get('quantidade')

        if not tipo or not quantidade_str:
            flash("Tipo e Quantidade são campos obrigatórios.", "warning")
            return redirect(url_for('nova_doacao'))

        try:
            quantidade = int(quantidade_str)
        except ValueError:
            logger.warning(f"Tentativa de registro de doação com quantidade inválida: {quantidade_str}")
            flash("Quantidade deve ser um número inteiro válido.", "danger")
            return redirect(url_for('nova_doacao'))

        if not (1 < len(tipo) < 80) or ('<' in tipo or '>' in tipo):
            logger.warning(f"Tentativa de registro de doação com tipo suspeito: {tipo}")
            flash("Tipo de doação inválido.", "danger")
            return redirect(url_for('nova_doacao'))

        user_id = session.get('user_id')

        nova = Doacao(
            tipo=tipo,
            quantidade=quantidade,
            voluntario_id=user_id
        )

        db.session.add(nova)
        db.session.commit()

        logger.info(f"Doação registrada por User ID: {user_id}. Tipo: {tipo}.")
        flash("Doação registrada com sucesso!", "success")
        return redirect(url_for('index'))

    return render_template('nova_doacao.html')




if __name__ == '__main__':
    # É fundamental rodar a aplicação em modo debug=False em produção.
    # Usamos debug=True apenas para desenvolvimento.
    app.run(debug=True)