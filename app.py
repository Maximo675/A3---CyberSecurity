import os
import time
import logging
from dotenv import load_dotenv
from flask import (
    Flask, request, redirect, url_for, session, 
    render_template, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from sqlalchemy.exc import IntegrityError

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
# Usando f-string para o URI do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Variáveis de Rate Limiting (A07)
FAILED_LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutos

# Inicialização de Extensões
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # Inicializa o Bcrypt para hashing seguro de senhas (A02)


# ----------------------------------------------------------------------
# 2. FUNÇÕES DE SEGURANÇA (A02 e A04)
# ----------------------------------------------------------------------

def set_password(password):
    """Cria o hash seguro da senha antes de armazenar (A02)."""
    # decode('utf-8') é usado para garantir que o hash seja uma string
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
                flash("Você precisa estar logado para acessar esta página.", "info")
                return redirect(url_for('login')) # Se não está logado
            
            # Checa se o role do usuário é igual ao role exigido pela rota
            if session.get('user_role') != role:
                user_id = session.get('user_id', 'Unknown')
                logger.error(f"Acesso NEGADO. Usuário ID {user_id} tentou acessar área de {role}") # Log (A09)
                flash(f"Acesso negado. Permissão insuficiente. Requer: {role}", "danger")
                return redirect(url_for('index')) 
            
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
    
    # Se você tivesse um template HTML (login.html) você usaria:
    # return render_template('login.html')

    client_ip = request.remote_addr # Pega o IP do cliente
    
    # --- LÓGICA DE RATE LIMITING (A07) ---
    if client_ip in FAILED_LOGIN_ATTEMPTS:
        attempts, lock_time = FAILED_LOGIN_ATTEMPTS[client_ip]
        current_time = time.time()
        
        # 1. Checa se o IP está bloqueado
        if attempts >= MAX_ATTEMPTS and current_time < lock_time + LOCKOUT_TIME:
            remaining_time = int(lock_time + LOCKOUT_TIME - current_time)
            logger.warning(f"Acesso BLOQUEADO (A07) por rate limiting. IP: {client_ip}. Tempo restante: {remaining_time}s")
            flash(f"Acesso bloqueado por muitas tentativas. Tente novamente em {remaining_time} segundos.", "danger")
            return redirect(url_for('login'))
        
        # 2. Reseta a contagem se o tempo de bloqueio já passou
        elif attempts >= MAX_ATTEMPTS and current_time >= lock_time + LOCKOUT_TIME:
            FAILED_LOGIN_ATTEMPTS.pop(client_ip, None) # Remove ou reseta o IP


    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password(user.password_hash, password):
            # Login BEM-SUCEDIDO
            session['logged_in'] = True
            session['user_id'] = user.id
            session['user_role'] = user.role
            
            # Limpa a contagem de falhas do IP
            FAILED_LOGIN_ATTEMPTS.pop(client_ip, None) 
            
            logger.info(f"Login BEM-SUCEDIDO. Usuário ID: {user.id}, Role: {user.role}") # Log (A09)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            # Login MAL-SUCEDIDO
            
            # Incrementa o contador de falhas (A07)
            current_attempts = FAILED_LOGIN_ATTEMPTS.get(client_ip, [0, 0])[0] + 1
            
            if current_attempts >= MAX_ATTEMPTS:
                FAILED_LOGIN_ATTEMPTS[client_ip] = [current_attempts, time.time()]
                flash("Credenciais inválidas. Seu IP foi bloqueado temporariamente (A07).", "danger")
            else:
                FAILED_LOGIN_ATTEMPTS[client_ip] = [current_attempts, 0]
                attempts_left = MAX_ATTEMPTS - current_attempts
                flash(f"Credenciais inválidas ou usuário não encontrado. Tentativas restantes: {attempts_left}", "warning")
            
            logger.warning(f"Login MAL-SUCEDIDO. Tentativa com usuário: {username}. IP: {client_ip}") # Log (A09)
            return redirect(url_for('login'))
            
    return """
        <h2>Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class=flashes>
                {% for category, message in messages %}
                <li class="{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Entrar">
        </form>
        <p>Use: admin / SenhaForte123 (Após rodar 'flask create-admin')</p>
        <p>Ou acesse <a href="/register_voluntario">Registrar Voluntário</a></p>
    """


@app.route('/logout')
def logout():
    user_id = session.get('user_id', 'Unknown')
    session.clear()

    logger.info(f"Logout realizado para o Usuário ID: {user_id}") # Log (A09)
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('index'))


@app.route('/register_voluntario', methods=['GET', 'POST'])
@role_required('admin') # APENAS ADMIN PODE ACESSAR (A04)
def register_voluntario():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Garante que, se a role for omitida, seja 'voluntario' (A04)
        role = request.form.get('role', 'voluntario') 

        
        # 1. Validação de dados de entrada (A03)
        if not username or not password or len(password) < 8:
            flash("Nome de usuário e senha (mínimo 8 caracteres) são obrigatórios.", "warning")
            return redirect(url_for('register_voluntario'))

        if User.query.filter_by(username=username).first():
            flash("Nome de usuário já existe.", "danger")
            return redirect(url_for('register_voluntario'))

        # 2. Hashing Seguro (A02)
        hashed_password = set_password(password)
        
        try:
            new_user = User()
            new_user.username = username
            new_user.password_hash = hashed_password
            new_user.role = role

            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"Novo usuário criado por Admin (ID: {session.get('user_id')}). Username: {username}, Role: {role}") # Log (A09)
            flash(f"Usuário {username} criado com sucesso!", "success")
            return redirect(url_for('index'))
        except IntegrityError:
            # Caso raro onde o username foi adicionado por outro processo após a verificação
            db.session.rollback()
            flash("Erro ao registrar: nome de usuário duplicado.", "danger")
            return redirect(url_for('register_voluntario'))

    return """
        <h2>Registrar Novo Voluntário (Apenas Admin)</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class=flashes>
                {% for category, message in messages %}
                <li class="{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required minlength="8"><br>
            Role (admin/voluntario): <input type="text" name="role" value="voluntario"><br>
            <input type="submit" value="Registrar">
        </form>
        <p><a href="/">Voltar</a></p>
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
    
    # Lógica para exibir mensagens flash
    flashes = ""
    for category, message in app.extensions['flashes'].get('flashes', []):
        flashes += f'<li class="{category}">{message}</li>'

    return f"""
        <h1>Bem-vindo ao Gerenciamento de Doações</h1>
        <ul class="flashes">{flashes}</ul>
        <p>Status: Logado como {user_role} ({'Online' if is_logged_in else 'Offline'})</p>
        <p>Total de itens registrados: {len(doacoes)}</p>
        <p><a href="/login">Login</a> | <a href="/logout">Logout</a></p>
        {'<p><a href="/nova_doacao">Registrar Nova Doação</a></p>' if is_logged_in else '<p>Faça login para registrar doações.</p>'}
        {'<p><a href="/register_voluntario">Gerenciar Usuários (Admin)</a></p>' if user_role == 'admin' else ''}
        
        <h2>Doações Registradas:</h2>
        <ul>
            {''.join(f'<li>{d.tipo}: {d.quantidade} (Por Usuário {d.voluntario_id})</li>' for d in doacoes)}
        </ul>
    """

@app.route('/nova_doacao', methods=['GET', 'POST'])
@role_required('voluntario') # Protegido pelo Design Seguro (A04)
def nova_doacao():
    if request.method == 'POST':
        tipo = request.form.get('tipo')
        quantidade_str = request.form.get('quantidade')

        # 1. VERIFICAÇÃO DE EXISTÊNCIA (Obrigatório para A03)
        if not tipo or not quantidade_str:
            flash("Tipo e Quantidade são campos obrigatórios.", "warning")
            return redirect(url_for('nova_doacao'))

        # 2. CONVERSÃO SEGURA (A03)
        try:
            quantidade = int(quantidade_str)
        except ValueError:
            logger.warning(f"Tentativa de registro de doação com quantidade inválida: {quantidade_str}") # Log (A09)
            flash("Quantidade deve ser um número inteiro válido.", "danger")
            return redirect(url_for('nova_doacao'))

        # 3. VERIFICAÇÃO DE CONTEÚDO (A03: XSS Prevention)
        # Verifica se o campo 'tipo' tem um tamanho aceitável e não contém tags HTML
        if not (1 < len(tipo) < 80) or ('<' in tipo or '>' in tipo):
            logger.warning(f"Tentativa de registro de doação com tipo suspeito: {tipo}") # Log (A09)
            flash("Tipo de doação inválido. Evite caracteres especiais como '<' e '>'.", "danger")
            return redirect(url_for('nova_doacao'))

        # --- FIM DA VALIDAÇÃO ---

        user_id = session.get('user_id')

        nova = Doacao()
        nova.tipo = tipo
        nova.quantidade = quantidade
        nova.voluntario_id = user_id # Liga a doação ao usuário logado (A04)

        db.session.add(nova)
        db.session.commit()
        
        logger.info(f"Doação registrada por User ID: {user_id}. Tipo: {tipo}.") # Log (A09)
        flash("Doação registrada com sucesso!", "success")
        return redirect(url_for('index'))

    return """
        <h2>Registrar Nova Doação</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class=flashes>
                {% for category, message in messages %}
                <li class="{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <form method="post">
            <label>Tipo:</label><input type="text" name="tipo" required><br>
            <label>Quantidade:</label><input type="number" name="quantidade" required min="1"><br>
            <input type="submit" value="Registrar Doação">
        </form>
        <p><a href="/">Voltar</a></p>
    """


if __name__ == '__main__':
    # Em produção, use debug=False
    app.run(debug=True)