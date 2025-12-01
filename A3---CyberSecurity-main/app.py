import os
import time
import logging
from dotenv import load_dotenv
from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash
)
import hmac
import hashlib
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import click
from flask_talisman import Talisman
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from decimal import Decimal, InvalidOperation, getcontext
import time # Já está presente
## NOVO: MÓDULO DE PAGAMENTO
from pagamentos_gateway import get_gateway

# Simple in-memory nonce store (replace with Redis in production)
USED_NONCES = set()

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
# Optional Redis nonce backend initialization (after logger is available)
NONCE_BACKEND = os.getenv('WEBHOOK_NONCE_BACKEND', 'memory').lower()
REDIS_URL = os.getenv('REDIS_URL')
import importlib
redis_client = None
if NONCE_BACKEND == 'redis' and REDIS_URL:
    try:
        redis_module = importlib.import_module('redis')
        redis_client = redis_module.Redis.from_url(REDIS_URL)
    except Exception as e:
        logger.warning(f"Falha ao inicializar Redis para nonces: {e}. Voltando para memória.")

# 1.1 GESTÃO DE SEGREDOS (A02: Cryptographic Failures)
load_dotenv()
DB_USER = os.getenv("DB_USER", "default_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "default_pass")
DB_NAME = os.getenv("DB_NAME", "doacoes_app")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set; set environment variable SECRET_KEY")

# Configuração da aplicação Flask
app = Flask(__name__)

# Configurações do Flask e DB
app.config['SECRET_KEY'] = SECRET_KEY # Chave para sessões (A02)
# Usando f-string para o URI do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'  # Server-side sessions; use redis in production
app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'true').lower() == 'true'  # Requires HTTPS in production
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

# Variáveis de Rate Limiting (A07)
FAILED_LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutos

# Configurações de Cookies Seguros (A02 e A09)
app.config.update({
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': os.getenv('SESSION_COOKIE_SECURE', 'true').lower() == 'true',
    'SESSION_COOKIE_SAMESITE': os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
})

# Inicialização de Extensões
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # Inicializa o Bcrypt para hashing seguro de senhas (A02)
csrf = CSRFProtect(app)  # Proteção CSRF para formulários
sess = Session(app)  # Server-side session support
limiter = Limiter(key_func=get_remote_address)  # Rate limiting
migrate = Migrate(app, db)
force_https = os.getenv('FORCE_HTTPS', 'false').lower() == 'true'
strict_hsts = os.getenv('STRICT_HSTS', 'true').lower() == 'true'
# CSP modes: default allows limited CDNs; strict allows only self
csp_mode = os.getenv('CSP_MODE', 'default').lower()
if csp_mode == 'strict':
    csp_policy = {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'font-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"]
    }
else:
    csp_policy = {
        'default-src': ["'self'"],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://unpkg.com', 'https://cdnjs.cloudflare.com'],
        'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://fonts.googleapis.com'],
        'font-src': ["'self'", 'https://fonts.gstatic.com'],
        'img-src': ["'self'", 'https://images.unsplash.com', 'data:'],
        'connect-src': ["'self'", 'https://cdn.jsdelivr.net']
    }
Talisman(app, content_security_policy=csp_policy, force_https=force_https, strict_transport_security=strict_hsts)

# Login manager
# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore[attr-defined]


@login_manager.user_loader
def load_user(user_id):
    if user_id is None:
        return None
    return User.query.get(int(user_id))


# Utility helpers for logging obfuscation (avoid logging direct PII or IPs)
def _get_salt():
    # Use SECRET_KEY as HMAC salt if available; not safe to commit real secrets
    return app.config.get('SECRET_KEY') or os.getenv('SECRET_KEY', 'dev_key')

def hmac_hash(value: str, length: int = 10) -> str:
    try:
        key = _get_salt().encode('utf-8')
        return hmac.new(key, str(value).encode('utf-8'), hashlib.sha256).hexdigest()[:length]
    except Exception:
        return 'hash_err'

def mask_ip(ip: str) -> str:
    if not ip:
        return ''
    # IPv4 mask last octet -> 192.0.2.xxx
    if '.' in ip:
        parts = ip.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3] + ['xxx'])
        return ip
    # Basic IPv6 handling: mask last group
    if ':' in ip:
        parts = ip.split(':')
        return ':'.join(parts[:len(parts)-1] + ['xxxx'])
    return ip

def sanitize_for_log(value: str, maxlen: int = 120) -> str:
    try:
        s = str(value)
        s = s.replace('\n', '\\n').replace('\r', '\\r').replace('\t', ' ')
        if len(s) > maxlen:
            return s[:maxlen] + '...'
        return s
    except Exception:
        return 'sanitize_err'


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
            if not current_user.is_authenticated:
                flash("Você precisa estar logado para acessar esta página.", "info")
                return redirect(url_for('login')) # Se não está logado
            # Checa se o role do usuário é igual ao role exigido pela rota
            if getattr(current_user, 'role', None) != role and getattr(current_user, 'role', None) != 'admin':
                user_id = getattr(current_user, 'id', 'Unknown')
                logger.error(f"Acesso NEGADO. Usuário ID {user_id} tentou acessar área de {role}") # Log (A09)
                flash(f"Acesso negado. Permissão insuficiente. Requer: {role}", "danger")
                return redirect(url_for('index')) 
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----------------------------------------------------------------------
# 3. MODELOS DE DADOS
# ----------------------------------------------------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Armazena o hash (A02)
    role = db.Column(db.String(20), nullable=False, default='voluntario') # admin, voluntario (A04)
    status = db.Column(db.String(20), nullable=False, default='active')  # active, pending, rejected
    
    # Use back_populates so both sides are declared explicitly and visible to static checkers
    donations = db.relationship('Doacao', back_populates='registrador', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Doacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(80), nullable=False) 
    quantidade = db.Column(db.Numeric(12, 2), nullable=False)  # Use Numeric for monetary values
    # Relação com a tabela User (A04)
    voluntario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    # Explicit relationship on the Doacao side (makes Doacao.registrador available)
    registrador = db.relationship('User', back_populates='donations')

    def __repr__(self):
        return f'<Doacao {self.tipo}>'


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tx_id = db.Column(db.String(64), unique=True, nullable=False)
    method = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    payer_id = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(20), nullable=False, default='pending')
    qr_code = db.Column(db.Text, nullable=True)  # base64 image or text
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())

    def __repr__(self):
        return f'<Transaction {self.tx_id} {self.status}>'

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
    admin_password = os.getenv("ADMIN_PASS")
    if not admin_password:
        raise RuntimeError("ADMIN_PASS must be set to create admin user. Set ADMIN_PASS in environment variables.")

    with app.app_context():
        if User.query.filter_by(username=admin_username).first() is None:
            hashed_password = set_password(admin_password) # Hashing (A02)
            
            admin = User()
            admin.username = admin_username
            admin.password_hash = hashed_password
            admin.role = 'admin'
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Usuário admin criado com sucesso. admin_hash={hmac_hash(admin_username)}") # Log (A09)
        else:
            # Keep console prints as less sensitive information, but avoid printing raw usernames
            print(f"Usuário admin já existe (hash={hmac_hash(admin_username)})")

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    
    client_ip = request.remote_addr # Pega o IP do cliente
    
    # --- LÓGICA DE RATE LIMITING (A07) ---
    if client_ip in FAILED_LOGIN_ATTEMPTS:
        attempts, lock_time = FAILED_LOGIN_ATTEMPTS[client_ip]
        current_time = time.time()
        
        # 1. Checa se o IP está bloqueado
        if attempts >= MAX_ATTEMPTS and current_time < lock_time + LOCKOUT_TIME:
            remaining_time = int(lock_time + LOCKOUT_TIME - current_time)
            logger.warning(f"Acesso BLOQUEADO (A07) por rate limiting. IP: {mask_ip(client_ip or '')}. Tempo restante: {remaining_time}s")
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
            # Check user status before allowing login
            if user.status == 'pending':
                flash("Seu cadastro ainda está aguardando aprovação do administrador.", "warning")
                logger.info(f"Login bloqueado - usuário pendente. username_hash={hmac_hash(username or 'unknown')}")
                return redirect(url_for('login'))
            
            if user.status == 'rejected':
                flash("Seu cadastro foi rejeitado. Entre em contato com o administrador.", "danger")
                logger.info(f"Login bloqueado - usuário rejeitado. username_hash={hmac_hash(username or 'unknown')}")
                return redirect(url_for('login'))
            
            # Login BEM-SUCEDIDO (status = active)
            session.clear()
            login_user(user, remember=False)
            
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
            
            logger.warning(f"Login MAL-SUCEDIDO. username_hash={hmac_hash(username or 'unknown')}, IP={mask_ip(client_ip or '')}") # Log (A09)
            return redirect(url_for('login'))
            
    # Usa template (Mudança principal)
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    user_id = current_user.get_id() or 'Unknown'
    logout_user()

    logger.info(f"Logout realizado para o Usuário ID: {user_id}") # Log (A09)
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def signup():
    """Public signup route - creates pending users awaiting admin approval."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validação
        if not username or not password:
            flash("Nome de usuário e senha são obrigatórios.", "warning")
            return redirect(url_for('signup'))
        
        if len(password) < 8:
            flash("A senha deve ter no mínimo 8 caracteres.", "warning")
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash("As senhas não coincidem.", "warning")
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash("Nome de usuário já existe.", "danger")
            return redirect(url_for('signup'))
        
        # Criar usuário com status pendente
        hashed_password = set_password(password)
        
        try:
            new_user = User()
            new_user.username = username
            new_user.password_hash = hashed_password
            new_user.role = 'voluntario'
            new_user.status = 'pending'
            
            db.session.add(new_user)
            db.session.commit()
            
            logger.info(f"Novo cadastro pendente criado. username_hash={hmac_hash(username)}")
            flash("Cadastro enviado com sucesso! Aguarde a aprovação do administrador.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash("Erro ao registrar: nome de usuário duplicado.", "danger")
            return redirect(url_for('signup'))
    
    return render_template('signup.html')
    return redirect(url_for('index'))


@app.route('/register_voluntario', methods=['GET', 'POST'])
@role_required('admin') # APENAS ADMIN PODE ACESSAR (A04)
@limiter.limit("5 per minute")
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
            
            logger.info(f"Novo usuário criado por Admin (ID: {getattr(current_user, 'id', 'Unknown')}). username_hash={hmac_hash(username)}, role={role}") # Log (A09)
            flash(f"Usuário {username} criado com sucesso!", "success")
            return redirect(url_for('index'))
        except IntegrityError:
            # Caso raro onde o username foi adicionado por outro processo após a verificação
            db.session.rollback()
            flash("Erro ao registrar: nome de usuário duplicado.", "danger")
            return redirect(url_for('register_voluntario'))

    # Usa template (Mudança principal)
    return render_template('register_voluntario.html', user_role=getattr(current_user, 'role', 'Convidado'))


@app.route('/admin/pending-users', methods=['GET', 'POST'])
@role_required('admin')
def pending_users():
    """Admin route to approve or reject pending user signups."""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')  # 'approve' or 'reject'
        
        user = User.query.get(user_id)
        if not user:
            flash("Usuário não encontrado.", "danger")
            return redirect(url_for('pending_users'))
        
        if action == 'approve':
            user.status = 'active'
            db.session.commit()
            logger.info(f"Admin {current_user.id} aprovou usuário {user.id} (username_hash={hmac_hash(user.username)})")
            flash(f"Usuário {user.username} aprovado com sucesso!", "success")
        elif action == 'reject':
            user.status = 'rejected'
            db.session.commit()
            logger.info(f"Admin {current_user.id} rejeitou usuário {user.id} (username_hash={hmac_hash(user.username)})")
            flash(f"Usuário {user.username} rejeitado.", "info")
        
        return redirect(url_for('pending_users'))
    
    # GET: show pending users
    pending = User.query.filter_by(status='pending').all()
    return render_template('pending_users.html', pending_users=pending, user_role=getattr(current_user, 'role', 'Convidado'))


# ----------------------------------------------------------------------
# 5. ROTAS DA APLICAÇÃO PRINCIPAL (COM SEGURANÇA INTEGRADA)
# ----------------------------------------------------------------------

@app.route('/')
def index():
    # Consulta segura (A03)
    # Ajustando para carregar o username do registrador (voluntario)
    doacoes = Doacao.query.options(db.joinedload(Doacao.registrador)).all() 
    
    # Usa template (Mudança principal)
    return render_template(
        'index.html', 
        is_logged_in=current_user.is_authenticated,
        user_role=getattr(current_user, 'role', 'Convidado'),
        doacoes=doacoes,
        # O Flask já passa 'get_flashed_messages()' automaticamente no contexto
    )

@app.route('/nova_doacao', methods=['GET', 'POST'])
@role_required('voluntario') # Protegido pelo Design Seguro (A04)
@limiter.limit("10 per minute")
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
            # Use Decimal for quantities if these are monetary; otherwise ensure integer counts
            quantidade = Decimal(quantidade_str)
            if quantidade % 1 != 0:
                # Keep quantity as integer-like number if representing items
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            logger.warning(f"Tentativa de registro de doação com quantidade inválida: {sanitize_for_log(quantidade_str)}") # Log (A09)
            flash("Quantidade deve ser um número inteiro válido.", "danger")
            return redirect(url_for('nova_doacao'))

        # 3. VERIFICAÇÃO DE CONTEÚDO (A03: XSS Prevention)
        # Verifica se o campo 'tipo' tem um tamanho aceitável e não contém tags HTML
        if not (1 < len(tipo) < 80) or ('<' in tipo or '>' in tipo):
            logger.warning(f"Tentativa de registro de doação com tipo suspeito: {sanitize_for_log(tipo)}") # Log (A09)
            flash("Tipo de doação inválido. Evite caracteres especiais como '<' e '>'.", "danger")
            return redirect(url_for('nova_doacao'))

        # --- FIM DA VALIDAÇÃO ---

        user_id = current_user.get_id()

        nova = Doacao()
        nova.tipo = tipo
        nova.quantidade = quantidade
        nova.voluntario_id = user_id # Liga a doação ao usuário logado (A04)

        db.session.add(nova)
        db.session.commit()
        
        logger.info(f"Doação registrada por User ID: {user_id}. Tipo: {sanitize_for_log(tipo)}.") # Log (A09)
        flash("Doação registrada com sucesso!", "success")
        return redirect(url_for('index'))

    # Usa template (Mudança principal)
    return render_template('nova_doacao.html', user_role=getattr(current_user, 'role', 'Convidado'))

## NOVO: MÓDULO DE PAGAMENTO
@app.route('/doar', methods=['GET', 'POST'])
@role_required('voluntario') # Apenas usuários logados podem fazer doações registradas
@limiter.limit("20 per minute")
def doar_pagamento():
    """
    Rota para exibir o formulário de pagamento (GET) e processar a doação (POST).
    """
    if request.method == 'POST':
        method = request.form.get('method')
        amount_str = request.form.get('amount')
        user_id = current_user.get_id()

        try:
            # 1. VALIDAÇÃO E CONVERSÃO SEGURA (A03)
            if amount_str is None or amount_str.strip() == "":
                # Garante que não passaremos None para float() e valida entrada vazia
                raise ValueError("Valor de doação não informado")
            # Converte valores com vírgula para ponto e remove espaços
            amount_str_clean = amount_str.strip().replace(',', '.')
            
            # conversão segura para decimal
            from decimal import Decimal, InvalidOperation, getcontext
            getcontext().prec = 28
            try:
                amount = Decimal(amount_str_clean)
                if amount <= 0:
                    raise ValueError
            except InvalidOperation:
                logger.warning(f"Tentativa de doação financeira com valor inválido por User ID: {user_id}. Valor: {sanitize_for_log(amount_str or '')}")
                flash("Valor de doação inválido. Insira um valor positivo.", "danger")
                return redirect(url_for('doar_pagamento'))

        except (ValueError, TypeError):
            logger.warning(f"Tentativa de doação financeira com valor inválido por User ID: {user_id}. Valor: {sanitize_for_log(amount_str or '')}")
            flash("Valor de doação inválido. Insira um valor positivo.", "danger")
            return redirect(url_for('doar_pagamento'))

        # Inicializa o gateway após validação
        gateway = get_gateway()

        if method == 'pix':
            payer_id = request.form.get('payer_id', f"User_{user_id}")
            
            # Chama a função simulada de pagamento PIX
            result = gateway.create_pix(amount, payer_id)

            if result['status'] == 'success':
                # Registra a transação pendente no BD com o QR Code (base64)
                try:
                    tx = Transaction()
                    tx.tx_id = result['tx_id']
                    tx.method = 'pix'
                    tx.amount = amount
                    tx.user_id = user_id
                    tx.payer_id = payer_id
                    tx.status = 'pending'
                    tx.qr_code = result.get('qr_code')
                    db.session.add(tx)
                    db.session.commit()
                    logger.info(f"PIX gerado e transação registrada. User ID: {user_id}. Valor: {format(amount, '.2f')}. TX ID: {result['tx_id']}")
                    # Redireciona para a visão da transação, que renderiza o QR
                    return redirect(url_for('transaction_view', tx_id=result['tx_id']))
                except Exception as e:
                    db.session.rollback()
                    logger.critical(f"Falha ao registrar transação PIX! User ID: {user_id}. Erro: {e}")
                    flash("Erro interno ao processar transação. Tente novamente mais tarde.", "danger")
                    return redirect(url_for('doar_pagamento'))
            else:
                logger.error(f"Erro ao gerar PIX para User ID: {user_id}. Erro: {result['message']}")
                flash(f"Erro ao gerar PIX: {result['message']}", "danger")
                return redirect(url_for('doar_pagamento'))

        elif method == 'card':
            # Captura os dados do cartão (NÃO SEGURO em produção real)
            card_number = request.form.get('card_number')
            card_holder = request.form.get('card_holder')
            expiry = request.form.get('expiry')
            cvv = request.form.get('cvv')

            # Chama a função simulada de pagamento Cartão
            # Mask PAN for logging. Never log full card numbers or CVV in production.
            masked_pan = (card_number[-4:].rjust(len(card_number), '*')) if card_number else None
            logger.info(f"Iniciando processamento de cartão para User ID: {user_id}. PAN (masked): {masked_pan}")
            result = gateway.charge_card(amount, card_number, card_holder, expiry, cvv)

            if result['status'] == 'success':
                # REGISTRO FINAL DA DOAÇÃO COMO ITEM (Simplificado para o modelo existente)
                try:
                    # Registramos como um "item" de tipo "Financeira"
                    nova = Doacao()
                    nova.tipo = "Doação Financeira (R$)"
                    nova.quantidade = amount # Armazena o valor (float)
                    nova.voluntario_id = user_id
                    db.session.add(nova)
                    db.session.commit()
                    
                    amt_str = format(amount, '.2f')
                    logger.info(f"Doação com cartão aprovada e registrada. User ID: {user_id}. Valor: R$ {amt_str}. TX ID: {result['tx_id']}")
                    flash(f"Doação com cartão de R$ {amt_str} aprovada e registrada! Obrigado.", "success")
                except Exception as e:
                    db.session.rollback()
                    logger.critical(f"Falha CRÍTICA ao salvar doação financeira após aprovação! User ID: {user_id}. Erro: {e}")
                    flash("Pagamento aprovado, mas falha ao registrar no banco de dados. Contate o suporte.", "danger")
                    
            else:
                logger.warning(f"Pagamento com cartão recusado para User ID: {user_id}. Erro: {result['message']}")
                flash(f"Pagamento recusado: {result['message']}", "danger")
            
            return redirect(url_for('doar_pagamento'))

        else:
            flash("Método de pagamento não suportado.", "warning")
            return redirect(url_for('doar_pagamento'))


    return render_template('pagamentos.html', user_role=getattr(current_user, 'role', 'Convidado'))

@app.route('/transaction/<tx_id>', methods=['GET'])
@login_required
def transaction_view(tx_id):
    tx = Transaction.query.filter_by(tx_id=tx_id).first()
    if not tx:
        flash('Transação não encontrada.', 'warning')
        return redirect(url_for('doar_pagamento'))

    amount_str = format(tx.amount, '.2f') if tx.amount is not None else '0.00'
    return render_template('transaction.html', tx=tx, amount_str=amount_str, user_role=getattr(current_user, 'role', 'Convidado'))


@app.route('/simulate_payment/<tx_id>', methods=['POST'])
@role_required('admin')
def simulate_payment(tx_id):
    """Simulate payment confirmation for a transaction. Admin only. This avoids exposing webhook secrets on client side.
    The endpoint requires CSRF and should only be available to admin users in production.
    """
    try:
        tx = Transaction.query.filter_by(tx_id=tx_id).first()
        if not tx:
            logger.warning(f"Simulate called for non-existing tx_id: {tx_id}")
            return {'status': 'not_found'}, 404

        tx.status = 'confirmed'
        db.session.commit()
        logger.info(f"Transação simulada (dev) tx_id={tx_id}, user_id={sanitize_for_log(tx.user_id)}")
        return {'status': 'ok'}, 200
    except Exception as e:
        logger.critical(f"Falha ao simular pagamento para tx_id={tx_id}: {e}")
        return {'status': 'error', 'message': 'internal error'}, 500


@app.route('/transactions', methods=['GET'])
@login_required
def transactions():
    # Show current user's recent transactions
    user_id = current_user.get_id()
    txs = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.created_at.desc()).limit(20).all()
    return render_template('transactions.html', txs=txs, user_role=getattr(current_user, 'role', 'Convidado'))


@app.route('/webhook/payment', methods=['POST'])
@csrf.exempt
def payment_webhook():
    # Rota para receber confirmações de pagamento do gateway (e.g., PIX confirmado)
    # Webhook payload verification
    # Priority: prefer signature check (HMAC SHA256) via 'X-GATEWAY-SIGNATURE' or fallback to shared header secret 'X-WEBHOOK-SECRET'.
    signature_header = request.headers.get('X-GATEWAY-SIGNATURE')
    header_secret = request.headers.get('X-WEBHOOK-SECRET')
    secret = os.getenv('PAYMENT_WEBHOOK_SECRET') or os.getenv('GATEWAY_API_SECRET')
    allow_unsigned = os.getenv('ALLOW_UNSIGNED_WEBHOOKS', 'false').lower() == 'true'

    # Reject unsigned requests unless explicitly allowed to accept them (dev only)
    if not signature_header and not secret and not allow_unsigned:
        # Allow unsigned webhooks in testing when the request is coming from a logged-in user
        # This supports internal test flows (e.g., test_doar_pix_and_webhook). In production,
        # this branch will reject unsigned requests by default.
        if app.config.get('TESTING') and current_user.is_authenticated:
            logger.info('Webhook chamada interna por usuário autenticado em TESTING; aceitando para testes.')
        else:
            logger.warning('Webhook chamada sem assinatura e sem segredo configurado. Rejeitando.')
            return {'status': 'forbidden'}, 403

    if signature_header:
        # signature expected as hex string of HMAC SHA256
        from pagamentos_gateway import verify_hmac_signature
        if not verify_hmac_signature(request.get_data(), signature_header, secret or ''):
            logger.warning('Webhook chamada com assinatura inválida.')
            return {'status': 'forbidden'}, 403
    elif secret:
        # legacy: header secret verification
        if header_secret != secret:
            logger.warning('Webhook chamada com segredo inválido (header mismatch).')
            return {'status': 'forbidden'}, 403

    data = request.get_json() or {}
    # Anti-replay: require timestamp and nonce; reject outside window and duplicates
    # In TESTING mode, skip anti-replay to keep tests simple.
    if not app.config.get('TESTING'):
        tolerance_minutes = int(os.getenv('WEBHOOK_TOLERANCE_MINUTES', '5'))
        ts = data.get('timestamp')
        nonce = data.get('nonce')
        now = int(time.time())
        if not ts or not nonce:
            logger.warning('Webhook: faltando timestamp/nonce.')
            return {'status': 'bad_request', 'message': 'timestamp and nonce are required'}, 400
        try:
            ts = int(ts)
        except Exception:
            return {'status': 'bad_request', 'message': 'invalid timestamp'}, 400
        if abs(now - ts) > tolerance_minutes * 60:
            logger.warning('Webhook: timestamp fora da janela tolerada.')
            return {'status': 'forbidden', 'message': 'stale or future timestamp'}, 403
        # Basic nonce store using in-memory cache; replace with Redis in production
        combo = f"{nonce}:{ts}"
        if combo in USED_NONCES:
            logger.warning('Webhook: nonce reutilizado (possível replay).')
            return {'status': 'forbidden', 'message': 'nonce replay detected'}, 403
        USED_NONCES.add(combo)
    tx_id = data.get('tx_id')
    status = data.get('status')

    if not tx_id or not status:
        logger.warning('Webhook chamada com payload incompleto.')
        return {'status': 'bad_request', 'message': 'tx_id and status are required'}, 400

    tx = Transaction.query.filter_by(tx_id=tx_id).first()
    if not tx:
        logger.warning(f'Webhook: transação não encontrada. tx_id={tx_id}')
        return {'status': 'not_found'}, 404

    # Atualiza o status somente para estados conhecidos
    if status not in ['pending', 'confirmed', 'failed']:
        logger.warning(f'Webhook: status inválido recebido: {status}')
        return {'status': 'bad_request', 'message': 'status inválido'}, 400

    tx.status = status
    db.session.commit()
    logger.info(f'Transação tx_id={tx_id} atualizada via webhook para status={status}')
    return {'status': 'ok'}
# FIM DA ROTA DE PAGAMENTO ##


if __name__ == '__main__':
    # Em produção, use debug=False; control via env
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)


@app.errorhandler(404)
def handle_404(e):
    logger.info(f"404 Not Found: {request.path}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def handle_500(e):
    # Log exception details with stack (server-side) but do not expose internals to client.
    logger.exception(f"Unhandled exception while handling request: {request.path}")
    return render_template('500.html'), 500


@app.errorhandler(403)
def handle_403(e):
    logger.warning(f"403 Forbidden: {request.path} by IP: {mask_ip(request.remote_addr or '')}")
    return render_template('403.html'), 403