import os
import time
import logging
from dotenv import load_dotenv
from flask import (
    Flask, request, redirect, url_for, session,
    render_template, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_talisman import Talisman
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from decimal import Decimal, InvalidOperation, getcontext
import time # Já está presente
## NOVO: MÓDULO DE PAGAMENTO
from pagamentos import process_pix, process_card # Importa as funções de pagamento simulado

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
app.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Variáveis de Rate Limiting (A07)
FAILED_LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutos

# Configurações de Cookies Seguros (A02 e A09)
app.config.update({
  'SESSION_COOKIE_HTTPONLY': True,
  'SESSION_COOKIE_SECURE': True,  # garantir HTTPS
  'SESSION_COOKIE_SAMESITE': 'Lax'
})

# Inicialização de Extensões
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # Inicializa o Bcrypt para hashing seguro de senhas (A02)
csrf = CSRFProtect(app)  # Proteção CSRF para formulários
sess = Session(app)  # Server-side session support
limiter = Limiter(key_func=get_remote_address)  # Rate limiting
force_https = os.getenv('FORCE_HTTPS', 'false').lower() == 'true'
Talisman(app, content_security_policy={
    'default-src': ["'self'"],
    'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'style-src': ["'self'", 'https://cdn.jsdelivr.net'],
}, force_https=force_https)  # Set via env var to enforce HTTPS in production

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
            logger.info(f"Usuário admin '{admin_username}' criado com sucesso.") # Log (A09)
        else:
            print(f"Usuário admin '{admin_username}' já existe.")

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
            
            logger.warning(f"Login MAL-SUCEDIDO. Tentativa com usuário: {username}. IP: {client_ip}") # Log (A09)
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
            
            logger.info(f"Novo usuário criado por Admin (ID: {getattr(current_user, 'id', 'Unknown')}). Username: {username}, Role: {role}") # Log (A09)
            flash(f"Usuário {username} criado com sucesso!", "success")
            return redirect(url_for('index'))
        except IntegrityError:
            # Caso raro onde o username foi adicionado por outro processo após a verificação
            db.session.rollback()
            flash("Erro ao registrar: nome de usuário duplicado.", "danger")
            return redirect(url_for('register_voluntario'))

    # Usa template (Mudança principal)
    return render_template('register_voluntario.html', user_role=getattr(current_user, 'role', 'Convidado'))


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

        user_id = current_user.get_id()

        nova = Doacao()
        nova.tipo = tipo
        nova.quantidade = quantidade
        nova.voluntario_id = user_id # Liga a doação ao usuário logado (A04)

        db.session.add(nova)
        db.session.commit()
        
        logger.info(f"Doação registrada por User ID: {user_id}. Tipo: {tipo}.") # Log (A09)
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
                logger.warning(f"Tentativa de doação financeira com valor inválido por User ID: {user_id}. Valor: {amount_str}")
                flash("Valor de doação inválido. Insira um valor positivo.", "danger")
                return redirect(url_for('doar_pagamento'))

        except (ValueError, TypeError):
            logger.warning(f"Tentativa de doação financeira com valor inválido por User ID: {user_id}. Valor: {amount_str}")
            flash("Valor de doação inválido. Insira um valor positivo.", "danger")
            return redirect(url_for('doar_pagamento'))

        if method == 'pix':
            payer_id = request.form.get('payer_id', f"User_{user_id}")
            
            # Chama a função simulada de pagamento PIX
            result = process_pix(amount, payer_id)

            if result['status'] == 'success':
                # Em um app real, aqui você registraria a transação pendente no BD.
                logger.info(f"PIX gerado por User ID: {user_id}. Valor: {format(amount, '.2f')}. TX ID: {result['tx_id']}")
                flash(f"PIX gerado com sucesso! Use o código/QR Code para pagar. (ID: {result['tx_id']})", "success")
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
            result = process_card(amount, card_number, card_holder, expiry, cvv)

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
# FIM DA ROTA DE PAGAMENTO ##


if __name__ == '__main__':
    # Em produção, use debug=False; control via env
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)