import os
import uuid
import re
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import inspect, text, or_
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'big_secret_key'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['PROFILE_UPLOAD_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
app.config['_DB_INITIALIZED'] = False
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db = SQLAlchemy(app)

post_categories = db.Table(
    'post_categories',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.id'), primary_key=True)
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.before_request
def ensure_database_ready():
    initialize_database_if_needed()

@app.before_request
def enforce_ban():
    if current_user.is_authenticated and current_user.is_banned:
        allowed_endpoints = {'logout', 'static'}
        endpoint = request.endpoint or ''
        if endpoint not in allowed_endpoints and not endpoint.startswith('static'):
            logout_user()
            flash('Tu cuenta ha sido baneada. Contacta con un administrador.')
            return redirect(url_for('login'))

@app.route('/')
def index():
    search_query = request.args.get('q', '').strip()
    category_slug = request.args.get('category', '').strip()
    sort_option = request.args.get('sort', 'popular')
    posts_query = Post.query
    selected_category = None

    if search_query:
        like_pattern = f"%{search_query}%"
        posts_query = posts_query.filter(
            or_(
                Post.title.ilike(like_pattern),
                Post.content.ilike(like_pattern)
            )
        )

    if category_slug:
        selected_category = Category.query.filter_by(slug=category_slug).first()
        if selected_category:
            posts_query = posts_query.join(Post.categories).filter(Category.id == selected_category.id)
        else:
            flash('La categoría seleccionada no existe.')

    if sort_option == 'new':
        posts_query = posts_query.order_by(Post.date_posted.desc())
    else:
        posts_query = posts_query.order_by(Post.upvotes.desc(), Post.date_posted.desc())

    posts = posts_query.all()
    liked_post_ids = set()
    if current_user.is_authenticated and posts:
        post_ids = [post.id for post in posts]
        likes = PostLike.query.filter(
            PostLike.user_id == current_user.id,
            PostLike.post_id.in_(post_ids)
        ).all()
        liked_post_ids = {like.post_id for like in likes}
    categories = Category.query.order_by(Category.name.asc()).all()
    return render_template(
        'index.html',
        posts=posts,
        search_query=search_query,
        categories=categories,
        selected_category=selected_category,
        sort_option=sort_option,
        liked_post_ids=liked_post_ids
    )

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique = True, nullable = False)
    email = db.Column(db.String(100), unique = True, nullable = False)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmed_at = db.Column(db.DateTime, nullable=True)
    password_hash = db.Column(db.String(256), nullable = False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    profile_image = db.Column(db.String(255))
    posts = db.relationship('Post', back_populates='author', lazy=True)
    comments = db.relationship('Comment', back_populates='author', lazy=True)
    post_likes = db.relationship('PostLike', back_populates='user', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(150), nullable = False)
    content = db.Column(db.Text, nullable = False)
    date_posted = db.Column(db.DateTime, default = datetime.utcnow)
    image_filename = db.Column(db.String(255))
    upvotes = db.Column(db.Integer, default=0, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    likes = db.relationship('PostLike', back_populates='post', cascade="all, delete-orphan")
    categories = db.relationship('Category', secondary=post_categories, back_populates='posts')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    author = db.relationship('User', back_populates='comments')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    posts = db.relationship('Post', secondary=post_categories, back_populates='categories')

class PostLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='post_likes')
    post = db.relationship('Post', back_populates='likes')
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),)

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    performed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    performed_by = db.relationship('User', foreign_keys=[performed_by_id])

def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('No tienes permisos para acceder a esa página.')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return wrapped_view

def log_admin_action(action, target_type, target_id, details):
    log = AdminLog(
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        performed_by=current_user if current_user.is_authenticated else None
    )
    db.session.add(log)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def delete_image_file(filename):
    if not filename:
        return
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(image_path):
        os.remove(image_path)

def delete_profile_image(filename):
    if not filename:
        return
    image_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], filename)
    if os.path.exists(image_path):
        os.remove(image_path)

def slugify(value):
    return re.sub(r'[^a-z0-9]+', '-', value.lower()).strip('-')

def build_categories_from_input(raw_input):
    categories = []
    seen_slugs = set()
    if not raw_input:
        return categories

    for part in raw_input.split(','):
        label = part.strip()
        if not label:
            continue
        slug = slugify(label)
        if not slug or slug in seen_slugs:
            continue
        seen_slugs.add(slug)
        category = Category.query.filter_by(slug=slug).first()
        if not category:
            category = Category(name=label, slug=slug)
            db.session.add(category)
        categories.append(category)
    return categories


def ensure_post_image_column():
    inspector = inspect(db.engine)
    columns = {col['name'] for col in inspector.get_columns('post')}
    if 'image_filename' not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text('ALTER TABLE post ADD COLUMN image_filename VARCHAR(255)')
            )

def ensure_user_profile_column():
    inspector = inspect(db.engine)
    columns = {col['name'] for col in inspector.get_columns('user')}
    if 'profile_image' not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text('ALTER TABLE user ADD COLUMN profile_image VARCHAR(255)')
            )

def initialize_database_if_needed():
    db.create_all()
    ensure_post_image_column()
    ensure_user_profile_column()
    ensure_post_upvotes_column()

def ensure_post_upvotes_column():
    inspector = inspect(db.engine)
    columns = {col['name'] for col in inspector.get_columns('post')}
    if 'upvotes' not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text('ALTER TABLE post ADD COLUMN upvotes INTEGER DEFAULT 0 NOT NULL')
            )

@app.route('/post/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    user_has_liked = False
    if current_user.is_authenticated:
        user_has_liked = PostLike.query.filter_by(post_id=post.id, user_id=current_user.id).first() is not None
    return render_template('post.html', post=post, user_has_liked=user_has_liked)

@app.route('/post/<int:post_id>/upvote', methods=['POST'])
@login_required
def toggle_upvote(post_id):
    post = Post.query.get_or_404(post_id)
    next_url = request.form.get('next') or url_for('post_detail', post_id=post.id)
    existing_like = PostLike.query.filter_by(post_id=post.id, user_id=current_user.id).first()
    if existing_like:
        db.session.delete(existing_like)
        post.upvotes = max(0, (post.upvotes or 0) - 1)
    else:
        new_like = PostLike(post_id=post.id, user_id=current_user.id)
        db.session.add(new_like)
        post.upvotes = (post.upvotes or 0) + 1
    db.session.commit()
    return redirect(next_url)
    
@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')

    if not content:
        flash('El comentario no puede estar vacío.')
        return redirect(url_for('post_detail', post_id=post.id))

    new_comment = Comment(content=content, author_id=current_user.id, post=post)
    db.session.add(new_comment)
    db.session.commit()
    flash('Comentario añadido.')
    return redirect(url_for('post_detail', post_id=post.id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    next_url = request.form.get('next') or url_for('post_detail', post_id=comment.post_id)
    post_title = comment.post.title if comment.post else f'ID {comment.post_id}'

    if comment.author_id != current_user.id and not current_user.is_admin:
        flash('No tienes permisos para eliminar este comentario.')
        return redirect(next_url)

    should_log_admin_action = current_user.is_admin and comment.author_id != current_user.id
    db.session.delete(comment)
    if should_log_admin_action:
        log_admin_action(
            'delete_comment',
            'comment',
            comment.id,
            f'Comentario #{comment.id} del post "{post_title}" eliminado por un administrador.'
        )
    db.session.commit()
    flash('Comentario eliminado.')
    return redirect(next_url)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/go')
def login_check():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    else:
        return redirect(url_for('login'))
    
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        image_file = request.files.get('avatar')
        if not image_file or not image_file.filename:
            flash('Selecciona una imagen para subir.')
            return redirect(url_for('account'))

        if not allowed_file(image_file.filename):
            flash('Formato de imagen no permitido. Usa png, jpg, jpeg, gif o webp.')
            return redirect(url_for('account'))

        safe_name = secure_filename(image_file.filename)
        image_filename = f"{uuid.uuid4().hex}_{safe_name}"
        image_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], image_filename)
        image_file.save(image_path)

        delete_profile_image(current_user.profile_image)
        current_user.profile_image = image_filename
        db.session.commit()
        flash('Foto de perfil actualizada.')
        return redirect(url_for('account'))
    return render_template('account.html')

@app.route('/login' , methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_banned:
                flash('Tu cuenta ha sido baneada. Contacta con un administrador.')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('account'))
        else:
            flash('Contraseña o usuario incorrecto')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe')
        elif User.query.filter_by(email=email).first():
            flash('El correo electrónico ya está registrado')
        else:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso! Por favor, inicia sesión.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    categories = Category.query.order_by(Category.name.asc()).all()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_input = request.form.get('categories', '')
        image_file = request.files.get('image')
        image_filename = None

        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                flash('Formato de imagen no permitido. Usa png, jpg, jpeg, gif o webp.')
                return redirect(url_for('create_post'))
            safe_name = secure_filename(image_file.filename)
            image_filename = f"{uuid.uuid4().hex}_{safe_name}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

        new_post = Post(title=title, content=content, author=current_user, image_filename=image_filename)
        new_post.categories = build_categories_from_input(category_input)
        db.session.add(new_post)
        db.session.commit()
        flash('Publicación creada con éxito!')
        return redirect(url_for('index'))
    return render_template('create_post.html', categories=categories)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.order_by(User.username).all()
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).limit(50).all()
    return render_template('admin_panel.html', users=users, posts=posts, logs=logs)

@app.route('/admin/posts/<int:post_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    next_url = request.form.get('next') or request.args.get('next')
    delete_image_file(post.image_filename)
    db.session.delete(post)
    log_admin_action('delete_post', 'post', post.id, f'Post "{post.title}" eliminado.')
    db.session.commit()
    flash('Publicación eliminada.')
    return redirect(next_url or url_for('admin_panel'))

@app.route('/admin/users/<int:user_id>/toggle_ban', methods=['POST'])
@login_required
@admin_required
def admin_toggle_ban(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('No puedes banear tu propia cuenta.')
        return redirect(url_for('admin_panel'))
    user.is_banned = not user.is_banned
    action = 'ban_user' if user.is_banned else 'unban_user'
    status = 'baneado' if user.is_banned else 'desbaneado'
    log_admin_action(action, 'user', user.id, f'Usuario "{user.username}" {status}.')
    db.session.commit()
    flash(f'Usuario {status}.')
    return redirect(url_for('admin_panel'))

if __name__ == "__main__":
    with app.app_context():
        initialize_database_if_needed()

    app.run(debug=True)
