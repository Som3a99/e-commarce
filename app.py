from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv
import re
from datetime import datetime
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from flask_migrate import Migrate
import requests
import json
import random
from collections import deque

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'static/product_images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Serializer for generating tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    products = db.relationship('Product', backref='seller', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_verification_token(self):
        self.email_verification_token = serializer.dumps(self.email, salt='email-verification')
        return self.email_verification_token

    def generate_reset_token(self):
        self.reset_token = serializer.dumps(self.email, salt='password-reset')
        self.reset_token_expiry = datetime.utcnow()
        return self.reset_token

# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_filename = db.Column(db.String(255))
    stock_quantity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def check_password_complexity(password):
    """Check if password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password meets complexity requirements"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(user):
    token = user.generate_verification_token()
    msg = Message('Verify Your Email',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not make this request then simply ignore this email.
'''
    mail.send(msg)

def send_reset_email(user):
    token = user.generate_reset_token()
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email.
'''
    mail.send(msg)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Check password complexity
        is_valid, message = check_password_complexity(password)
        if not is_valid:
            flash(message)
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Send verification email
        send_verification_email(user)

        flash('Registration successful! Please check your email to verify your account.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.email_verified = True
            user.email_verification_token = None
            db.session.commit()
            flash('Email verified successfully! You can now login.')
        else:
            flash('Invalid verification link.')
    except:
        flash('The verification link is invalid or has expired.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.email_verified:
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))
            login_user(user)
            if user.role == 'client':
                return redirect(url_for('products'))
            else:
                return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Check your email for instructions to reset your password.')
            return redirect(url_for('login'))
        flash('Email address not found.')
    return render_template('reset_password_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Invalid reset link.')
            return redirect(url_for('login'))

        if request.method == 'POST':
            password = request.form.get('password')
            is_valid, message = check_password_complexity(password)
            if not is_valid:
                flash(message)
                return redirect(url_for('reset_password', token=token))

            user.set_password(password)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            flash('Your password has been reset. You can now login.')
            return redirect(url_for('login'))

    except:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Product Management Routes
@app.route('/products')
def products():
    # Get filter/search parameters
    q = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    min_price = request.args.get('min_price', '').strip()
    max_price = request.args.get('max_price', '').strip()
    stock = request.args.get('stock', '').strip()  # 'in', 'out', or ''

    query = Product.query

    if q:
        query = query.filter((Product.name.ilike(f'%{q}%')) | (Product.description.ilike(f'%{q}%')))
    if category:
        query = query.filter(Product.category == category)
    if min_price:
        try:
            min_price_val = float(min_price)
            query = query.filter(Product.price >= min_price_val)
        except ValueError:
            pass
    if max_price:
        try:
            max_price_val = float(max_price)
            query = query.filter(Product.price <= max_price_val)
        except ValueError:
            pass
    if stock == 'in':
        query = query.filter(Product.stock_quantity > 0)
    elif stock == 'out':
        query = query.filter(Product.stock_quantity == 0)

    products = query.all()
    # For category dropdown
    categories = db.session.query(Product.category).distinct().all()
    categories = [c[0] for c in categories]
    return render_template('products.html', products=products, categories=categories, q=q, category=category, min_price=min_price, max_price=max_price, stock=stock)

@app.route('/seller/products')
@login_required
def seller_products():
    if current_user.role != 'seller':
        flash('Only sellers can access this page.')
        return redirect(url_for('dashboard'))
    products = Product.query.filter_by(seller_id=current_user.id).all()
    return render_template('seller_products.html', products=products)

@app.route('/seller/add-product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'seller':
        flash('Only sellers can add products.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        category = request.form.get('category')
        stock_quantity = int(request.form.get('stock_quantity'))
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to filename to make it unique
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename

        product = Product(
            name=name,
            description=description,
            price=price,
            category=category,
            image_filename=image_filename,
            stock_quantity=stock_quantity,
            seller_id=current_user.id
        )
        
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!')
        return redirect(url_for('seller_products'))

    return render_template('add_product.html')

@app.route('/seller/edit-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role != 'seller':
        flash('Only sellers can edit products.')
        return redirect(url_for('dashboard'))

    product = Product.query.get_or_404(product_id)
    if product.seller_id != current_user.id:
        flash('You can only edit your own products.')
        return redirect(url_for('seller_products'))

    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.category = request.form.get('category')
        product.stock_quantity = int(request.form.get('stock_quantity'))

        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                # Delete old image if exists
                if product.image_filename:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename))
                    except:
                        pass
                
                filename = secure_filename(file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_filename = filename

        db.session.commit()
        flash('Product updated successfully!')
        return redirect(url_for('seller_products'))

    return render_template('edit_product.html', product=product)

@app.route('/seller/delete-product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.role != 'seller':
        flash('Only sellers can delete products.')
        return redirect(url_for('dashboard'))

    product = Product.query.get_or_404(product_id)
    if product.seller_id != current_user.id:
        flash('You can only delete your own products.')
        return redirect(url_for('seller_products'))

    # Delete product image if exists
    if product.image_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename))
        except:
            pass

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!')
    return redirect(url_for('seller_products'))

# --- CART FUNCTIONALITY ---
@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart = session.get('cart', {})
    product_id_str = str(product_id)
    if product_id_str in cart:
        cart[product_id_str]['quantity'] += 1
    else:
        cart[product_id_str] = {
            'name': product.name,
            'price': product.price,
            'image_filename': product.image_filename,
            'seller_id': product.seller_id,
            'quantity': 1
        }
    session['cart'] = cart
    flash(f'Added {product.name} to cart!')
    return redirect(request.referrer or url_for('products'))

@app.route('/cart')
def view_cart():
    cart = session.get('cart', {})
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('cart.html', cart=cart, total=total)

@app.route('/update-cart', methods=['POST'])
def update_cart():
    cart = session.get('cart', {})
    for product_id, details in cart.items():
        quantity = int(request.form.get(f'quantity_{product_id}', details['quantity']))
        if quantity <= 0:
            continue
        cart[product_id]['quantity'] = quantity
    # Remove items with quantity 0
    cart = {pid: item for pid, item in cart.items() if item['quantity'] > 0}
    session['cart'] = cart
    flash('Cart updated!')
    return redirect(url_for('view_cart'))

@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    product_id_str = str(product_id)
    if product_id_str in cart:
        del cart[product_id_str]
        session['cart'] = cart
        flash('Item removed from cart.')
    return redirect(url_for('view_cart'))

# Create database tables
# with app.app_context():
#     db.drop_all()
#     db.create_all()

# Order and OrderItem models
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shipping_name = db.Column(db.String(100), nullable=False)
    shipping_address = db.Column(db.String(255), nullable=False)
    shipping_phone = db.Column(db.String(30), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default='Pending')  # Pending, Accepted, Prepared, Out for Delivery, Completed, Rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if current_user.role != 'client':
        flash('Only clients can place orders.')
        return redirect(url_for('index'))
    cart = session.get('cart', {})
    if not cart:
        flash('Your cart is empty.')
        return redirect(url_for('products'))
    if request.method == 'POST':
        shipping_name = request.form.get('shipping_name')
        shipping_address = request.form.get('shipping_address')
        shipping_phone = request.form.get('shipping_phone')
        payment_method = request.form.get('payment_method')
        # Create order
        order = Order(
            user_id=current_user.id,
            shipping_name=shipping_name,
            shipping_address=shipping_address,
            shipping_phone=shipping_phone,
            payment_method=payment_method,
            status='Pending'
        )
        db.session.add(order)
        db.session.flush()  # Get order.id before commit
        # Add order items
        for product_id, item in cart.items():
            order_item = OrderItem(
                order_id=order.id,
                product_id=int(product_id),
                product_name=item['name'],
                price=item['price'],
                quantity=item['quantity'],
                seller_id=item['seller_id']
            )
            db.session.add(order_item)
        db.session.commit()
        session['cart'] = {}
        flash('Order placed successfully!')
        return redirect(url_for('order_confirmation', order_id=order.id))
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('checkout.html', cart=cart, total=total)

@app.route('/order-confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('You do not have permission to view this order.')
        return redirect(url_for('dashboard'))
    return render_template('order_confirmation.html', order=order)

# Seller: View and manage orders for their products
@app.route('/seller/orders')
@login_required
def seller_orders():
    if current_user.role != 'seller':
        flash('Only sellers can view this page.')
        return redirect(url_for('dashboard'))
    # Find all orders that have at least one item for this seller
    order_items = OrderItem.query.filter_by(seller_id=current_user.id).all()
    order_ids = list(set([item.order_id for item in order_items]))
    orders = Order.query.filter(Order.id.in_(order_ids)).order_by(Order.created_at.desc()).all()
    return render_template('seller_orders.html', orders=orders, seller_id=current_user.id)

# Seller: Update order status
@app.route('/seller/update-order-status/<int:order_id>', methods=['POST'])
@login_required
def update_order_status(order_id):
    if current_user.role != 'seller':
        flash('Only sellers can update order status.')
        return redirect(url_for('dashboard'))
    order = Order.query.get_or_404(order_id)
    # Only allow if this seller has items in the order
    seller_item = any(item.seller_id == current_user.id for item in order.order_items)
    if not seller_item:
        flash('You do not have permission to update this order.')
        return redirect(url_for('seller_orders'))
    new_status = request.form.get('status')
    if new_status == 'Accepted' and order.status == 'Pending':
        # Decrease stock for each product belonging to this seller
        for item in order.order_items:
            if item.seller_id == current_user.id:
                product = Product.query.get(item.product_id)
                if product and product.stock_quantity >= item.quantity:
                    product.stock_quantity -= item.quantity
                else:
                    flash(f'Not enough stock for {item.product_name}.')
                    return redirect(url_for('seller_orders'))
    order.status = new_status
    db.session.commit()
    flash(f'Order status updated to {new_status}.')
    return redirect(url_for('seller_orders'))

# User: View their orders
@app.route('/orders')
@login_required
def user_orders():
    if current_user.role != 'client':
        flash('Only clients can view their orders.')
        return redirect(url_for('dashboard'))
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('user_orders.html', orders=orders)

# Add this class after the other model definitions
class SmartShopChatbot:
    def __init__(self):
        self.conversation_history = deque(maxlen=5)
        self.button_responses = {
            'shipping': {
                'title': 'Shipping Information',
                'response': 'We offer three shipping options:\n1. Standard Shipping (3-5 business days) - Free for orders over $50\n2. Express Shipping (1-2 business days) - $10\n3. Same Day Delivery (selected areas) - $15'
            },
            'returns': {
                'title': 'Return Policy',
                'response': 'Our return policy allows returns within 30 days of delivery:\n1. Log into your account\n2. Go to "Orders"\n3. Select the order\n4. Click "Return Item"\n5. Follow the instructions'
            },
            'track_order': {
                'title': 'Track Order',
                'response': 'To track your order:\n1. Log into your account\n2. Go to "Orders"\n3. Find your order\n4. Click "Track Order"\nYou\'ll see real-time updates on your order status.'
            },
            'payment': {
                'title': 'Payment Methods',
                'response': 'We accept multiple payment methods:\n- All major credit/debit cards\n- PayPal\n- Bank transfer\n- Cash on delivery (selected areas)'
            },
            'pricing': {
                'title': 'Pricing & Discounts',
                'response': 'Our pricing includes:\n- Competitive market rates\n- Volume discounts\n- Seasonal promotions\n- Special member prices\n- First-time buyer offers'
            },
            'refund': {
                'title': 'Refund Policy',
                'response': 'Refund process:\n1. Return the item within 30 days\n2. Once received, refund is processed\n3. Refund appears in 5-7 business days\n4. Original payment method is credited'
            },
            'warranty': {
                'title': 'Warranty Information',
                'response': 'Our warranty policy:\n- Standard warranty: 1 year\n- Extended warranty available\n- Covers manufacturing defects\n- Free repair or replacement'
            },
            'product_info': {
                'title': 'Product Details',
                'response': 'Product information includes:\n- Full specifications\n- Features and benefits\n- Customer reviews\n- Related products\n- Size and color options'
            },
            'availability': {
                'title': 'Stock Availability',
                'response': 'Stock information:\n- Real-time inventory updates\n- Back-in-stock notifications\n- Pre-order options\n- Store availability checker'
            },
            'contact': {
                'title': 'Contact Us',
                'response': 'You can reach us through:\n- Email: support@smartshop.com\n- Phone: 1-800-SHOP\n- Live chat: Available 24/7\n- Social media: @SmartShopOfficial'
            },
            'hours': {
                'title': 'Business Hours',
                'response': 'Our service hours:\n- Online store: 24/7\n- Customer service: 24/7\n- Phone support: 9 AM - 9 PM EST\n- Live chat: 24/7'
            },
            'faq': {
                'title': 'FAQ',
                'response': 'Common questions:\n1. How do I track my order?\n2. What is your return policy?\n3. How do I change my order?\n4. What payment methods do you accept?\nFor more FAQs, visit our Help Center.'
            }
        }
        self.rules = {
            'greeting': {
                'patterns': [r'hi', r'hello', r'hey', r'greetings', r'good morning', r'good afternoon', r'good evening'],
                'responses': [
                    'Hello! Welcome to SmartShop. How can I assist you today?',
                    'Hi there! I\'m your SmartShop assistant. What can I help you with?',
                    'Welcome to SmartShop! How may I help you with your shopping today?'
                ]
            },
            'order_status': {
                'patterns': [r'order status', r'where is my order', r'track order', r'order tracking', r'when will i get my order', r'order delivery'],
                'responses': [
                    'To check your order status, please visit the "Orders" section in your account. You can track your order\'s current location and estimated delivery date there.',
                    'You can track your order by logging into your account and visiting the "Orders" section. Each order has a detailed tracking history.',
                    'For real-time order tracking, please check the "Orders" section in your account. You\'ll find the current status and delivery updates there.'
                ]
            },
            'shipping': {
                'patterns': [r'shipping', r'delivery', r'when will i receive', r'shipping time', r'delivery time', r'how long to deliver', r'shipping cost'],
                'responses': [
                    'We offer three shipping options:\n1. Standard Shipping (3-5 business days) - Free for orders over $50\n2. Express Shipping (1-2 business days) - $10\n3. Same Day Delivery (selected areas) - $15',
                    'Shipping times vary by location:\n- Local deliveries: 1-2 business days\n- National deliveries: 3-5 business days\n- International: 7-14 business days',
                    'Our standard shipping is free for orders over $50. Express shipping is available for faster delivery at an additional cost.'
                ]
            },
            'returns': {
                'patterns': [r'return', r'refund', r'exchange', r'how to return', r'return policy', r'refund policy', r'return item'],
                'responses': [
                    'Our return policy allows returns within 30 days of delivery:\n1. Log into your account\n2. Go to "Orders"\n3. Select the order\n4. Click "Return Item"\n5. Follow the instructions',
                    'You can return items within 30 days if they\'re unused and in original packaging. Refunds are processed within 5-7 business days after we receive the item.',
                    'To initiate a return:\n1. Visit the "Returns" section in your account\n2. Select the item(s) to return\n3. Print the return label\n4. Ship the item back'
                ]
            },
            'payment': {
                'patterns': [r'payment', r'pay', r'credit card', r'debit card', r'payment method', r'how to pay', r'payment options'],
                'responses': [
                    'We accept multiple payment methods:\n- All major credit/debit cards\n- PayPal\n- Bank transfer\n- Cash on delivery (selected areas)',
                    'You can pay using:\n1. Credit/Debit cards (Visa, MasterCard, American Express)\n2. PayPal\n3. Bank transfer\n4. Cash on delivery (limited areas)',
                    'Our secure payment system accepts all major credit cards, PayPal, and bank transfers. All transactions are encrypted for your security.'
                ]
            },
            'pricing': {
                'patterns': [r'price', r'cost', r'how much', r'pricing', r'discount', r'sale', r'promotion', r'offer'],
                'responses': [
                    'Prices are listed on each product page. We offer:\n- Regular discounts for bulk orders\n- Seasonal sales\n- Loyalty program discounts\n- First-time buyer offers',
                    'Our pricing includes:\n- Competitive market rates\n- Volume discounts\n- Seasonal promotions\n- Special member prices',
                    'Check our website for current prices and promotions. We regularly update our offers and discounts.'
                ]
            },
            'contact': {
                'patterns': [r'contact', r'support', r'help', r'customer service', r'email', r'phone', r'call', r'speak to'],
                'responses': [
                    'You can reach us through:\n- Email: support@smartshop.com\n- Phone: 1-800-SHOP\n- Live chat: Available 24/7\n- Social media: @SmartShopOfficial',
                    'Our customer service team is available:\n- 24/7 via email and live chat\n- Phone support: 9 AM - 9 PM EST\n- Social media: @SmartShopOfficial',
                    'For immediate assistance:\n1. Use our live chat (24/7)\n2. Email: support@smartshop.com\n3. Call: 1-800-SHOP (9 AM - 9 PM EST)'
                ]
            },
            'hours': {
                'patterns': [r'hours', r'open', r'business hours', r'operating hours', r'when are you open', r'working hours'],
                'responses': [
                    'Our service hours:\n- Online store: 24/7\n- Customer service: 24/7\n- Phone support: 9 AM - 9 PM EST\n- Live chat: 24/7',
                    'We\'re always open online! Customer service is available through:\n- Live chat: 24/7\n- Phone: 9 AM - 9 PM EST\n- Email: 24/7'
                ]
            },
            'account': {
                'patterns': [r'account', r'login', r'sign in', r'register', r'sign up', r'create account', r'password', r'forgot password'],
                'responses': [
                    'To manage your account:\n1. Click "Sign In" at the top right\n2. For new accounts, click "Register"\n3. For password reset, use "Forgot Password"',
                    'Account features include:\n- Order history\n- Saved addresses\n- Payment methods\n- Wishlist\n- Account settings',
                    'You can create an account by clicking "Register" at the top right. Benefits include:\n- Faster checkout\n- Order tracking\n- Saved preferences'
                ]
            },
            'product_info': {
                'patterns': [r'product', r'item', r'description', r'details', r'specifications', r'features', r'what is', r'tell me about'],
                'responses': [
                    'Product details are available on each product page, including:\n- Full description\n- Specifications\n- Customer reviews\n- Related items',
                    'You can find detailed product information on the product page, including:\n- Features\n- Specifications\n- Reviews\n- Shipping info',
                    'Each product page contains comprehensive information about:\n- Product details\n- Technical specifications\n- Customer reviews\n- Availability'
                ]
            },
            'warranty': {
                'patterns': [r'warranty', r'guarantee', r'product guarantee', r'warranty period', r'how long warranty'],
                'responses': [
                    'Our warranty policy:\n- Standard warranty: 1 year\n- Extended warranty available\n- Covers manufacturing defects\n- Free repair or replacement',
                    'Products come with:\n- 1-year standard warranty\n- Option to purchase extended warranty\n- Coverage for defects\n- Quick repair service'
                ]
            },
            'loyalty': {
                'patterns': [r'loyalty', r'rewards', r'points', r'member benefits', r'loyalty program', r'rewards program'],
                'responses': [
                    'Our loyalty program benefits:\n- Earn points on every purchase\n- Exclusive member discounts\n- Early access to sales\n- Birthday rewards\n- Free shipping for members',
                    'Join our loyalty program to get:\n- 1 point per $1 spent\n- Special member-only deals\n- Priority customer service\n- Free shipping on all orders'
                ]
            },
            'fallback': {
                'patterns': [],
                'responses': [
                    'I apologize, but I don\'t have information about that. Please contact our customer service team at support@smartshop.com for assistance.',
                    'I\'m not sure about that. For detailed information, please reach out to our customer service team at support@smartshop.com.',
                    'I don\'t have that information. You can get help from our customer service team by emailing support@smartshop.com or calling 1-800-SHOP.'
                ]
            }
        }

    def get_button_response(self, button_id):
        return self.button_responses.get(button_id, {}).get('response')

    def get_response(self, message):
        message = message.lower().strip()
        self.conversation_history.append(message)
        
        # Check for multiple intents
        matched_intents = []
        for intent, data in self.rules.items():
            for pattern in data['patterns']:
                if re.search(r'\b' + pattern + r'\b', message):
                    matched_intents.append(intent)
                    break
        
        # If no matches found, return custom_question signal
        if not matched_intents:
            return "custom_question"
        
        # If multiple intents found, combine responses
        if len(matched_intents) > 1:
            responses = []
            for intent in matched_intents:
                responses.append(random.choice(self.rules[intent]['responses']))
            return "\n\n".join(responses)
        
        # If single intent found, return its response
        return random.choice(self.rules[matched_intents[0]]['responses'])

    def get_available_buttons(self):
        return {k: v['title'] for k, v in self.button_responses.items()}

# Initialize the chatbot
smartshop_chatbot = SmartShopChatbot()

# Update the chatbot route
@app.route('/chatbot', methods=['POST'])
def handle_chatbot():
    data = request.json
    message = data.get('message')
    button_id = data.get('button_id')  # New field for button clicks
    
    if not message and not button_id:
        return jsonify({'response': "Please enter a message or select an option."})
    
    try:
        # If it's a button click, get the predefined response
        if button_id:
            response = smartshop_chatbot.get_button_response(button_id)
            if response:
                return jsonify({'response': response})
        
        # If it's a text message, check if it's a custom question
        response = smartshop_chatbot.get_response(message)
        if response == "custom_question":
            return jsonify({
                'response': "I don't have information about that. Would you like to submit your question to our customer service team?",
                'needs_info': True,
                'original_question': message
            })
        
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'response': f"Error: {str(e)}"})

# Add new route for handling custom questions
@app.route('/submit-custom-question', methods=['POST'])
def submit_custom_question():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        email = data.get('email')
        phone = data.get('phone')
        question = data.get('question')
        
        if not all([email, phone, question]):
            return jsonify({
                'success': False, 
                'error': 'Please provide all required information (email, phone, and question).'
            }), 400
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({
                'success': False,
                'error': 'Please provide a valid email address.'
            }), 400

        # Validate phone number (basic validation)
        if not re.match(r"^\+?[\d\s-]{10,}$", phone):
            return jsonify({
                'success': False,
                'error': 'Please provide a valid phone number.'
            }), 400

        try:
            custom_question = CustomQuestion(
                email=email,
                phone=phone,
                question=question
            )
            db.session.add(custom_question)
            db.session.commit()
            
            # Send email notification to customer service
            try:
                msg = Message('New Customer Question',
                            sender=app.config['MAIL_USERNAME'],
                            recipients=[app.config['MAIL_USERNAME']])
                msg.body = f'''New question from customer:
Email: {email}
Phone: {phone}
Question: {question}
'''
                mail.send(msg)
            except Exception as email_error:
                app.logger.error(f"Failed to send email notification: {str(email_error)}")
                # Continue even if email fails
            
            return jsonify({
                'success': True,
                'message': "Thank you for your question. Our customer service team will contact you soon."
            })
            
        except Exception as db_error:
            db.session.rollback()
            app.logger.error(f"Database error: {str(db_error)}")
            return jsonify({
                'success': False,
                'error': 'Failed to save your question. Please try again.'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Unexpected error in submit_custom_question: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred. Please try again.'
        }), 500

# Add this route after the other routes
@app.route('/chat')
def chat():
    return render_template('chat.html', show_nav_button=True)

# Add this after the OrderItem model and before the SmartShopChatbot class
class CustomQuestion(db.Model):
    __tablename__ = 'custom_questions'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    question = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Pending')  # Pending, Answered, Closed

if __name__ == '__main__':
    app.run(debug=True) 