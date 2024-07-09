from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import pickle
import numpy as np
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

# Load pre-trained models and data
popular_df = pickle.load(open('popular.pkl', 'rb'))
pt = pickle.load(open('pt.pkl', 'rb'))
books = pickle.load(open('books.pkl', 'rb'))
similarity_score = pickle.load(open('similarity_score.pkl', 'rb'))

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Update with your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'  # Update with your email username
app.config['MAIL_PASSWORD'] = 'your-email-password'  # Update with your email password

mail = Mail(app)

# Initialize SQLite database for user management
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Route to handle logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Route to render index page
@app.route('/')
def index():
    return render_template('index.html',
                           book_name=list(popular_df['Book-Title'].values),
                           author=list(popular_df['Book-Author'].values),
                           image=list(popular_df['Image-URL-M'].values),
                           votes=list(popular_df['num_ratings'].values),
                           rating=[round(r, 2) for r in popular_df['avg_rating'].values],
                           logged_in='user_id' in session)

# Route to render recommendation UI
@app.route('/recommend')
def recommend_ui():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('recommend.html', logged_in=True)

# Route to handle book recommendations
@app.route('/recommend_books', methods=['POST'])
def recommend_books():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_input = request.form.get('user_input')

    if not user_input:
        error = 'Invalid input. Please provide a valid book title or genre.'
        return render_template('recommend.html', error=error, logged_in=True)

    recommendations = []
    if user_input in pt.index:
        index = np.where(pt.index == user_input)[0][0]
        similar_items = sorted(list(enumerate(similarity_score[index])), key=lambda x: x[1], reverse=True)[1:5]
        for i in similar_items:
            temp_df = books[books['Book-Title'] == pt.index[i[0]]]
            recommendations.append(
                list(temp_df.drop_duplicates('Book-Title')[['Book-Title', 'Book-Author', 'Image-URL-M']].values[0]))
    else:
        for title in pt.index:
            if user_input.lower() in title.lower():
                temp_df = books[books['Book-Title'] == title]
                recommendations.append(
                    list(temp_df.drop_duplicates('Book-Title')[['Book-Title', 'Book-Author', 'Image-URL-M']].values[0]))
            if len(recommendations) >= 4:
                break

    if not recommendations:
        error = 'No books found. Please try a different title or genre.'
        return render_template('recommend.html', error=error, logged_in=True)

    return render_template('recommend.html', data=recommendations[:4], logged_in=True)

# Route to render contact page
@app.route('/contact')
def contact():
    return render_template('contacts.html', logged_in='user_id' in session)

# Route to handle search suggestions
@app.route('/search_suggestions', methods=['GET'])
def search_suggestions():
    query = request.args.get('q')
    if query:
        suggestions = [title for title in pt.index if query.lower() in title.lower()]
        return jsonify(suggestions[:10])
    return jsonify([])

# Route to render the login page and handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['email'] = user[1]
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html', logged_in='user_id' in session)

# Route to render the registration page and handle user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html', logged_in='user_id' in session)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'danger')
        finally:
            conn.close()

    return render_template('register.html', logged_in='user_id' in session)

if __name__ == '__main__':
    app.run(debug=True)
