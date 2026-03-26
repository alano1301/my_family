from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
from flask import make_response

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection ko to

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'flask_users_db'
    
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        question = request.form['security_question']
        answer = request.form['security_answer'].lower().strip()

        if not question or not answer:
            flash("Please select a security question and provide an answer.", "danger")

        if not username or not password:
            flash('All fields are required!', 'danger')
            return render_template('signup.html')
        
        if len(username) <4:
            flash('Username must be at least 4 characters long.', 'danger')
            return render_template(signup.html)
        
        if len(password) <8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('signup.html')

        #HASHED SECURITY
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password, security_question, security_answer) VALUES (%s, %s, %s, %s)", 
               (username, hashed_password, question, answer))
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash('Username already exists. Please choose another.', 'danger')
        finally:
            cursor.close()
            conn.close()   
 
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Check if user exists and password matches the hash
        if user and check_password_hash(user['password'], password_input):
            session['loggedin'] = True
            session['id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']


            conn = get_db_connection()
            cursor = conn.cursor()
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("UPDATE users SET last_login = %s WHERE id = %s", (now, user['id']))
            conn.commit()
            cursor.close()
            conn.close()
            # ----------------------------------------

            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username/password!', 'danger')
            
    return render_template('login.html')



@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    # 1. Security Check: Only logged-in users can access this
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['id']
    current_username = session['username']

    if request.method == 'POST':
        new_username = request.form['username'].strip()
        new_password = request.form['new_password']
        
        # Validation
        if len(new_username) < 4 or not new_username.isalnum():
            flash('Invalid username format.', 'danger')
            return redirect(url_for('update_profile'))

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Update Username
            cursor.execute("UPDATE users SET username = %s WHERE id = %s", (new_username, user_id))
            session['username'] = new_username # Update the session so the UI reflects the change
            
            # Update Password only if the user typed a new one
            if new_password:
                if len(new_password) >= 8:
                    hashed_pw = generate_password_hash(new_password)
                    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pw, user_id))
                else:
                    flash('New password is too short.', 'danger')
                    return redirect(url_for('update_profile'))

            conn.commit()
            flash('Profile updated successfully!', 'success')
        except mysql.connector.Error:
            flash('Username already taken.', 'danger')
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('dashboard'))

    return render_template('update_profile.html', username=current_username)



@app.route('/admin')
def admin_dashboard():
    # Check if user is logged in AND is an admin
    if 'loggedin' in session and session.get('role') == 'admin':
        search_query = (request.args.get('search') or '').strip()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        
        
        if search_query:
            sql = "SELECT id, username, role, last_login FROM users WHERE username LIKE %s"
            cursor.execute(sql, (f"%{search_query}%",))
        else:
            cursor.execute("SELECT id, username, role, last_login FROM users")
  
        all_users = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin.html', users=all_users,)
    
    
    
    # If not admin, kick them back to the home page with an error
    flash('Access denied. Admins only.', 'danger')
    return redirect(url_for('home'))


@app.route('/admin/download_users')
def download_users():
    # Security: Only Admins can download
    if 'loggedin' not in session or session.get('role') != 'admin':
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role, last_login FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    # Create a string buffer to hold CSV data
    si = io.StringIO()
    cw = csv.writer(si)
    
    # Write the header row
    cw.writerow(['ID', 'Username', 'Role', 'Last Login'])
    
    # Write user data rows
    for user in users:
        cw.writerow([
            user['id'], 
            user['username'], 
            user['role'], 
            user['last_login'] if user['last_login'] else 'Never'
        ])

    # Create the response and set headers for file download
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=user_list_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output



@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    # Security: Only Admins can delete
    if 'loggedin' in session and session.get('role') == 'admin':
        # Prevent the Admin from deleting themselves!
        if id == session['id']:
            flash("You cannot delete your own admin account!", "danger")
            return redirect(url_for('admin_dashboard'))

        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM users WHERE id = %s", (id,))
            conn.commit()
            flash("User deleted successfully.", "success")
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "danger")
        finally:
            cursor.close()
            conn.close()
            
        return redirect(url_for('admin_dashboard'))
    
    flash("Unauthorized action.", "danger")
    return redirect(url_for('home'))

@app.route('/forgot.password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        answer_input = request.form.get('security_answer', '').lower().strip()
        new_password = request.form.get('new_password')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        # Step 1: Check if username exists
        if not user:
            flash("Username not found.", "danger")
            return render_template('forgot.password.html')

        # Step 2: If user exists but hasn't provided an answer yet, show the question
        if not answer_input:
            return render_template('forgot.password.html', user=user)

        # Step 3: Verify the answer and update password
        if answer_input == user['security_answer']:
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "danger")
                return render_template('forgot.password.html', user=user)
            
            hashed_pw = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pw, user['id']))
            conn.commit()
            flash("Password reset successful! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Incorrect answer to security question.", "danger")
            return render_template('forgot.password.html', user=user)

    return render_template('forgot.password.html')



@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'loggedin' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Remove session data
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)