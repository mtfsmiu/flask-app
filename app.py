from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Optional
import bcrypt
from flask_mysqldb import MySQL
from forms import RegisterForm
from captcha.image import ImageCaptcha
import random
import string
from flask_wtf.recaptcha import RecaptchaField  # Import reCAPTCHA field
from MySQLdb.cursors import DictCursor  # Add this import at the top




app = Flask(__name__)

#1-------------> Configurations START <------------
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdBQcQqAAAAAN7bAlkI6U263fVD-lkuUG0X7A_G'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdBQcQqAAAAAKy8wfCvneZkjRIetk0GWufczEp1'
app.config['SECRET_KEY'] = 'hasjdkhsajkdhasjdhjaskh'  # Replace with environment variable in production
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Replace with your MySQL root password
app.config['MYSQL_DB'] = 'dbms'

mysql = MySQL(app)
#-------------> Configurations END<------------



#2------------>Register START<--------------
# Register Form
class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email_address = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Get the form data
        name = form.name.data
        email_address = form.email_address.data
        password = form.password.data
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert the data into the MySQL database
        cursor = mysql.connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (name, email_address, password)
            VALUES (%s, %s, %s)
            """,
            (name, email_address, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()

        # Flash success message
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

#------------>Register End<--------------



#3----------->LOGIN Start<---------------#
# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()  # Add reCAPTCHA field
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Retrieve user from database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email_address=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):  # Password is at index 3
            session['user_id'] = user[0]  # user_id is at index 0
            flash('Login successful!', 'success')

            # Redirect to dashboard (or another page after successful login)
            return redirect(url_for('dashboard'))

        else:
            flash('Login failed! Incorrect email or password.', 'danger')

    return render_template('login.html', form=form)


#----------->LOGIN END<---------------#


#4----------->Dashboard Start<---------------#

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        # Fetch user info
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))  # Correct column name
        user = cursor.fetchone()
        cursor.close()

        if user:
            search_query = request.form.get('search')
            query = "SELECT * FROM constituencies"
            params = ()

            # Pagination settings
            per_page = request.args.get('per_page', 10, type=int)  # Default per_page is 10
            page = request.args.get('page', 1, type=int)  # Default page is 1
            offset = (page - 1) * per_page  # Calculate the offset for the query

            # Check if search query is provided
            if search_query:
                query += """ WHERE Name LIKE %s OR MP LIKE %s OR Area LIKE %s OR country LIKE %s"""
                params = ('%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%')

            # Get total number of constituencies
            cursor = mysql.connection.cursor()
            cursor.execute(query, params)
            total_items = len(cursor.fetchall())  # Count total items
            cursor.close()

            # Calculate total pages
            total_pages = (total_items // per_page) + (1 if total_items % per_page > 0 else 0)

            # Adjust the query to return only the selected page's data
            query += " LIMIT %s OFFSET %s"
            cursor = mysql.connection.cursor()
            cursor.execute(query, params + (per_page, offset))
            constituencies = cursor.fetchall()
            cursor.close()

            return render_template(
                'dashboard.html', 
                user=user, 
                constituencies=constituencies, 
                current_page=page, 
                total_pages=total_pages, 
                per_page=per_page
            )

    return redirect(url_for('login'))

#----------->Dashboard END<---------------#


#5----------->ADMIN Login Start<---------------#

# Admin Login Route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()  # Use the same form as regular login
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Retrieve admin from the 'admins' table
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE email_address=%s", (email,))  # Query the admins table
        admin = cursor.fetchone()
        cursor.close()

        if admin and password == admin[3]:  # Assuming password is at index 3
            session['user_id'] = admin[0]  # Assuming ID is at index 0
            session['role'] = 'admin'  # Assign 'admin' role

            flash('Admin Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard

        else:
            flash('Login failed! Incorrect email or password.', 'danger')

    return render_template('admin_login.html', form=form)

@app.route('/')
def index():
    return render_template('index.html')  # Ensure this file exists in your templates folder

#----------->ADMIN Login End<---------------#

#6----------->ADMIN Dashboard Start<---------------#
# Admin Dashboard
@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        # Fetch users
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

        # Fetch constituencies
        cursor.execute("SELECT * FROM constituencies")
        constituencies = cursor.fetchall()

        # Fetch constituency managers
        cursor.execute("SELECT * FROM constituency_managers")
        managers = cursor.fetchall()

        # Fetch helpers
        cursor.execute("SELECT * FROM helpers")
        helpers = cursor.fetchall()
        cursor.close()

        return render_template(
            'admin_dashboard.html',
            users=users,
            constituencies=constituencies,
            managers=managers,
            helpers=helpers
        )
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    

        #############################
        ###     CRUD FOR USERS    ###
        #############################

#Add User Page
@app.route('/admin/create_user', methods=['GET', 'POST'])
def create_user_page():
    if request.method == 'POST':
        # Fetch the form inputs
        name = request.form['name']
        email_address = request.form['email_address']
        password = request.form['password']

        # Insert into the database
        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO users (name, email_address, password)
            VALUES (%s, %s, %s)
        """, (name, email_address, password))
        mysql.connection.commit()
        cursor.close()

        flash('User added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Render the form template
    return render_template('create_user.html')


#Update User Page
@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user_page(user_id):
    # Fetch the user's current data
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if request.method == 'POST':
        # Get updated data from the form
        name = request.form['name']
        email_address = request.form['email_address']

        # Update the user in the database
        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE users 
            SET name=%s, email_address=%s 
            WHERE user_id=%s
        """, (name, email_address, user_id))
        mysql.connection.commit()
        cursor.close()

        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Render the update form with current user data
    return render_template('update_user.html', user=user)

#Delete User
@app.route('/admin/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    # Delete the user from the database
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))  # Use user_id instead of id
    mysql.connection.commit()
    cursor.close()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/constituencies', methods=['GET', 'POST'])
def manage_constituencies():
    if 'role' in session and session['role'] == 'user':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')
        if not action:
            flash('Invalid action.', 'danger')
            return redirect(url_for('manage_constituencies'))

        try:
            cursor = mysql.connection.cursor(DictCursor)
            if action == 'add':
                # Add new constituency (FIXED)
                name = request.form['name']
                mp = request.form['mp']
                mp_email = request.form['mp_email']
                area = request.form['area']
                country = request.form['country']
                cursor.execute("""
                    INSERT INTO constituencies (name, mp, mp_email, area, country)
                    VALUES (%s, %s, %s, %s, %s)
                """, (name, mp, mp_email, area, country))  # Added mp_email
                flash('Constituency added successfully!', 'success')

            elif action == 'update':
                # Update existing constituency (FIXED)
                constituency_id = request.form['constituency_id']
                name = request.form['name']
                mp = request.form['mp']
                mp_email = request.form['mp_email']  # Added
                area = request.form['area']
                country = request.form['country']
                cursor.execute("""
                    UPDATE constituencies
                    SET name = %s, mp = %s, mp_email = %s, area = %s, country = %s
                    WHERE constituency_id = %s
                """, (name, mp, mp_email, area, country, constituency_id))  # Added mp_email
                flash('Constituency updated successfully!', 'success')

            elif action == 'delete':
                # Delete constituency (unchanged)
                constituency_id = request.form['constituency_id']
                cursor.execute("DELETE FROM constituency_managers WHERE constituency_id = %s", (constituency_id,))
                cursor.execute("DELETE FROM constituencies WHERE constituency_id = %s", (constituency_id,))
                flash('Constituency deleted successfully!', 'success')

            mysql.connection.commit()
            cursor.close()

        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            if cursor:
                cursor.close()

        return redirect(url_for('manage_constituencies'))

    # Handle GET request (FIXED search)
    search_query = request.args.get('search', '')
    try:
        cursor = mysql.connection.cursor(DictCursor)
        if search_query:
            cursor.execute("""
                SELECT * FROM constituencies
                WHERE name LIKE %s 
                OR mp LIKE %s 
                OR mp_email LIKE %s  # Added email search
                OR area LIKE %s 
                OR country LIKE %s
            """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute("SELECT * FROM constituencies")
        constituencies = cursor.fetchall()
        cursor.close()
    except Exception as e:
        flash(f'Error fetching constituencies: {str(e)}', 'danger')
        constituencies = []

    return render_template('manage_constituencies.html', constituencies=constituencies, search_query=search_query)

# Constituency CRUD Operations (FIXED)
@app.route('/constituency/create', methods=['POST'])
def create_constituency():
    if 'role' in session and session['role'] == 'user':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    try:
        name = request.form['name']
        mp = request.form['mp']
        mp_email = request.form['mp_email']
        area = request.form['area']
        country = request.form['country']

        cursor = mysql.connection.cursor(DictCursor)
        cursor.execute("""
            INSERT INTO constituencies (name, mp, mp_email, area, country)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, mp, mp_email, area, country))
        mysql.connection.commit()
        cursor.close()

        flash('Constituency created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating constituency: {str(e)}', 'danger')

    return redirect(url_for('manage_constituencies'))

@app.route('/constituency/update', methods=['POST'])
def update_constituency():
    if 'role' in session and session['role'] == 'user':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    try:
        constituency_id = request.form['constituency_id']
        name = request.form['name']
        mp = request.form['mp']
        mp_email = request.form['mp_email']
        area = request.form['area']
        country = request.form['country']

        cursor = mysql.connection.cursor(DictCursor)
        cursor.execute("""
            UPDATE constituencies 
            SET name = %s, mp = %s, mp_email = %s, area = %s, country = %s 
            WHERE constituency_id = %s
        """, (name, mp, mp_email, area, country, constituency_id))  # Fixed order
        mysql.connection.commit()
        cursor.close()

        flash('Constituency updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating constituency: {str(e)}', 'danger')

    return redirect(url_for('manage_constituencies'))

@app.route('/constituency/delete/<int:constituency_id>', methods=['POST'])
def delete_constituency(constituency_id):
    if 'role' in session and session['role'] == 'user':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('login'))

    try:
        cursor = mysql.connection.cursor(DictCursor)
        cursor.execute("DELETE FROM constituency_managers WHERE constituency_id = %s", (constituency_id,))
        cursor.execute("DELETE FROM constituencies WHERE constituency_id = %s", (constituency_id,))
        mysql.connection.commit()
        cursor.close()
        flash('Constituency deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting constituency: {str(e)}', 'danger')

    return redirect(url_for('manage_constituencies'))

#-----------Manager Routes
@app.route('/admin/managers', methods=['GET', 'POST'])
def manage_managers():
    if 'role' in session and session['role'] == 'admin':
        if request.method == 'POST':
            if 'action' in request.form:
                action = request.form['action']
                cursor = mysql.connection.cursor()
                
                if action == 'add':
                    # Add new manager
                    cursor.execute("""
                        INSERT INTO constituency_managers 
                        (constituency_id, first_name, last_name, hometown, email_address, mobile, origin, origin_details, comments)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        request.form['constituency_id'],
                        request.form['first_name'],
                        request.form['last_name'],
                        request.form['hometown'],
                        request.form['email_address'],
                        request.form['mobile'],
                        request.form['origin'],
                        request.form['origin_details'],
                        request.form.get('comments', '')  # Use get() to handle cases where comments might not be provided
                    ))
                    flash('Manager added successfully!', 'success')

                elif action == 'update':
                    # Update existing manager
                    cursor.execute("""
                        UPDATE constituency_managers
                        SET constituency_id = %s, first_name = %s, last_name = %s, 
                            hometown = %s, email_address = %s, mobile = %s, origin = %s, origin_details = %s, comments = %s
                        WHERE manager_id = %s
                    """, (
                        request.form['constituency_id'],
                        request.form['first_name'],
                        request.form['last_name'],
                        request.form['hometown'],
                        request.form['email_address'],
                        request.form['mobile'],
                        request.form['origin'],
                        request.form['origin_details'],
                        request.form.get('comments', ''),  # Use get() to handle cases where comments might not be provided
                        request.form['manager_id']
                    ))
                    flash('Manager updated successfully!', 'success')

                elif action == 'delete':
                    # Delete manager
                    cursor.execute("""
                        DELETE FROM constituency_managers 
                        WHERE manager_id = %s
                    """, (request.form['manager_id'],))
                    flash('Manager deleted successfully!', 'success')

                mysql.connection.commit()
                cursor.close()
                return redirect(url_for('manage_managers'))

        # Fetch all managers and constituencies
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM constituency_managers")
        managers = cursor.fetchall()
        cursor.execute("SELECT * FROM constituencies")
        constituencies = cursor.fetchall()
        cursor.close()
        return render_template('manage_managers.html', managers=managers, constituencies=constituencies)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))
    
    # Manager CRUD Operations
@app.route('/manager/create', methods=['POST'])
def create_manager():
    if 'role' in session and session['role'] == 'admin':
        try:
            constituency_id = request.form['constituency_id']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            hometown = request.form['hometown']
            email_address = request.form['email_address']
            mobile = request.form['mobile']
            origin = request.form['origin']
            origin_details = request.form['origin_details']
            comments = request.form.get('comments', '')  # Use get() to handle cases where comments might not be provided

            cursor = mysql.connection.cursor()
            cursor.execute("""
                INSERT INTO constituency_managers 
                (constituency_id, first_name, last_name, hometown, email_address, mobile, origin, origin_details, comments)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (constituency_id, first_name, last_name, hometown, email_address, mobile, origin, origin_details, comments))
            mysql.connection.commit()
            cursor.close()
            
            flash('Manager created successfully!', 'success')
        except Exception as e:
            flash(f'Error creating manager: {str(e)}', 'danger')
            
        return redirect(url_for('manage_managers'))
    return redirect(url_for('login'))

@app.route('/manager/update', methods=['POST'])
def update_manager():
    if 'role' in session and session['role'] == 'admin':
        try:
            manager_id = request.form['manager_id']
            constituency_id = request.form['constituency_id']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            hometown = request.form['hometown']
            email_address = request.form['email_address']
            mobile = request.form['mobile']
            origin = request.form['origin']
            origin_details = request.form['origin_details']
            comments = request.form.get('comments', '')  # Use get() to handle cases where comments might not be provided

            cursor = mysql.connection.cursor()
            cursor.execute("""
                UPDATE constituency_managers 
                SET constituency_id=%s, first_name=%s, last_name=%s, hometown=%s, 
                    email_address=%s, mobile=%s, origin=%s, origin_details=%s, comments=%s 
                WHERE manager_id=%s
            """, (constituency_id, first_name, last_name, hometown, email_address, 
                 mobile, origin, origin_details, comments, manager_id))
            mysql.connection.commit()
            cursor.close()
            
            flash('Manager updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating manager: {str(e)}', 'danger')
            
        return redirect(url_for('manage_managers'))
    return redirect(url_for('login'))

@app.route('/manager/delete/<int:manager_id>', methods=['POST'])
def delete_manager(manager_id):
    if 'role' in session and session['role'] == 'admin':
        try:
            cursor = mysql.connection.cursor()
            # First, delete related records in helpers
            cursor.execute("DELETE FROM helpers WHERE manager_id = %s", (manager_id,))
            # Then delete the manager
            cursor.execute("DELETE FROM constituency_managers WHERE manager_id = %s", (manager_id,))
            mysql.connection.commit()
            cursor.close()
            
            flash('Manager deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting manager: {str(e)}', 'danger')
            
        return redirect(url_for('manage_managers'))
    return redirect(url_for('login'))

#-----------Helper Routes
@app.route('/admin/helpers', methods=['GET', 'POST'])
def manage_helpers():
    if 'role' in session and session['role'] == 'admin':
        if request.method == 'POST':
            if 'action' in request.form:
                action = request.form['action']
                cursor = mysql.connection.cursor()
                try:
                    if action == 'add':
                        # Convert empty strings to None for nullable fields
                        mobile = request.form['mobile'].strip() or None
                        origin_details = request.form['origin_details'].strip() or None
                        comments = request.form.get('comments', '').strip() or None

                        cursor.execute("""
                           INSERT INTO helpers 
                            (manager_id, first_name, last_name, hometown, email_address, mobile, origin, origin_details, comments)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            request.form['manager_id'],
                            request.form['first_name'],
                            request.form['last_name'],
                            request.form['hometown'],
                            request.form['email_address'],
                            mobile,
                            request.form['origin'],
                            origin_details,
                            comments
                        ))
                        flash('Helper added successfully!', 'success')

                    elif action == 'update':
                        mobile = request.form['mobile'].strip() or None
                        origin_details = request.form['origin_details'].strip() or None
                        comments = request.form.get('comments', '').strip() or None

                        cursor.execute("""
                            UPDATE helpers
                            SET manager_id = %s, 
                                first_name = %s, 
                                last_name = %s, 
                                hometown = %s, 
                                email_address = %s, 
                                mobile = %s, 
                                origin = %s, 
                                origin_details = %s,
                                comments = %s
                            WHERE helper_id = %s
                        """, (
                            request.form['manager_id'],
                            request.form['first_name'],
                            request.form['last_name'],
                            request.form['hometown'],
                            request.form['email_address'],
                            mobile,
                            request.form['origin'],
                            origin_details,
                            comments,
                            request.form['helper_id']
                        ))
                        flash('Helper updated successfully!', 'success')

                    elif action == 'delete':
                        cursor.execute("DELETE FROM helpers WHERE helper_id = %s", (request.form['helper_id'],))
                        flash('Helper deleted successfully!', 'success')

                    mysql.connection.commit()
                except Exception as e:
                    mysql.connection.rollback()
                    flash(f'An error occurred: {str(e)}', 'danger')
                finally:
                    cursor.close()
                return redirect(url_for('manage_helpers'))

        # Fetch all helpers and managers
        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT h.*, m.constituency_id 
            FROM helpers h
            JOIN constituency_managers m ON h.manager_id = m.manager_id
        """)
        helpers = cursor.fetchall()
        cursor.execute("SELECT * FROM constituency_managers")
        managers = cursor.fetchall()
        cursor.close()
        return render_template('manage_helpers.html', helpers=helpers, managers=managers)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

# Helper CRUD Operations
@app.route('/helper/create', methods=['POST'])
def create_helper():
    if 'role' in session and session['role'] == 'admin':
        try:
            # Get form data with proper null handling
            data = {
                'manager_id': request.form['manager_id'],
                'first_name': request.form['first_name'],
                'last_name': request.form['last_name'],
                'hometown': request.form['hometown'],
                'email_address': request.form['email_address'],
                'mobile': request.form['mobile'].strip() or None,
                'origin': request.form['origin'],
                'origin_details': request.form['origin_details'].strip() or None,
                'comments': request.form.get('comments', '').strip() or None
            }

            cursor = mysql.connection.cursor()
            cursor.execute("""
                INSERT INTO helpers 
                (manager_id, first_name, last_name, hometown, email_address, mobile, origin, origin_details, comments)
                VALUES (%(manager_id)s, %(first_name)s, %(last_name)s, %(hometown)s, 
                        %(email_address)s, %(mobile)s, %(origin)s, %(origin_details)s, %(comments)s)
            """, data)
            mysql.connection.commit()
            cursor.close()
            
            flash('Helper created successfully!', 'success')
        except Exception as e:
            flash(f'Error creating helper: {str(e)}', 'danger')
            
        return redirect(url_for('manage_helpers'))
    return redirect(url_for('login'))

@app.route('/helper/update', methods=['POST'])
def update_helper():
    if 'role' in session and session['role'] == 'admin':
        try:
            data = {
                'helper_id': request.form['helper_id'],
                'manager_id': request.form['manager_id'],
                'first_name': request.form['first_name'],
                'last_name': request.form['last_name'],
                'hometown': request.form['hometown'],
                'email_address': request.form['email_address'],
                'mobile': request.form['mobile'].strip() or None,
                'origin': request.form['origin'],
                'origin_details': request.form['origin_details'].strip() or None,
                'comments': request.form.get('comments', '').strip() or None
            }

            cursor = mysql.connection.cursor()
            cursor.execute("""
                UPDATE helpers 
                SET manager_id = %(manager_id)s,
                    first_name = %(first_name)s,
                    last_name = %(last_name)s,
                    hometown = %(hometown)s,
                    email_address = %(email_address)s,
                    mobile = %(mobile)s,
                    origin = %(origin)s,
                    origin_details = %(origin_details)s,
                    comments = %(comments)s
                WHERE helper_id = %(helper_id)s
            """, data)
            mysql.connection.commit()
            cursor.close()
            
            flash('Helper updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating helper: {str(e)}', 'danger')
            
        return redirect(url_for('manage_helpers'))
    return redirect(url_for('login'))

@app.route('/helper/delete/<int:helper_id>', methods=['POST'])
def delete_helper(helper_id):
    if 'role' in session and session['role'] == 'admin':
        try:
            cursor = mysql.connection.cursor()
            cursor.execute("DELETE FROM helpers WHERE helper_id = %s", (helper_id,))
            mysql.connection.commit()
            cursor.close()
            
            flash('Helper deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting helper: {str(e)}', 'danger')
            
        return redirect(url_for('manage_helpers'))
    return redirect(url_for('login'))
#---------------REPORTS START----------------->

@app.route('/reports')
def reports():
    if 'role' in session and session['role'] == 'admin':
        cursor = mysql.connection.cursor(DictCursor)
    
        # Fetch constituencies
        cursor.execute("SELECT * FROM constituencies")
        constituencies = cursor.fetchall()
    
        # Fetch managers with their corresponding constituency names
        cursor.execute("""
        SELECT cm.*, c.name AS constituency_name 
        FROM constituency_managers cm 
        LEFT JOIN constituencies c ON cm.constituency_id = c.constituency_id
        """)
        managers = cursor.fetchall()
    
        # Calculate summary statistics
        total_constituencies = len(constituencies)
        managed_constituencies_count = sum(1 for m in managers if m['constituency_id'])
        manager_coverage_percentage = (managed_constituencies_count / total_constituencies * 100) if total_constituencies > 0 else 0
    
        # Fetch unassigned managers
        cursor.execute("SELECT * FROM constituency_managers WHERE constituency_id IS NULL")
        unassigned_managers = cursor.fetchall()
    
        # Fetch managers with at least one helper
        cursor.execute("""
            SELECT cm.*, c.name AS constituency_name, COUNT(h.helper_id) AS helper_count
            FROM constituency_managers cm
            LEFT JOIN constituencies c ON cm.constituency_id = c.constituency_id
            LEFT JOIN helpers h ON cm.manager_id = h.manager_id
            WHERE cm.constituency_id IS NOT NULL
            GROUP BY cm.manager_id
            HAVING helper_count > 0
        """)
        managers_with_helpers = cursor.fetchall()
    
        # Fetch managers without any helpers
        cursor.execute("""
            SELECT cm.*, c.name AS constituency_name
            FROM constituency_managers cm
            LEFT JOIN constituencies c ON cm.constituency_id = c.constituency_id
            LEFT JOIN helpers h ON cm.manager_id = h.manager_id
            WHERE cm.constituency_id IS NOT NULL
            AND h.helper_id IS NULL
        """)
        managers_without_helpers = cursor.fetchall()
    
        cursor.close()
    
        return render_template('reports.html',
            constituencies=constituencies,
            managers=managers,
            total_constituencies=total_constituencies,
            managed_constituencies_count=managed_constituencies_count,
            manager_coverage_percentage=manager_coverage_percentage,
            unassigned_managers=unassigned_managers,
            managers_with_helpers=managers_with_helpers,
            managers_without_helpers=managers_without_helpers
        )
    else:
        # Redirect non-admin users to the login page or show an error
        return redirect(url_for('login'))
#---------------REPORTS END----------------->


# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)