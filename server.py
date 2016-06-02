from flask import Flask, request, redirect, render_template, flash, session
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "lkjf8lelf"

# email_validation is NAME of DB which already exists! 
mysql = MySQLConnector(app, 'loginregistration')

@app.route('/')
def index(): 
	return render_template('index.html')

@app.route('/register', methods=['POST'])
def validate(): 
	email = request.form['email']
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	password = request.form['password']
	password_confirmation = request.form['password_confirmation']
	pw_hash = bcrypt.generate_password_hash(password)

	if len(first_name) < 2: 
		flash('First Name must have at least 2 letters!')
	if len(last_name) < 2: 
		flash('Last Name must have at least 2 letters!')
	elif not (first_name).isalpha(): 
		flash('First Name cannot contain numbers/special characters!')
	elif not (last_name).isalpha():
		flash('Last Name cannot contain numbers/special characters')
	elif not EMAIL_REGEX.match(email): 
		flash("EMAIL IS NOT VALID!", 'error')
	elif len(password) < 8: 
		flash('Password must be at least 8 characters!')
	elif password != password_confirmation: 
		flash('Passwords do not match!')
	else: 
		query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
		data = {
			'first_name': first_name, 
			'last_name': last_name, 
			'email': email, 
			'pw_hash': pw_hash
		}
		mysql.query_db(query, data)
		flash('Successfully registered! Please login to access your data!')
	return redirect('/')

@app.route('/login', methods=['POST'])
def login():
	email = request.form['email']
	password = request.form['password']
	query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	data = {
		'email': email
	}
	user = mysql.query_db(query, data)
	if bcrypt.check_password_hash(user[0]['pw_hash'], password): 
		#login user and redirect 
		session['email'] = email
		return redirect('/success')
	else: 
		#flash error message and redirect
		flash('Email/Password does not match!')
		return redirect('/')

@app.route('/success', methods=['GET'])
def show(): 
	query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	data = {
		'email': session['email']
	}
	user = mysql.query_db(query, data)
	return render_template('success.html', user = user)

@app.route('/logout', methods=['POST'])
def logout(): 
	session.clear()
	return redirect('/')

@app.route('/edit', methods=['GET'])
def edit(): 
	query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	data = {
		'email': session['email']
	}
	user = mysql.query_db(query, data)
	return render_template('update.html', user = user)

@app.route('/update/<user_id>', methods=['POST'])
def update(user_id): 
	query = "UPDATE users SET first_name = :first_name, last_name = :last_name, email = :email WHERE id = :id"
	data = {
		'first_name': request.form['first_name'], 
		'last_name': request.form['last_name'], 
		'email': request.form['email'], 
		'id': user_id
	}
	mysql.query_db(query, data)
	return redirect('/edit')

@app.route('/delete', methods=['POST'])
def delete(): 
	query = "DELETE FROM users WHERE id = :id"
	data = {
		'id': request.form['user_id']
	}
	mysql.query_db(query, data)
	session.clear()
	return redirect('/')
# @app.route('/destroy/<email_id>', methods=['POST'])
# def delete(email_id): 
# 	query = "DELETE FROM emails WHERE id = :id"
# 	data = {'id': email_id}
# 	mysql.query_db(query, data) 
# 	return redirect('/success')

app.run(debug=True)

