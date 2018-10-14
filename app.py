#!/usr/bin/env python3

import sqlite3, time, os, binascii
from passlib.hash import bcrypt
from flask import Flask
from flask import abort
from flask import flash
from flask import g
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import send_from_directory

from flask_seasurf import SeaSurf

app = Flask(__name__, static_url_path='')
csrf = SeaSurf(app)

DATABASE = './app.db'
app.secret_key = '2ea67cc186f0da342bc81ffbdb3a1880' # un-hardcode me after dev
#app.secret_key = binascii.hexlify(os.urandom(32))

def dict_factory(cursor, row):
	d = {}
	for idx, col in enumerate(cursor.description):
		d[col[0]] = row[idx]
	return d

def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DATABASE)
		db.row_factory = dict_factory
	return db

@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()

def user_exists(username):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id FROM users WHERE username = ? LIMIT 1',(username,))
		res = cur.fetchone()
		if res is not None:
			return True
		return False
	except Exception as e:
		print(e)
		return False

def register(username, password):
	if user_exists(username):
		return {'status': False, 'message': 'UserName Exists, <a href="/forgot">forgot password?</a>'}
	if password == '':
		return {'status': False, 'message': 'Password Too $hort!'}
	if username == '':
		return {'status': False, 'message': 'Username Too $hort!'}
	try:
		cur = get_db().cursor()
		cmd = '''INSERT INTO users (username, password, score) VALUES (?, ?, 0)'''
		password_hash = bcrypt.encrypt(password, rounds=8)
		cur.execute(cmd,(username,password_hash))
		cur.connection.commit()
		login(username,password)
		return {'status': True, 'message': 'Registration Successful'}
	except Exception as e:
		print(e)
		return {'status': False, 'message': str(e)}

def login(username,password):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id, username, email, password FROM users WHERE username = ? LIMIT 1', (username,))
		res = cur.fetchone()
		if res is None:
			return False
		if not bcrypt.verify(password,res.get('password')):
			return False
		session['userid'] = res.get('id')
		session['username'] = res.get('username')
		session['email'] = res.get('email')
		return True
	except Exception as e:
		print(e)
		return False

def is_logged_in():
	return True if session.get('userid') else False

def get_user_solved(userid):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT challengeid FROM scoreboard WHERE userid = ?', (userid,))
		res = cur.fetchall()
		print('get_user_solved out:', repr(res))
		return res if res is not None else []
	except Exception as e:
		print(e)
		return [{'fuck': 'shit'}]

def is_legit_problem(problem_id):
	challs = get_challenges()
	if problem_id in [chall.get('id') for chall in challs]:
		return True
	return False

def get_flag(problem_id):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id, flag FROM challenges WHERE id = ? LIMIT 1', (problem_id,))
		res = cur.fetchone()
		if res == '':
			return {'status': False, 'message': 'Unknown Problem'}
		return res
	except Exception as e:
		print(e)
		return {'fuck': 'shit'}

def award_solve(problem_id):
	try:
		userid = session.get('userid')
		cur = get_db().cursor()
		challs = get_challenges()
		points = 0
		now = int(time.time())
		points = get_challenges(challenge_id=problem_id).get('points')
		cmd = '''INSERT INTO scoreboard (userid, challengeid, points, occured) VALUES (?,?,?,?)'''
		cur.execute(cmd, (userid,problem_id, points, now))
		cmd = '''UPDATE users SET score = score + ? WHERE id = ? LIMIT 1'''
		cur.execute(cmd, (points, userid))
		cur.connection.commit()
		return True
	except Exception as e:
		print(e)
		return False

def grade_flag(problem_id,userid,send_flag):
	if problem_id in [x.get('challengeid') for x in get_user_solved(session.get('userid'))]:
		print('already solved')
		return {'status': False, 'message': 'Already Solved'}
	if not is_legit_problem(problem_id):
		print('Non-existent problem')
		return {'status': False, 'message': 'Non-existent Problem'}
	flag_status = get_flag(problem_id)
	if send_flag.strip() == flag_status.get('flag').strip():
		print('looks good, award them...')
		award_solve(problem_id)
		return {'status': True}
	print(repr(send_flag),flag_status.get('flag'))
	return {'status': False, 'message': 'Incorrect Flag'}

def get_user_score(userid):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT score FROM users WHERE userid = ? LIMIT 1',(userid,))
		res = cur.fetchone()
		if res is not None:
			return res.get('score')
		return 0
	except Exception as e:
		print(e)
		return 0

def get_hl_path(path):
	if path == '/':
		return 'home'
	elif path == '/scores':
		return 'scores'
	elif path == '/rules':
		return 'rules'
	elif path.startswith('/challenge'):
		return 'challenges'
	else:
		return 'home'

def get_challenges(challenge_id=None):
	try:
		cur = get_db().cursor()
		if not challenge_id:
			cur.execute('SELECT id, name, description, points FROM challenges ORDER BY points, id ASC')
			res = cur.fetchall()
			return res if res is not None else {'error': 'unknown challenge'}
		else:
			cur.execute('SELECT id, name, description, points, files FROM challenges WHERE id = ? LIMIT 1', (challenge_id,))
			res = cur.fetchone()
			if res is not None:
				if res.get('files',None) is not None:
					res['files'] = [x.strip() for x in res.get('files').split(',')]
				cur.execute('SELECT count(id) AS the_count FROM scoreboard WHERE challengeid = ?', (challenge_id,))
				solves = cur.fetchone()
				if solves is not None:
					solves = solves.get('the_count')
				res['solves'] = solves
				return res
			else:
				return {'error': 'unknown challenge'}
	except Exception as e:
		print(e)
		return {'error': str(e)}


@app.route('/challenge/<int:challenge_id>',methods=['GET','POST'])
def challenge_route(challenge_id):
	if not is_logged_in():
		return redirect(url_for('index_route'))
	if not is_legit_problem(challenge_id):
		abort(404)
	if request.method == 'POST':
		status = grade_flag(challenge_id,session.get('userid'),request.form.get('flag'))
		print(repr(status))
		if not status.get('status'):
			flash(status.get('message'),'danger')
		else:
			flash('Great Success!','success')
	user_solved = [x.get('challengeid') for x in get_user_solved(session.get('userid'))]
	solved_status = challenge_id in user_solved
	user_info = get_user_info(session.get('userid',0))
	challenges = get_challenges()
	challenge_info = get_challenges(challenge_id)
	hl_path = get_hl_path(request.path)
	site_data = get_site_data()
	return render_template('challenge.html',logged_in=is_logged_in(),user_info=user_info,challenges=challenges,challenge_info=challenge_info,
							hl_path=hl_path,solved_status=solved_status,site_data=site_data)


### defunct route ###
@app.route('/problems', methods=['GET','POST'])
def problems_route():
	if not is_logged_in():
		return redirect(url_for('index_route'))
	message = ''
	user_solved = [x.get('challengeid') for x in get_user_solved(session.get('userid'))]
	if request.method == 'POST':
		try:
			if grade_flag(request.form.get('problem_id'),session.get('userid'),request.form.get('send_flag')).get('status'):
				message = 'congrats, solved'
				user_solved = get_user_solved(session.get('userid'))
			else:
				message = 'nope, sorry'
		except Exception as e:
			print(e)
			message = 'uhhhhh....'
	problem_data = get_challenges()
	print(repr(problem_data))
	print(user_solved)
	return render_template('problems.html',problem_data=problem_data,user_solved=user_solved,message=message)
### end defunct route ###

@app.route('/logout')
def logout_route():
	session.clear()
	return redirect(url_for('index_route'))

def get_user_info(userid):
	cur = get_db().cursor()
	cur.execute('SELECT username, email, score, admin FROM users WHERE id = ? LIMIT 1', (userid,))
	res = cur.fetchone()
	print(repr(res))
	if res is None:
		return res
	res['solved'] = get_user_solved(userid)
	return res

def update_user(form):
	email = form.get('email',None) if form.get('email',None) != '' else None
	password1 = form.get('password1',None) if form.get('password1',None) != '' else None
	password2 = form.get('password2',None) if form.get('password2',None) != '' else None
	print(repr(email),repr(password1),repr(password2))
	if email is not None:
		cur = get_db().cursor()
		cur.execute('UPDATE users SET email = ? WHERE id = ? LIMIT 1',(email.strip(),session.get('userid')))
		cur.connection.commit()
	if all([password1,password2]):
		if password1 == password2:
			password_hash = bcrypt.encrypt(password1.strip(), rounds=8)
			cur = get_db().cursor()
			cur.execute('UPDATE users SET password = ? WHERE id = ? LIMIT 1', (password_hash,session.get('userid')))
			cur.connection.commit()
		else:
			return {'status': False, 'message': 'Passwords did not match'}
	return {'status': True, 'message': 'Profile updated'}

def get_scores():
	try:
		cur = get_db().cursor()
		cur.execute('select userid, sum(points) as score, count(id) as solves,\
			(select username from users where id = userid) AS username, \
			occured from scoreboard group by userid order by score DESC, occured ASC')
		res = cur.fetchall()
		return res
	except Exception as e:
		print(e)
		return []

@app.route('/scores')
def scores_route():
	score_data = get_scores()
	user_info = get_user_info(session.get('userid',0))
	challenges = get_challenges()
	hl_path = get_hl_path(request.path)
	site_data = get_site_data()
	return render_template('scores.html',logged_in=is_logged_in(),user_info=user_info,score_data=score_data, challenges=challenges,
							hl_path=hl_path,site_data=site_data)

@app.route('/profile',methods=['GET','POST'])
def profile_route():
	if request.method == 'POST':
		status = update_user(request.form)
		if not status.get('status'):
			flash(status.get('message'), 'danger')
		else:
			flash(status.get('message'), 'success')
	user_info = get_user_info(session.get('userid',0))
	challenges = get_challenges()
	hl_path = get_hl_path(request.path)
	site_data = get_site_data()
	return render_template('profile.html',logged_in=is_logged_in(),user_info=user_info,challenges=challenges,hl_path=hl_path,site_data=site_data)

def get_site_rules():
	cur = get_db().cursor()
	cur.execute("SELECT setting_value AS site_rules FROM site_data WHERE setting_name = 'site_rules' LIMIT 1")
	res = cur.fetchone()
	rules = res.get('site_rules').split('\n')
	return rules

def get_site_data():
	cur = get_db().cursor()
	cur.execute("SELECT setting_value AS site_title FROM site_data WHERE setting_name = 'site_title' LIMIT 1")
	res = cur.fetchone()
	return res

@app.route('/rules')
def rules_route():
	user_info = get_user_info(session.get('userid',0))
	challenges = get_challenges()
	hl_path = get_hl_path(request.path)
	site_data = get_site_data()
	site_rules = get_site_rules()
	print(repr(site_rules))
	return render_template('rules.html',logged_in=is_logged_in(),user_info=user_info, challenges=challenges,hl_path=hl_path,
							site_data=site_data,site_rules=site_rules)

@app.route('/',methods=['GET','POST'])
def index_route():
	if request.method == 'POST':
		status = login(request.form.get('username','').strip(), request.form.get('password','').strip())
		print("before register\n%s" % (status))
		if not status:
			status = register(request.form.get('username','').strip(), request.form.get('password','').strip())
			if not status.get('status'):
				flash(status.get('message'),'danger')
			else:
				flash(status.get('message'), 'success')
		else:
			flash('Logged In', 'success')
	user_info = get_user_info(session.get('userid',0))
	challenges = get_challenges()
	hl_path = get_hl_path(request.path)
	site_data = get_site_data()
	return render_template('index.html',logged_in=is_logged_in(),user_info=user_info, challenges=challenges,hl_path=hl_path,
							site_data=site_data)

### defunct route ###
@app.route('/login', methods=['GET','POST'])
def login_route():
	message = ''
	if request.method == 'POST':
		if request.form.get('submit') == 'login':
			if login(request.form.get('username'), request.form.get('password')):
				return redirect(url_for('index_route'))
			else:
				message = 'Sorry, Nope'
		elif request.form.get('submit') == 'register':
			status = register(request.form.get('username','').strip(), request.form.get('password','').strip())
			if status.get('status'):
				return redirect(url_for('index_route'))
			else:
				message = status.get('message')
	return render_template('login.html',message=message)
### end defunct route ###

if __name__ == "__main__":
	FLASK_DEBUG=1
	app.run(host='0.0.0.0',port=9005)
