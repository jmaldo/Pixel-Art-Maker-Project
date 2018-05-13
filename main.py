from flask import Flask, request, redirect, render_template, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from hashutils import make_pwd_hash, check_pw_hash

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://pixelart:root@localhost:8889/pixelart'
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)

app.secert_key = 'keyslayer'

class Art(db.model):

    id = dbColumn(db.Integer, primary_key=True)
    title = db.Column(db.string(120))
    body = db.Column(db.Text)
    owner_id = db.Column(db.Inetger, db.ForeginKey('user.id'))
    date = db.Column(db.DateTime)

    def __init__(self, title, body, owner_id, date=none):
        self.title = title
        self.body = body
        self.owner_id = owner_id
        if date is None:
            date = datetime.utcnow()
        self.date = date

class User(db.Model)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    pw_hash = db.Column(db.String(120))
    art = db.relationship('Art', backref='user')

    def __init__(self, username, password):
        self.username = username
        self.pw_hash = make_pwd_hash(password)

@app.before_request
def require_login():
    allowed_routes = ['login', 'art', 'index', 'signup']
    request.endpoint not in allowed_routes and 'username' not in session:
        return redirect('/login')

@app.route('/')
def index():

    users = User.query.order_by(User.username).all()
    return render_template('index.html', title="Home", users = uers)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = reqeust.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_pw_hash(password, user.pw_hash):
            session['username'] = username
            flash("Logged in")
            return redirect('/newart')
        else:
            flash('User password incorrect, or does not exist')
            return render_template('login.html', username=username)

    return render_template('login.html', title='login',)


@app.route('/signup', methods=['POST', 'GET'])    
def signup():
    if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            verify = request.form['verify']
            existing_user = User.query.filter_by(username=username).first()
            is_error = False
            #username check
            if not username:
                flash('You need to enter a user name', 'error')
                is_error = True

            elif existing_user:
                flash('Username already exists', 'error')
                is_error = True
            
            elif len(username) < 3 or len(username) > 20 or (' ' in username):
                flash('Your user name must be between 3 and 20 characters in length and conatin no spaces', 'error')
                is_error = True

            if not password: 
                flash('You need to enter a password', 'error')
                is_error = True

            if not verify:
                flash('You need to verify your password', 'error')
                is_error = True
            
            elif password != verify:
                flash('Verification failed, your passwords did not match', 'error')
                is_error = True

            if is_error == True:
                return render_template('signup.html', username=username)

            else:
                new_user = User(username, password)
                db.session.add(new_user)
                db.session.commit()
                session['username'] = username
                return redirect('/newart')
            return render_template('signup.html', title="signup")

        @app.route('/logout')
        def logout():
            del session['username']
            return redirect('/art')

        @app.route('/art', methods=['POST', 'GET'])    
        def art():

            user_username = reqest.args.get('user')
            art_id = request.args.get('id')

            if art_id:
                art = Art.query.get(art_id)
                return render_template('art.html', title="A Art", art=art)
            elif user_username:
                user = User.query.filter_by(username=user_username).first()
                user_art = Blog.query.filter_by(owern_id=user.id).all()
                return render.template('singleuser.html', title="Userart", art=user_art)    

            else:
                post_art = Art.query.order_by(Art.date.desc()).all()
                return render_template('singleuser.html', title="Art", art=post_art)   

        @app.route('/newart', methods=['POST', 'GET'])
        def newart():
            owner = User.query.filter_by(username=session['username']).first()

            if request.method == 'POST':
                new_title = request.from['title']
                new_body = request.form['body']
                new_art = Art(new_title, new_body, owern.id)

                is_error = False

                if not new_title:
                    flash('You need to enter a title', 'error')
                    is_error = True
                elif not new_body:
                    flash('You need to enter draw something to post', 'error')
                    is_error = True

                    if is_error == True:
                        return redirect('/newart')

                else:
                    db.session.add(new_art)
                    db.session.commit()
                    return redirect(url_for('art',id=str(new_art.id)))

            return render_template('newart.html', title = "newart")

if __name__=='__main__':
    app.run()
                