from flask import *
from forms import RegistrationForm, LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required


app = Flask(__name__)
app.config['SECRET_KEY'] = '664aa76e2e3d0bf72ba19b4bbadd0331'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sample.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Send the user to the default login route
login_manager.login_message_category = 'danger'  # Show red alert, user not logged in


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# UserMixin to manage sessions etc.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"'{self.username}', '{self.email}'"


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in', category='success')
        return redirect(url_for('protected'))
    form = RegistrationForm()

    # If form is validated when submitted
    if form.validate_on_submit():
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # Create a user instance
        user = User(username=form.username.data,
                    password=hashed_password,
                    email=form.email.data)
        db.session.add(user)  # Add user to db
        db.session.commit()

        flash(f'{form.username.data} is registered', category='success')
        return redirect(url_for('protected'))  # Go to protected page
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in', category='success')
        return redirect(url_for('protected'))

    form = LoginForm()
    if form.validate_on_submit():

        # Check if email is in db
        user = User.query.filter_by(email=form.email.data).first()

        # If user exists and password hash matches
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remeber.data)  # Login user, with remember me status
            return redirect(url_for('protected'))
        else:
            flash('Login unsuccessful, retry', category='danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/protected')
@login_required
def protected():
    """ Cannot be accessed by unauthenticated users. """
    user = list(User.query.all())
    return render_template('protected.html', user=user)


@app.route('/logout')
def logout():
    """ Logout user and send back to home """
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
