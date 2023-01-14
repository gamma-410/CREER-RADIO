from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '5730292743938474948439320285857603'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    title = db.Column(db.Text)
    md5 = db.Column(db.Text)
    detail = db.Column(db.Text)


# ログインデータ
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    detail = db.Column(db.Text)
    email = db.Column(db.String(100), nullable=False, unique=True)
    md5 = db.Column(db.Text)
    password = db.Column(db.String(25), nullable=False)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template("index.html")

    else:
        email = request.form.get('email')
        password = request.form.get('password')

        # Check
        if email:
            pass
        else:
            flash("メールアドレスが入力されていません")
            return redirect('/')

        if password:
            pass
        else:
            flash("パスワードが入力されていません")
            return redirect('/')

        user = User.query.filter_by(email=email).first()

        if user:
            pass
        else:
            flash("メールアドレスまたはパスワードが間違っています。<br>ご確認の上もう一度お試しください。")
            return redirect('/')
        # Check END

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect('/home')

        else:
            flash("メールアドレスまたはパスワードが間違っています。<br>ご確認の上もう一度お試しください。")
            return redirect('/')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template("signup.html")

    else:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        detail = "プロフィールを設定しよう!"

        # Check
        if username:
            pass
        else:
            flash("ユーザー名が設定されていません")
            return redirect('/signup')

        if email:
            pass
        else:
            flash("メールアドレスが設定されていません")
            return redirect('/signup')

        if password:
            pass
        else:
            flash("パスワードが設定されていません")
            return redirect('/signup')

        userData = User.query.filter_by(username=username).first()

        if userData == None:
            pass
        else:
            flash("同じ名前のユーザーが既に存在しています")
            return redirect('/signup')
        # Check END

        # Create New User
        createUser = User(
            username = username,
            email = email,
            md5 = hashlib.md5(email.encode("utf-8")).hexdigest(),
            detail = detail,
            password = generate_password_hash(password, method='sha256')
        )

        db.session.add(createUser)
        db.session.commit()

        flash("アカウント作成が完了しました！")
        return redirect('/')


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'GET':
        posts = Post.query.order_by(Post.id.desc()).all()
        return render_template("home.html", posts=posts)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'GET':
        return render_template("create.html")

    else:
        username = current_user.username
        title = request.form.get('title')
        detail = request.form.get('detail')
        md5 = hashlib.md5(current_user.email.encode("utf-8")).hexdigest()
        
        # Check
        if username:
            pass
        else:
            flash("ユーザー名が設定されていません")
            return redirect('/create')

        if title:
            pass
        else:
            flash("タイトルが入力されていません")
            return redirect('/create')
        postData = Post.query.filter_by(username=username).first()

        if postData == None:
            pass
        else:
            flash("ルームを終了させてください !!")
            return redirect('/create')
        # Check END

        # Create New Room
        createRoom = Post (
            username = username,
            title = title,
            md5 = md5,
            detail = detail
        )

        db.session.add(createRoom)
        db.session.commit()

        return redirect(f'/room/{ username }')


@app.route('/room/<string:username>')
def room(username):
    roomdata = Post.query.filter_by(username=username).first()
    userdata = User.query.filter_by(username=roomdata.username).first()
    return render_template("room.html", roomdata=roomdata, userdata=userdata)


@app.route('/del/<int:id>')
def delete(id):
    post = Post.query.get(id)
    db.session.delete(post)
    db.session.commit()
    return redirect('/home')


@app.route('/users/<int:id>')
def users(id):
    userdata = User.query.filter_by(id=id).first()
    return render_template("profile.html", userdata=userdata)


@app.route('/edit_profile/<int:id>', methods=['GET', 'POST'])
@login_required
def editProfile(id):
    if request.method == "GET":
        return render_template('editprof.html')

    else:
        if id == current_user.id:
            try:
                detail = request.form.get('detail')

                if detail:
                    user = User.query.filter_by(id=id).first()
                    user.detail = detail
                    db.session.merge(user)
                    db.session.commit()
                else:
                    pass

                flash("プロフィールを変更しました!")
                return redirect(f'/users/{ id }')

            except:
                flash("プロフィールの変更に失敗しました...")
                return redirect(f'/users/{ id }')
        else:
            flash("ログインしているアカウントが異なります...")
            return redirect(f'/users/{ id }')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


# ログイン前はリダイレクト
@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=80)
