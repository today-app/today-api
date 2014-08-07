import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import logging
import simplejson as json
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, request, render_template, jsonify, redirect, url_for
from flask.ext.login import current_user, login_required, logout_user, login_user, LoginManager
from flask.ext.sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from forms import LoginForm

from models import Client, Grant, Token, User, Base

from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket, TTransport
from gen.today import TodayInternalApiService

app = Flask(__name__)
oauth = OAuth2Provider(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sched.db'
app.config['SECRET_KEY'] = 'enydM2ANhdcoKwdVa0jWvEsbPFuQpMjf'

db = SQLAlchemy(app)
db.Model = Base

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to see your appointments.'

logger = logging.getLogger('flask_oauthlib')
logger2 = logging.getLogger('oauthlib')
logger.setLevel(logging.DEBUG)
logger2.setLevel(logging.DEBUG)

fh = logging.FileHandler('flask_oauthlib.log')
fh2 = logging.FileHandler('oauthlib.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
fh2.setFormatter(formatter)

logger.addHandler(fh)
logger2.addHandler(fh2)


@login_manager.user_loader
def load_user(user_id):
    app.logger.debug('load_user({user_id})'.format(user_id=user_id))
    app.logger.debug(db.session.query(User).get(user_id))
    return db.session.query(User).get(user_id)


@oauth.clientgetter
def load_client(client_id):
    app.logger.debug('load_client({client_id})'.format(client_id=client_id))
    return db.session.query(Client).filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    app.logger.debug('load_grant({client_id}, {code})'.format(client_id=client_id, code=code))
    return db.session.query(Grant).filter_by(client_id=client_id, code=code).first()


def get_current_user():
    app.logger.debug('get_current_user()')
    return db.session.query(User).get(current_user.id)


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # app.logger.debug( 'save_grant({client_id}, {code}, {redirect_uri}, ...)'.format( client_id=client_id, code=code['code'], redirect_uri=request.redirect_uri))
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    # app.logger.debug(get_current_user())
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    # app.logger.debug('load_token')
    # app.logger.debug( 'access_token={access_token}/refresh_token={refresh_token}'.format( access_token=access_token, refresh_token=refresh_token ))
    if access_token:
        # app.logger.debug('== access_token ==')
        # app.logger.debug(db.session.query(Token).filter_by( access_token=access_token).first())
        return db.session.query(Token).filter_by(access_token=access_token).first()
    elif refresh_token:
        # app.logger.debug('== refresh_token ==')
        # app.logger.debug(db.session.query(Token).filter_by( refresh_token=refresh_token).first())
        return db.session.query(Token).filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    # app.logger.debug('save_token')
    #toks = db.session.query(Token).filter_by(client_id=request.client.client_id,
    #                             user_id=request.user.id).all()
    #app.logger.debug('client_id={client_id}, user_id={user_id}'.format(client_id=request.client.client_id, user_id=request.user.id))
    #app.logger.debug(toks)
    ## make sure that every client has only one token connected to a user
    #db.session.delete(toks)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    # app.logger.debug(token)

    #from pprint import pprint
    # import pprint
    # from inspect import getmembers
    #
    # pp = pprint.PrettyPrinter(indent=4)
    #
    # app.logger.debug('=' * 80)
    # app.logger.debug(pp.pformat(getmembers(request)))
    # app.logger.debug('=' * 80)
    # app.logger.debug(pp.pformat(getmembers(current_user)))
    # app.logger.debug('=' * 80)
    #app.logger.debug(current_user.dir())
    tok = Token(**token)
    tok.expires = expires
    tok.client_id = request.client.client_id

    if not request.user:
        tok.user_id = current_user.id
    else:
        tok.user_id = request.user.id

        #if hasattr(request, 'user'):
        #tok.user_id = request.user.id
        #elif current_user.id:
        #tok.user_id = current_user.id
    #tok.user_id = current_user.id
    db.session.add(tok)
    db.session.commit()
    return tok


@oauth.usergetter
def get_user(username, password, *args, **kwargs):
    # app.logger.debug('get_user')
    user = User.query.filter_by(username=username).first()
    if user.check_password(password):
        return user
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    # app.logger.debug('authorize')
    # app.logger.debug(request)
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        #client = Client.query.filter_by(client_id=client_id).first()
        client = db.session.query(Client).filter_by(client_id=client_id).first()
        kwargs['client'] = client
        # app.logger.debug(kwargs)
        return render_template('oauthorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    # app.logger.debug('access_token')
    # app.logger.debug(request.method)
    # app.logger.debug(request.form)
    return None


@app.route('/api/me')
@oauth.require_oauth('email')
def me(request):
    user = request.user
    return jsonify(email=user.email, name=user.name)


@app.route('/api/user/<username>')
@oauth.require_oauth('email')
def user(request, username):
    # app.logger.debug('user')
    user = db.session.query(User).filter_by(name=username).first()
    #user = db.session.query(User).get(username)
    #q = db.session.query(User).filter(User.name==username)
    #user = db.session.query(q).first()
    # app.logger.debug(user)
    return jsonify(email=user.email, username=user.name)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    # app.logger.debug(request.form)
    error = None
    if request.method == 'POST' and form.validate():
        email = form.username.data.lower().strip()
        password = form.password.data.lower().strip()
        user, authenticated = User.authenticate(db.session.query, email, password)
        if authenticated:
            login_user(user)
            # return redirect(url_for('authorize'))
            return redirect(request.args.get("next") or url_for("authorize"))
        else:
            error = 'Incorrect username or password. Try again.'
    return render_template('user/login.html', form=form, error=error)


@app.route('/logout/')
def logout():
    logout_user()
    return redirect(url_for('login'))


from flask.ext.restful import reqparse, abort, Api, Resource

api = Api(app)

#TODOS = {
    #'todo1': {'task': 'build an API'},
    #'todo2': {'task': '?????'},
    #'todo3': {'task': 'profit!'},
#}


#def abort_if_todo_doesnt_exist(todo_id):
    #if todo_id not in TODOS:
        #abort(404, message="Todo {} doesn't exist".format(todo_id))


parser = reqparse.RequestParser()
#parser.add_argument('task', type=str)
parser.add_argument('letter', type=str)
parser.add_argument('Authorization', type=str, location='headers', required=False)


def oauth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        f = oauth.require_oauth('email')
        return f

    return wrapper

## Todo
##   show a single todo item and lets you delete them
#class Todo(Resource):
    #method_decorators = [oauth.require_oauth('email')]

    #def get(self, request, todo_id):
        #abort_if_todo_doesnt_exist(todo_id)
        #app.logger.debug('Todo.get(self, %s, %s)' % (request, todo_id))
        #app.logger.debug('Todo.get > %s' % (request.user.email))
        #return TODOS[todo_id]

    #def delete(self, todo_id):
        #abort_if_todo_doesnt_exist(todo_id)
        #del TODOS[todo_id]
        #return '', 204

    #def put(self, todo_id):
        #args = parser.parse_args()
        #task = {'task': args['task']}
        #TODOS[todo_id] = task
        #return task, 201


## TodoList
##   shows a list of all todos, and lets you POST to add new tasks
#class TodoList(Resource):
    #method_decorators = [oauth.require_oauth('email')]

    #def get(self, request):
        #print 'TodoList.get()'
        #app.logger.debug('TodoList.get(self, %s)' % (request))

        #return TODOS

    #def post(self):
        #args = parser.parse_args()
        #todo_id = 'todo%d' % (len(TODOS) + 1)
        #TODOS[todo_id] = {'task': args['task']}
        #return TODOS[todo_id], 201



class LetterItem(Resource):
    method_decorators = [oauth.require_oauth('email')]

    def get(self, request, letter_id):
        THRIFT_HOST = '127.0.0.1'
        THRIFT_PORT = '9091'
        socket = TSocket.TSocket(THRIFT_HOST, THRIFT_PORT)
        transport = TTransport.TFramedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = TodayInternalApiService.Client(protocol)
        transport.open()
        resp = client.letters_get(1, letter_id)

        # return jsonify(json.loads(resp.result))
        LETTER = json.loads(resp.result)
        transport.close()
        return LETTER

    def delete(self, request, letter_id):
        app.logger.debug('LetterItem.delete():')
        THRIFT_HOST = '127.0.0.1'
        THRIFT_PORT = '9091'
        socket = TSocket.TSocket(THRIFT_HOST, THRIFT_PORT)
        transport = TTransport.TFramedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = TodayInternalApiService.Client(protocol)
        transport.open()
        resp = client.letters_get(1, letter_id)

        app.logger.debug('LetterItem():')
        app.logger.debug(resp.code)
        app.logger.debug(resp.result)
        # return jsonify(json.loads(resp.result))
        LETTER = json.loads(resp.result)
        transport.close()

        # 1. get letter
        # 1-1 if not found exception, handle it 
        # 2. check permission
        # 3. return result

        return {'message': 'ok'}

    def put(self, request, letter_id):
        # update letter content
        app.logger.debug('LetterItem.put():')
        return {'message': 'ok'}


class LetterList(Resource):
    method_decorators = [oauth.require_oauth('email')]

    def get(self, request):
        THRIFT_HOST = '127.0.0.1'
        THRIFT_PORT = '9091'
        socket = TSocket.TSocket(THRIFT_HOST, THRIFT_PORT)
        transport = TTransport.TFramedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = TodayInternalApiService.Client(protocol)
        transport.open()
        resp = client.letters_all('{}', '{}')

        app.logger.debug('letters():')
        app.logger.debug(resp.code)
        app.logger.debug(resp.result)
        # return jsonify(json.loads(resp.result))
        LETTERS = json.loads(resp.result)
        transport.close()
        return LETTERS

    def post(self, request):
        user_id = request.user.id

        args = parser.parse_args()
        #todo_id = 'todo%d' % (len(TODOS) + 1)
        #TODOS[todo_id] = {'task': args['task']}
        #return TODOS[todo_id], 201
        letter_json = args['letter']
        app.logger.debug('LetterList/post')
        app.logger.debug('user_id: %d', user_id)
        app.logger.debug('letter_json: %s', letter_json)

        THRIFT_HOST = '127.0.0.1'
        THRIFT_PORT = '9091'
        socket = TSocket.TSocket(THRIFT_HOST, THRIFT_PORT)
        transport = TTransport.TFramedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = TodayInternalApiService.Client(protocol)
        transport.open()
        resp = client.letter_create(user_id, letter_json)

        app.logger.debug('letter_create():')
        app.logger.debug(resp.code)
        app.logger.debug(resp.result)
        # return jsonify(json.loads(resp.result))
        LETTERS = json.loads(resp.result)
        transport.close()
        return LETTERS


class CommentItem(Resource):
    method_decorators = [oauth.require_oauth('email')]

    def delete(self, request, letter_id, comment_id):
        app.logger.debug('CommentItem.delete():')
        app.logger.debug('letter_id: %s, comment_id: %s' % (letter_id, comment_id))
        return {'message': 'ok'}


class CommentList(Resource):
    method_decorators = [oauth.require_oauth('email')]

    def get(self, request, letter_id):
        # COMMENTS = [{'name': 'foo'}, {'name': 'bar'}]
        # return COMMENTS
        app.logger.debug('CommentList.get():')
        app.logger.debug('letter_id: %s' % letter_id)
        return {'message': 'ok'}

    def post(self, request, letter_id):
        app.logger.debug('CommentList.post():')
        app.logger.debug('letter_id: %s' % letter_id)
        return {'message': 'ok'}


##
## Actually setup the Api resource routing here
##
#api.add_resource(TodoList, '/todos')
#api.add_resource(Todo, '/todos/<string:todo_id>')

api.add_resource(LetterList, '/letters')
api.add_resource(LetterItem, '/letter/<string:letter_id>')
api.add_resource(CommentList, '/letter/<string:letter_id>/comments')
api.add_resource(CommentItem, '/letter/<string:letter_id>/comment/<string:comment_id>')
