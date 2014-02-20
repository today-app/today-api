from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, String, Boolean, Unicode, ForeignKey, UnicodeText, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, synonym, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

Base = declarative_base()

class Client(Base):
    __tablename__ = 'client'
    # human readable name, not required
    name = Column(Unicode(40))

    # human readable description, not required
    description = Column(Unicode(400))

    # creator of the client, not required
    user_id = Column(ForeignKey('user.id'))
    # required if you need to support client credential
    user = relationship('User')

    client_id = Column(Unicode(40), primary_key=True)
    client_secret = Column(Unicode(55), unique=True, index=True,
                              nullable=False)

    # public or confidential
    is_confidential = Column(Boolean)

    _redirect_uris = Column(UnicodeText)
    _default_scopes = Column(UnicodeText)

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(Base):
    __tablename__ = 'grant'

    id = Column(Integer, primary_key=True)

    user_id = Column(
        Integer, ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = Column(
        Unicode(40), ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    code = Column(Unicode(255), index=True, nullable=False)

    redirect_uri = Column(Unicode(255))
    expires = Column(DateTime)

    _scopes = Column(UnicodeText)

    # def delete(self):
    #     session.delete(self)
    #     session.commit()
    #     return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _get_session(self):
        session = inspect(self).session
        return session

    def delete(self):
        session = self._get_session()
        session.delete(self)
        session.commit()
        return self

class Token(Base):
    __tablename__ = 'token'

    id = Column(Integer, primary_key=True)
    client_id = Column(
        Unicode(40), ForeignKey('client.client_id'),
        nullable=False,
    )
    client = relationship('Client')

    user_id = Column(
        Integer, ForeignKey('user.id')
    )
    user = relationship('User')

    # currently only bearer is supported
    token_type = Column(Unicode(40))

    access_token = Column(Unicode(255), unique=True)
    refresh_token = Column(Unicode(255), unique=True)
    expires = Column(DateTime)
    _scopes = Column(UnicodeText)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _get_scope(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def _set_scope(self, scope):
        if scope:
            scope = scope
        self._scopes = scope

    scope_descriptor = property(_get_scope, _set_scope)
    scope = synonym('_scopes', descriptor=scope_descriptor)


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, default=datetime.now)
    modified = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    name = Column('name', String(200))
    email = Column(String(100), unique=True, nullable=False)
    active = Column(Boolean, default=True)
    _password = Column('password', String(100))

    def _get_password(self):
        return self._password

    def _set_password(self, password):
        if password:
            password = password.strip()
        self._password = generate_password_hash(password)

    password_descriptor = property(_get_password, _set_password)
    password = synonym('_password', descriptor=password_descriptor)

    def check_password(self, password):
        if self.password is None:
            return False
        password = password.strip()
        if not password:
            return False
        return check_password_hash(self.password, password)

    @classmethod
    def authenticate(cls, query, email, password):
        email = email.strip().lower()
        user = query(cls).filter(cls.email==email).first()
        if user is None:
            return None, False
        if not user.active:
            return user, False
        return user, user.check_password(password)

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

    def __repr__(self):
        return u'<{self.__class__.__name__}: {self.id}>'.format(self=self)


if __name__ == '__main__':
    from sqlalchemy import create_engine

    engine = create_engine('sqlite:///sched.db', echo=True)

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    user1 = User(name='Pyunghyuk Yoo',
                email='yoophi@gmail.com',
                password='secret')

    session.add(user1)
    session.commit()

    user2 = User(name='Shinhye Park',
                email='sh.park@gmail.com',
                password='secret')

    session.add(user2)
    session.commit()

    client = Client(name='foo',
                    description='',
                    user=user1,
                    client_id='foo',
                    client_secret='secret',
                    is_confidential=True,
                    _redirect_uris='http://yoophi.com/oauth/redirect')
    session.add(client)
    session.commit()
