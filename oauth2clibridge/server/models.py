from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Oauth2Record(Base):
	__tablename__ = 'oauth2'

	id = Column(Integer, primary_key=True)
	client_id = Column(String, nullable=False, index=True)
	#client_secret = Column(String, nullable=False)
	auth_uri = Column(String, nullable=False)
	token_uri = Column(String, nullable=False)
	name = Column(String, nullable=True)
	scope = Column(String, nullable=False)
	csrf = Column(String, nullable=True)
	auth_code = Column(String, nullable=True)
	refresh_token = Column(String, nullable=True)
	refresh_sha1 = Column(String(40), nullable=True)
	access_token = Column(String, nullable=True)
	access_sha1 = Column(String(40), nullable=True)
	access_exp = Column(Integer, nullable=True)
	access_token_type = Column(String, nullable=True)

	def __repr__(self):
		return "<Oauth2Record(client_id='%s', auth_uri='%s', name='%s', auth='%s', refresh='%s', access='%s')>" % (
		  self.client_id, self.auth_uri, self.name, self.auth_code is not None,
		  self.refresh_token is not None, self.access_token is not None)


def create_db(dbengine):
	Base.metadata.create_all(bind=dbengine)
