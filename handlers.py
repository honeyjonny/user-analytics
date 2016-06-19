import tornado.web
import tornado.websocket
import tornado.escape

from hashlib import md5, sha512
from time import time
from dbproviders import MongoDbModelsMiddleware




class Basehandler(tornado.web.RequestHandler, MongoDbModelsMiddleware):
	"""Base class for application handlers"""

	cookiestring = "__tokionare"

	@property	
	def current_token(self):
		if not hasattr(self, "_current_token"):
			self._current_token = self.get_cookie(self.cookiestring)
		return self._current_token

	@current_token.setter
	def current_token(self, value):
		self._current_token = value

	@property
	def current_username(self):
		if self.current_user == None:
			return None
		else:
			return self.current_user["name"]

	async def generate_key_iv_for_usr_async(self, user):

		def get_key_iv(string):
			return string[:8].encode('ascii'), string[-8:].encode('ascii')

		userDto = user
		salt = self.application.SALT

		digest = sha512()
		digest.update(userDto["name"].encode("utf-8"))
		#digest.update(userDto["pass"].encode("utf-8"))
		digest.update( str( userDto["_id"] ).encode("utf-8") )
		digest.update( salt.encode("utf-8") )
		hexcode = digest.hexdigest()
		return get_key_iv(hexcode)


	async def generate_session_for_user(self, userDto):
		digest = md5()

		salt = self.application.SALT

		digest.update(userDto["name"].encode("utf-8"))
		#digest.update(userDto["pass"].encode("utf-8"))
		digest.update( str( userDto["_id"] ).encode("utf-8") )
		digest.update( salt.encode("utf-8") )
		digest.update( str( time() ).encode("utf-8") )		
		return digest.hexdigest()

	async def prepare(self):
		token = self.current_token

		if token == None:
			self.current_user = None;

		else:
			user = await self.find_user_by_token(token)
			if user == None:
				return

			else:
				self.current_user = user


class RegisteredOnlyHandler(Basehandler):
	"""Class for handlers that work with logined-only users"""
	
	async def prepare(self):
		await super().prepare()

		if self.current_user == None and self.current_token == None:
			self.set_status(401)
			self.write({"error": "unauthorized"})
			self.finish()


class ApiUsershandler(Basehandler):
	async def get(self):
		resp = await self.find_users()
		if self.current_user:
			usr = self.map_doc_to_dto(self.current_user)
		else:
			usr = "none"
		self.write( { "current_user": usr, "users": resp } )


class MainHandler(Basehandler):
	async def get(self):
		resp = await self.find_users()

		if self.current_user == None:
			uid = None
		else:
			uid = str(self.current_user["_id"] )

		self.render("index.html", users = resp, current_username = self.current_username, cur_uid = uid )


class RegisterHandler(Basehandler):
	async def get(self):
		self.render("form.html", action="register", current_username = self.current_username )

	async def post(self):
		username = self.get_argument( "username" )
		password = self.get_argument( "password" )

		if (len(username) > 256) or (len(password)>256):
			self.set_status(400)
			self.write({"error":"do you really need so long nickname or password? lol"})
			self.finish()
			return

		cursor = await self.find_user_byname(username)
		count = cursor.count()

		if count > 0:
			self.set_status(409)
			self.write({"error": "user already exists"})
			self.finish()
			return

		usr = {"name":username, "pass": password}

		uid = await self.create_user(usr)

		self.set_status(201)
		self.redirect("/login")


class LoginHandler(Basehandler):
	async def get(self):
		self.render("form.html", action="login", current_username = self.current_username )

	async def post(self):

		username = self.get_argument( "username" )
		password = self.get_argument( "password" )

		if (len(username) > 256) or (len(password)>256):
			self.set_status(400)
			self.write({"error":"ahahaha, off mark. lol"})
			self.finish()
			return
		
		usr = {"name":username, "pass": password}

		cursor = await self.find_user_by_logindata(usr)
		count = cursor.count()

		if count == 1:

			user = cursor[0]
			#print(user)

			cookie = await self.generate_session_for_user(user)

			await self.delete_prev_tokens(user)
			await self.save_cookie_for_user(user, cookie)

			self.set_status(202)
			self.set_cookie(self.cookiestring, cookie)
			self.redirect("/")
			return
		else:
			self.set_status(404)
			self.write({ "status": "not found this user", "user": usr})


class Logouthandler(RegisteredOnlyHandler):
	async def get(self):
		user = self.current_user
		await self.delete_prev_tokens(user)

		self.set_status(303)
		self.redirect("/")