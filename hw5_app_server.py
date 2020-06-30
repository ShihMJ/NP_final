import sys
sys.path.append("/home/ubuntu/.local/lib/python3.6/site-packages/")
import argparse
import json
import socket
import sys
import time
import ast
import hashlib
import datetime
import boto3
from peewee import *

db = MySQLDatabase('hw5db2', host = YOUR_HOST, port = YOUR_PORT, user = YOUR_USER, passwd = YOUR_PASSWORD)

# inherit from peewee.Model
# store information in subclass Meta. BaseModel can't be instantiated
# meaning cannot create an object of BaseModel 
class BaseModel(Model):
	class Meta:
		database = db

class User(BaseModel):
	id = AutoField()
	username = CharField(unique = True)
	password = CharField()
	#login_time = DateTimeField(null = True)
	access_token = CharField(null = True)
	serverd_instance = IntegerField(null = True)


# A and B <--> B and A, save as two data
class Friend(BaseModel):
	id = AutoField()
	userA_id = ForeignKeyField(User, on_delete = 'CASCADE')
	userB_id = ForeignKeyField(User, on_delete = 'CASCADE')

# B is invited by A !!! A won't see the invitation if A type list-invite
class Invite(BaseModel):
	id = AutoField()
	userA_id = ForeignKeyField(User, on_delete = 'CASCADE')
	userB_id = ForeignKeyField(User, on_delete = 'CASCADE')

# all the user's friend can see even if he/she becomes the user's friend after the user post
class Post(BaseModel):
	id = AutoField()
	user_id = ForeignKeyField(User, on_delete = 'CASCADE')
	post_message = CharField()

class Group(BaseModel):
	id = AutoField()
	group_name = CharField()

class Subscribe(BaseModel):
	id = AutoField()
	user_id = ForeignKeyField(User, on_delete = 'CASCADE')
	group_id = ForeignKeyField(Group, on_delete = 'CASCADE')

class Instance(BaseModel):
	id = AutoField()
	instance_dns = CharField(unique = True)
	instance_id = CharField()
	serving = IntegerField()

db.connect()
db.create_tables([User, Friend, Invite, Post, Group, Subscribe, Instance])


def main():
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-ip', action = 'store', dest = 'ip')
	parser.add_argument('-port', action = 'store', dest = 'port')
	parser.add_argument('-login_server_ip', action = 'store', dest = 'login_server_ip')
	args = parser.parse_args()
	ip = args.ip
	port = args.port
	login_server_ip = args.login_server_ip
	if not ip :
		print("please input ip with -ip")
		return -1
	if not port :
		print("please input port with -port")
		return -1
	port = int(port)
	if not ip or not port :
		print("請輸入ip及port")
		return 1

	address = (login_server_ip, int(port))
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print(address)
	s.connect(address)
	res = "finish"
	s.send(res.encode())


	address = (ip, int(port))

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(address)
	s.listen(1)

	while True:
		(clientsocket, address) = s.accept()
		cmd = clientsocket.recv(2048)
		cmd = cmd.decode()
		print(cmd)
		cmd_list = cmd.split()
		response = {}

		if cmd_list[0] == "invite":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					data = data.get()
					user_name = data.username
					user_id = data.id
					if len(cmd_list) != 3:
						response["status"] = 1
						response["message"] = "Usage: invite <user> <id>"
					elif cmd_list[2] == user_name:
						response["status"] = 1
						response["message"] = "You cannot invite yourself"
					else:
						invite_user = cmd_list[2]
						data = User.select().where(User.username == invite_user)
						if not data:
							response["status"] = 1
							response["message"] = "{} does not exist".format(invite_user)
						else:
							data = data.get()
							invite_user_id = data.id
							data_have_invited = Invite.select().where(Invite.userA_id == user_id, Invite.userB_id == invite_user_id)
							data_be_invited = Invite.select().where(Invite.userA_id == invite_user_id, Invite.userB_id == user_id)
							data_friended = Friend.select().where(Friend.userA_id == user_id, Friend.userB_id == invite_user_id)
							if data_have_invited:
								response["status"] = 1
								response["message"] = "Already invited"
							elif data_be_invited:
								response["status"] = 1
								response["message"] = "{} has invited you".format(invite_user)
							elif data_friended:
								response["status"] = 1
								response["message"] = "{} is already your friend".format(invite_user)
							else:
								Invite.create(userA_id = user_id, userB_id = invite_user_id)
								response["status"] = 0
								response["message"] = "Success!"

		elif cmd_list[0] == "list-invite":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) != 2:
						response["status"] = 1
						response["message"] = "Usage: list-invite <user>"
					else:
						data = data.get()
						user_id = data.id
						data = Invite.select().where(Invite.userB_id == user_id)
						invite_me = []
						for u in data:
							invite_me.append(u.userA_id)

						invite_me_username = []
						for uid in invite_me:
							data = User.select().where(User.id == uid).get()
							invite_me_username.append(data.username)

						response["status"] = 0
						response["invite"] = invite_me_username

		elif cmd_list[0] == "accept-invite":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) != 3:
						response["status"] = 1
						response["message"] = "Usage: accept-invite <user> <id>"
					else:
						data = data.get()
						user_id = data.id
						data = User.select().where(User.username == cmd_list[2])
						if not data:
							response["status"] = 1
							response["message"] = "{} did not invite you".format(cmd_list[2])
						else:
							data = data.get()
							inviter_id = data.id
							data = Invite.select().where(Invite.userA_id == inviter_id, Invite.userB_id == user_id)
							if not data:
								response["status"] = 1
								response["message"] = "{} did not invite you".format(cmd_list[2])
							else:
								Friend.create(userA_id = inviter_id, userB_id = user_id)
								Friend.create(userA_id = user_id, userB_id = inviter_id)
								Invite.delete().where(Invite.userA_id == inviter_id, Invite.userB_id == user_id).execute()
								response["status"] = 0
								response["message"] = "Success!"

		elif cmd_list[0] == "list-friend":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) != 2:
						response["status"] = 1
						response["message"] = "Usage: list-friend <user>"				
					else:
						data = data.get()
						user_id = data.id
						data = Friend.select().where(Friend.userA_id == user_id)
						friend_id = []
						for f in data:
							friend_id.append(f.userB_id)

						friend_name = []
						for f_id in friend_id:
							data = User.select().where(User.id == f_id)
							data = data.get()
							friend_name.append(data.username)

						response["status"] = 0
						response["friend"] = friend_name

		elif cmd_list[0] == "post":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) == 2:
						response["status"] = 1
						response["message"] = "Usage: post <user> <message>"

					else:
						data = data.get()
						user_id = data.id
						message = ' '.join(cmd_list[2:])
						Post.create(user_id = user_id, post_message = message)
						response["status"] = 0
						response["message"] = "Success!"

		elif cmd_list[0] == "receive-post":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) != 2:
						response["status"] = 1
						response["message"] = "Usage: receive-post <user>"

					else:
						response["post"] = []
						data = data.get()
						user_id = data.id
						data = Friend.select().where(Friend.userA_id == user_id)
						for friend in data:
							f_id = friend.userB_id
							f_post = Post.select().where(Post.user_id == f_id)
							for post in f_post:
								tmp = {}
								tmp["id"] = f_id.username
								tmp["message"] = post.post_message
								response["post"].append(tmp)
						#print(response)
						response["status"] = 0

		elif cmd_list[0] == "send":
			if len(cmd_list) == 1:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					if len(cmd_list) < 4:
						response["status"] = 1
						response["message"] = "Usage: send <user> <friend> <message>"
					else:
						data = data.get()
						user_id = data.id
						send_user = cmd_list[2]
						data = User.select().where(User.username == send_user)
						if not data:
							response["status"] = 1
							response["message"] = "No such user exist"
						else:
							data = data.get()
							friend_id = data.id
							friend_token = data.access_token
							data_friended = Friend.select().where(Friend.userA_id == user_id, Friend.userB_id == friend_id)
							if not data_friended:
								response["status"] = 1
								response["message"] = "{} is not your friend".format(send_user)
							else:
								if not friend_token :
									response["status"] = 1
									response["message"] = "{} is not online".format(send_user)
								else :
									response["status"] = 0
									response["message"] = "Success!"

		elif cmd_list[0] == "create-group" :
			if len(cmd_list) == 1 :
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					data = data.get()
					user_id = data.id
					if len(cmd_list) != 3 :
						response["status"] = 1
						response["message"] = "Usage: create-group <user> <group>"
					else :
						group_name = cmd_list[2]
						data = Group.select().where(Group.group_name == group_name)
						if data :
							response["status"] = 1
							response["message"] = "{} already exist".format(group_name)
						else :
							Group.create(group_name = group_name)
							data = Group.select().where(Group.group_name == group_name).get()
							Subscribe.create(user_id = user_id, group_id = data.id)
							response["status"] = 0
							response["message"] = "Success!"

		elif cmd_list[0] == "list-group" :
			if len(cmd_list) == 1 :
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data :
					response["status"] = 1
					response["message"] = "Not login yet"
				else :
					if len(cmd_list) != 2 :
						response["status"] = 1
						response["message"] = "Usage: list-group <user>"
					else :
						data = Group.select()
						group_list = []
						for group in data :
							group_list.append(group.group_name)
						response["status"] = 0
						#response["message"] = "Success!"
						response["group"] = group_list

		elif cmd_list[0] == "list-joined" :
			if len(cmd_list) == 1 :
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data :
					response["status"] = 1
					response["message"] = "Not login yet"
				else :
					if len(cmd_list) != 2 :
						response["status"] = 1
						response["message"] = "Usage: list-joined <user>"
					else :
						data = data.get()
						user_id = data.id
						data = Subscribe.select().where(Subscribe.user_id == user_id)
						group_id_list = []
						for group in data:
							group_id_list.append(group.group_id)
						response["group"] = []
						for group_id in group_id_list:
							data = Group.select().where(Group.id == group_id).get()
							response["group"].append(data.group_name)
						response["status"] = 0
						#response["message"] = "Success!"

		elif cmd_list[0] == "join-group" :
			if len(cmd_list) == 1 :
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data :
					response["status"] = 1
					response["message"] = "Not login yet"
				else :
					if len(cmd_list) != 3 :
						response["status"] = 1
						response["message"] = "Usage: join-group <user> <group>"
					else :
						group_name = cmd_list[2]
						data = data.get()
						user_id = data.id
						data = Group.select().where(Group.group_name == group_name)
						if not data :
							response["status"] = 1
							response["message"] = "{} does not exist".format(group_name)
						else :
							data = data.get()
							group_id = data.id
							data = Subscribe.select().where(Subscribe.user_id == user_id, Subscribe.group_id == group_id)
							if data :
								response["status"] = 1
								response["message"] = "Already a member of {}".format(group_name)
							else :
								Subscribe.create(user_id = user_id, group_id = group_id)
								response["status"] = 0
								response["message"] = "Success!"

		elif cmd_list[0] == "send-group" :
			if len(cmd_list) == 1 :
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data :
					response["status"] = 1
					response["message"] = "Not login yet"
				else :
					if len(cmd_list) < 4 :
						response["status"] = 1
						response["message"] = "Usage: send-group <user> <group> <message>"
					else :
						data = data.get()
						user_id = data.id
						group_name = cmd_list[2]
						data = Group.select().where(Group.group_name == group_name)
						if not data :
							response["status"] = 1
							response["message"] = "No such group exist"
						else :
							data = data.get()
							group_id = data.id
							data = Subscribe.select().where(Subscribe.user_id == user_id, Subscribe.group_id == group_id)
							if not data :
								response["status"] = 1
								response["message"] = "You are not the member of {}".format(group_name)
							else :
								response["status"] = 0
								response["message"] = "Success!"

		else:
			response["status"] = 1
			response["message"] = "Unknown command {}".format(cmd_list[0])

		response = json.dumps(response)
		clientsocket.sendall(response.encode())



		clientsocket.close()


if __name__ == "__main__" :
	main()