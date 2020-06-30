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

#db = SqliteDatabase('0516228_hw4_db.db', pragmas={'foreign_keys': 1}, host = "140.113.123.90", port = 9527)
db = MySQLDatabase('hw5db2', host = "hw5db2.crfvrjxn3mpu.us-east-1.rds.amazonaws.com", port = 9527, user = "ruren", passwd = "ruren9527")

#db.pragma('foreign_keys', 1, permanent=True)

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
	"""
	data = Instance.select()
	if not data:
		print("success")
	"""

	parser = argparse.ArgumentParser()
	parser.add_argument('-ip', action = 'store', dest = 'ip')
	parser.add_argument('-port', action = 'store', dest = 'port')
	args = parser.parse_args()
	ip = args.ip
	port = args.port
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
	#print("ip:{} port:{}".format(ip, port))


	app_command = ["invite", "list-invite", "accept-invite", "list-friend", "post", "receive-post", "send", "create-group", "list-group", "list-joined", "join-group", "send-group"]

	address = (ip, int(port))

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(None)
	s.bind(address)
	s.listen(1)
	#(clientsocket, address) = s.accept()
	#s.settimeout(5.0)
	while True:
		(clientsocket, address) = s.accept()
		#s.settimeout(5.0)
		cmd = clientsocket.recv(2048)
		cmd = cmd.decode()
		print(cmd)
		cmd_list = cmd.split()
		response = {}
		if cmd_list[0] == "register":
			if len(cmd_list) != 3:
				response["status"] = 1
				response["message"] = "Usage: register <id> <password>"
			else:
				user_name = cmd_list[1]
				data = User.select().where(User.username == user_name)
				if data:
					response["status"] = 1
					response["message"] = "{} is already used".format(user_name)
				else:
					User.create(username = user_name, password = cmd_list[2])
					response["status"] = 0
					response["message"] = "Success!"

		elif cmd_list[0] == "login":
			if len(cmd_list) != 3:
				response["status"] = 1
				response["message"] = "Usage: login <id> <password>"
			else:
				user_name = cmd_list[1]
				pwd = cmd_list[2]
				data = User.select().where(User.username == user_name, User.password == pwd)
				if not data:
					response["status"] = 1
					response["message"] = "No such user or password error"
				else:
					dns = ""
					data = data.get()
					if not data.access_token:
						md5 = hashlib.md5()
						D = datetime.datetime.today()
						token = user_name + str(D)
						md5.update(token.encode())
						token = md5.hexdigest()
						User.update(access_token = token).where(User.username == user_name).execute()

						instances = Instance.select()
						instance_id = -1
						for ins in instances:
							if ins.serving != 10:
								instance_id = ins.id
								break

						if instance_id == -1:
							# create instance
							user_data = """#!/bin/bash
/usr/bin/python3 /home/ubuntu/hw5_app_server.py -ip 0.0.0.0 -port 9527 -login_server_ip """ + ip + '\n'
							ec2 = boto3.resource('ec2', region_name='us-east-1')
							instance = ec2.create_instances(ImageId='ami-0e71ec172814e712b', MinCount=1, MaxCount=1, InstanceType = "t2.micro", KeyName='test_aws', SecurityGroupIds = ['sg-06162cd60d9f02db4'], UserData=user_data) # this id for ubuntu 18.04 64-bit x86
							instance[0].wait_until_running()

							# app_server tell login_server that it's ready
							(clientsocket2, address2) = s.accept()
							finish = clientsocket2.recv(2048)
							finish = finish.decode()
							print(finish)

							ec2 = boto3.client('ec2', region_name = 'us-east-1')
							d = ec2.describe_instances(InstanceIds = [instance[0].id])
							dns = d["Reservations"][0]["Instances"][0]["PublicDnsName"]
							Instance.create(instance_dns = dns, instance_id = instance[0].id, serving = 1)
							new_instance_id = Instance.select().where(Instance.instance_dns == dns).get()
							new_instance_id = new_instance_id.id

							User.update(serverd_instance = new_instance_id).where(User.username == user_name).execute()


						else :
							# distribute existed instance_id to client
							app = Instance.select().where(Instance.id == instance_id).get()
							dns = app.instance_dns
							new_serving = app.serving + 1
							Instance.update(serving = new_serving).where(Instance.id == instance_id).execute()
							User.update(serverd_instance = app.id).where(User.username == user_name).execute()



					else:
						token = data.access_token
						app_id = data.serverd_instance
						app = Instance.select().where(Instance.id == app_id).get()
						dns = app.instance_dns
						# query app_dns



					response["status"] = 0
					response["token"] = token
					response["message"] = "Success!"
					response["app_dns"] = dns
					response["group"] = []
					user_id = data.id
					data = Subscribe.select().where(Subscribe.user_id == user_id) # query groups that this user subscribes from Subscribe 
					g_id_list = []
					for sub in data:
						g_id_list.append(sub.group_id) # get those group_id and make them a list
					for g_id in g_id_list:
						data = Group.select().where(Group.id == g_id).get() # get those group_id in the list and get their name
						response["group"].append(data.group_name)


		elif cmd_list[0] == "delete":
			# quite strange. There must be some problems. It shouldn't be like this lol
			if len(cmd_list) < 2:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					# logged in and the cmd is "delete LOGIN_TOKEN SOMETHING_BRABRABRA"
					if len(cmd_list) != 2:
						response["status"] = 1
						response["message"] = "Usage: delete <user>"
					else:
						data = data.get()
						app_id = data.serverd_instance
						app = Instance.select().where(Instance.id == app_id).get()
						if app.serving == 1:
							# delete app_server
							ec2 = boto3.client('ec2', region_name = 'us-east-1')
							d = ec2.terminate_instances(InstanceIds = [app.instance_id])
							Instance.delete().where(Instance.id == app_id).execute()

						else:
							# serve - 1
							new_serving = app.serving - 1
							Instance.update(serving = new_serving).where(Instance.id == app_id).execute()

						User.delete().where(User.access_token == login_token).execute()
						response["status"] = 0
						response["message"] = "Success!"

		elif cmd_list[0] == "logout":
			if len(cmd_list) < 2:
				response["status"] = 1
				response["message"] = "Not login yet"
			else:
				login_token = cmd_list[1]
				data = User.select().where(User.access_token == login_token)
				if not data:
					response["status"] = 1
					response["message"] = "Not login yet"
				else:
					# logged in and the cmd is "login LOGIN_TOKEN SOMETHING_BRABRABRA"
					if len(cmd_list) != 2:
						response["status"] = 1
						response["message"] = "Usage: logout <user>"
					else:

						data = data.get()
						app_id = data.serverd_instance
						app = Instance.select().where(Instance.id == app_id).get()
						if app.serving == 1:
							# delete app_server
							ec2 = boto3.client('ec2', region_name = 'us-east-1')
							d = ec2.terminate_instances(InstanceIds = [app.instance_id])
							Instance.delete().where(Instance.id == app_id).execute()

						else:
							# serve - 1
							new_serving = app.serving - 1
							Instance.update(serving = new_serving).where(Instance.id == app_id).execute()


						User.update(access_token = None).where(User.access_token == login_token).execute()
						response["status"] = 0
						response["message"] = "Bye!"

		elif cmd_list[0] in app_command:
			response["status"] = 1
			response["message"] = "Not login yet"

		else:
			response["status"] = 1
			response["message"] = "Unknown command {}".format(cmd_list[0])

		response = json.dumps(response)
		clientsocket.sendall(response.encode())


		clientsocket.close()


if __name__ == "__main__" :
	main()