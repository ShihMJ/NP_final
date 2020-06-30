import argparse
import json
import socket
import sys
import time
import ast
import stomp

class MyListener(stomp.ConnectionListener):
    def on_error(self, headers, message):
        print('received an error "%s"' % message)
    def on_message(self, headers, message):
        print(message)

def main():
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

	address = (ip, int(port))

	login_token = {}
	user_broker_con = {}
	user_app_server_map = {}

	while True :
		cmd = input()
		cmd_list = cmd.split()
		if not cmd_list :
			continue
		
		if cmd_list[0] == "exit" :
			break
		
		if len(cmd_list) > 1 :
			user = cmd_list[1] # get user account
			if cmd_list[0] != "register" and cmd_list[0] != "login" :
				if user in login_token :
					cmd_list[1] = login_token[user] # if this user have logged in, replace user with token
				else :
					cmd_list[1] = " " # if the command is not register and not logged in, replace user with space

			cmd = ' '.join(cmd_list)
		
		app_command = ["invite", "list-invite", "accept-invite", "list-friend", "post", "receive-post", "send", "create-group", "list-group", "list-joined", "join-group", "send-group"]

		if len(cmd_list) > 1 :
			if cmd_list[0] in app_command and user in user_app_server_map :
				address = (user_app_server_map[user], int(port))
				#print("yeah")
			else:
				address = (ip, int(port))
		else :
			address = (ip, int(port))

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(None)
		s.connect(address)
		s.send(cmd.encode())
		data = s.recv(2048)
		data = data.decode()
		data = ast.literal_eval(data) # transform json string to dict
		message = ""
		for key, value in data.items():
			if key == "message" :
				print(value)
				message = value
			elif key == "token" :
				#design with the same format of server!!
				if user not in login_token :
					conn = stomp.Connection()
					conn.set_listener('', MyListener())
					conn.start()
					conn.connect()
					user_broker_con[user] = conn
					#print("connect")
					user_broker_con[user].subscribe(destination = '/topic/' + user, id = 1, ack='auto')
					for sub in data["group"]:
						user_broker_con[user].subscribe(destination = '/topic/' + sub, id = 1, ack='auto')

				login_token[user] = value
				user_app_server_map[user] = data["app_dns"]
				#print(login_token)

		if cmd_list[0] == "logout" or cmd_list[0] == "delete" :
			if message == "Bye!" or message == "Success!" :
				#print("disconnect")
				del login_token[user]
				user_broker_con[user].disconnect()
				del user_broker_con[user]
				del user_app_server_map[user]



		if data["status"] == 0:
			if cmd_list[0] == "list-invite" :
				if not data["invite"] :
					print("No invitations")
				for invite in data["invite"] :
					print(invite)

			elif cmd_list[0] == "list-friend" :
				if not data["friend"] :
					print("No friends")
				for friend in data["friend"] :
					print(friend)

			elif cmd_list[0] == "receive-post" :
				if not data["post"] :
					print("No posts")
				for post in data["post"] :
					print("{}: {}".format(post["id"], post["message"]))

			elif cmd_list[0] == "send" :
				user_broker_con[user].send(body = "<<<" + user + "->" + cmd_list[2] + ": " + ' '.join(cmd_list[3:]) + ">>>", destination = '/topic/' + cmd_list[2])

			elif cmd_list[0] == "create-group" :
				user_broker_con[user].subscribe(destination = '/topic/' + cmd_list[2], id = 1, ack='auto')

			elif cmd_list[0] == "list-group" or cmd_list[0] == "list-joined" :
				if not data["group"]:
					print("No groups")
				for group in data["group"] :
					print(group)

			elif cmd_list[0] == "join-group" :
				user_broker_con[user].subscribe(destination = '/topic/' + cmd_list[2], id = 1, ack='auto')

			elif cmd_list[0] == "send-group" :
				user_broker_con[user].send(body = "<<<" + user + "->GROUP" + "<" + cmd_list[2] + ">" + ": " + ' '.join(cmd_list[3:]) + ">>>", destination = '/topic/' + cmd_list[2])

		s.close()


if __name__ == "__main__" :
	main()