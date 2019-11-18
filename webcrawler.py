import socket
import sys
import re

# global variables
global s

port = 80

visited = set() # track urls that have been visited
queue = list() # urls that we have to search
flags = list() # found secret flags

def main():
	# Parse inputs for username and password
	username = ''
	password = ''

	if len(sys.argv) == 3:
		username = sys.argv[1]
		password = sys.argv[2]
	else:
		print('Incorrect number of input arguments')
		sys.exit()

	# Connect to the server
	hostname = '/accounts/login/?next=/fakebook'

	# Make the socket
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	# Error
	except socket.error:
		print('Error creating the socket.')
		sys.exit()

	# Get our host
	try:
		host = socket.gethostbyname("net2.cs.vt.edu") 
	except:
		print('Error with given host name.')
		sys.exit()

	# connecting to the server 
	try:
		s.connect((host, port)) 
	except socket.gaierror:
		print('Error connecting to address given for server.')

	# Use a GET request to get the CSRF token
	request = 'GET %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\n\r\n' % hostname
	s.send(request.encode())

	response = s.recv(4096)  
	http_response = str(response)

	i = http_response.find('csrfmiddlewaretoken')
	j = http_response.find('value', i)
	pattern = r"'([A-Za-z0-9]*)'"
	m = re.search(pattern, http_response[j: j+80])
	token = m.group()[1:len(m.group())-1]

	# start by logging into fakebook through the login page
	login = 'username=%s&password=%s&csrfmiddlewaretoken=%s' % (username, password, token)
	l = len(login)
	request = 'POST %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\nCookie: csrftoken=%s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\n\r\n%s\r\n' % (hostname, token, l, login)
	s.send(request.encode())
	visited.add(hostname)

	response = s.recv(4096)  
	http_response = str(response)
	#print(http_response)

	# Get Session Cookie
	i = http_response.find('sessionid')
	session = http_response[i+10:].split(';')[0]

	# Check response code
	# TODO: Find a better way to get the response code
	code = get_code(http_response)
	while code != 200 and code != 403 and code != 404:
		#print(code)
		if code != 500:
			i = http_response.find('net2.cs.vt.edu')

			# url is not in the right domain
			if i == -1:
				code = 404
				break

			url = http_response[i+14:].split('\r')[0]
			request = 'GET %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\nCookie: csrftoken=%s;sessionid=%s\r\n\r\n' % (url, token, session)
		
		#print(request)
		check_conn(http_response) 
		s.send(request.encode())

		response = s.recv(4096)  
		http_response = str(response)
		#print(http_response)
		code = get_code(http_response)

	if code == 403 or code == 404:
		print("Error %d received after login" % code)
		sys.exit()
	
	print("the first url is " + str(url))
	visited.add(url)

	# Start the web crawler
	# Parse the input for urls - add them to the queue
	get_urls(http_response)
	while len(queue) > 0 and len(flags) < 5:
		print("queue length: %d\nFlag length: %d" % (len(queue), len(flags)))
		curr = queue.pop(0) # get first url in queue
		#print(curr)

		# request url and get http response
		request = 'GET %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\nCookie: csrftoken=%s;sessionid=%s\r\n\r\n' % (curr, token, session)
		#print(request)
		check_conn(http_response) # always check connectioni before sending a request
		s.send(request.encode())
		response = s.recv(4096)  
		http_response = str(response)
		#print(http_response)
		code = get_code(http_response)
		#print(code)

		while code != 200 and code != 403 and code != 404:
			#print(code)
			if code != 500:
				i = http_response.find('net2.cs.vt.edu')

				# url is not in the right domain
				if i == -1:
					code = 404
					i = 0
					break

				url = http_response[i+14:].split('\r')[0]
				visited.add(url)
				#print(url)
				request = 'GET %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\nCookie: csrftoken=%s;sessionid=%s\r\n\r\n' % (url, token, session)
				
				#print(request)
				check_conn(http_response) 
				s.send(request.encode())

				response = s.recv(4096)  
				http_response = str(response)
				#print(http_response)
				code = get_code(http_response)
			# when the 500 code is received
			else:
				t = 0
				while(code == 500):
					url = curr	
					s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
					try:
						s.connect((host, port)) 
					except socket.gaierror:
						print('Error connecting to address given for server.')

					visited.add(url)
					#print(url)
					request = 'GET %s HTTP/1.1\r\nHost: net2.cs.vt.edu\r\nCookie: csrftoken=%s;sessionid=%s\r\n\r\n' % (url, token, session)
					
					#print(request)
					check_conn(http_response) 
					s.send(request.encode())

					response = s.recv(4096)  
					http_response = str(response)
					#print(http_response)
					code = get_code(http_response)
					if t > 0:
						print('this is my life ' + str(code))
					t += 1

		if code == 403 or code == 404: # abandon the url
			visited.add(curr)
			continue

		# scan for secret flags
		find_flags(http_response)

		# add to visited
		if curr != url: 
			visited.add(curr)
		
		# scan for urls
		get_urls(http_response)
		#print(queue)
		#print(len(queue))

	print(flags)
	
	s.close()

'''
	Helper function to check connection status and 
	reconnect if needed
'''
def check_conn(response):
	pattern = r'Connection: [a-z]*'
	conn = re.search(pattern, response)

	if conn is not None and conn.group()[12:] == "close":
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		host = socket.gethostbyname("net2.cs.vt.edu") 
		s.connect((host, port))

'''
	Helper function to retrieve the response code
'''
def get_code(response):
	pattern = r'HTTP\/1.1 [0-9]*'
	code = re.search(pattern, response)
	if code is None:
		return 404
	return int(code.group()[9:])

'''
	Helper function to parse HTML and retrieve all links 
'''
def get_urls(response):
	pattern = r'href="\/fakebook\/[A-Za-z0-9@.\/:]*'
	for url in re.findall(pattern, response):
		u = url[6:]
		if u not in visited and u not in queue:
			queue.append(u)

'''
	Helper function to search HTML for secret flags
'''
def find_flags(response):
	pattern = r'<h2 class=\'secret_flag\' style="color:red">FLAG: [A-Za-z0-9]*'
	flag = re.search(pattern, response)
	if flag is not None:
		print('flag')
		flags.append(flag.group()[48:])

# Call main
if __name__=="__main__":
	main()
