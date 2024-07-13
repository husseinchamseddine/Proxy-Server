import socket
from concurrent.futures import ThreadPoolExecutor
import datetime
import requests
import threading
from urllib.parse import urlsplit, urljoin
from email.utils import parsedate_to_datetime
from hashlib import md5
from flask import Flask, render_template, request, redirect, Response, url_for
from urllib.parse import urlsplit, urlparse

app = Flask(__name__)


class ProxyServer:

    

    def __init__(self, host='127.0.0.1', port=8080, defualt_ttl=3600):
        """ 
            Initialize socket and start listening,and having "local Host" & port 8080 as intial values
        """
        self.host = host 
        self.port = port
        
        """ 
            Create a socket parameter using the imported socket class
        """
        self.default_ttl = defualt_ttl
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        """
            Using the socket.socket() function which takes the family and the type as parameters 
            The family is either IPv4, IPv6, or Unix domain sockets
            The type is either a stream oriented (TCP), connectionless datagrams(UDP),or RAW sockets
            
            (socket.AF_INET) : It indicates that the socket will use IPv4 addressing.
            (socket.SOCK_STREAM) : Which means the socket will be a stream socket. Stream sockets are associated
            with the TCP protocol.
        """
        address = (self.host, self.port)
        self.sock.bind(address)
        """
            Binding the socket to the respective host and port number, the server needs to bind to an address
            (host and port) so that clients can connect to it. This enables the socket
            to communicate over the network using that particular address.
        """
        self.sock.listen() 
        """
            Listen() function lets the server listen to incoming client requests, with having 10 as 
            a thresehold to incoming requests, any additional requests will be denied
        """
        print("Listening on {}:{}".format(self.host, self.port))
        
        self.cache = {} #initialize a dict for caching
        self.cache_size_limit = 1024*1024*10 #10 MB size limit for cache
        self.pool = ThreadPoolExecutor(max_workers=50)

        
    def listen(self):
        """
            Listen for incoming connections and start a thread per connection
        """

        while True:
            client, address = self.sock.accept()
            (host, port) = address
            
            """
                client: This is the new socket object that represents the connection to the client.
                All communication with the client occurs through this socket.
        
                address: This is a tuple containing the address of the client (host, port). 
                It provides information about where the incoming connection is coming from.
            """
            print("Accepted connection from: "+ host + " : " + str(port))
            
            self.handle_client(client,address)
           # self.pool.submit(self.handle_client, client, address)
            """s
                The threading approach allows multiple seemless connections to run more smoothly, the client_thread uses the
                Thread method from threading library to run the handle_client method & passing the client and address as paramater args
            """
        
            
    def handle_client(self, client_socket, addr):
        limit = 1024 * 10
        request = client_socket.recv(1024*1024 *8)  # 1 MB
        print("INFO ABOUT PACKET: ")
        method,url,http_version,host = self.extract_request_data(request)
        print("\n")

        try:
            
            if self.is_cached_response_valid(url):
                # Serve the cached response to the client
                print("The URL is found in the cache.")
                self.serve_cached_response(client_socket, url)
                print("URL sent from the cache.")
                
            else:
                
                print(f"{str(datetime.datetime.now())}: Forwarding request to {host+url}")
            
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((host, 80))
                print("TCP connected")
                server_socket.send(request)
                print("Request sent")
                response = server_socket.recv(1024 * 1024)
                print("Caching the response")    
                # Cache the response
                self.cache_response(url, response)

                print(f"{str(datetime.datetime.now())}: Sending response from: {host+url}")
                
                client_socket.send(response)
        except Exception as e:
          # Handle errors
          current_time = datetime.datetime.now()
          print(str(current_time) +": Error: " +str(e)) 
          client_socket.send(("HTTP/"+ http_version +" 500 Internal Server Error\r\n\r\n").encode('utf-8') )
          """
          Send in bytes,an HTTP response line with a status code of 500 (Internal Server Error) to the client. 
          The response includes the HTTP version, status code, and reason phrase.  
          (\r\n\r\n) indicates the end of the headers.
          """
        finally:
            print("Closing connection")
            client_socket.close()


    def serve_cached_response(self, client_socket, url):
        if self.is_cached_response_valid(url):
            # Serve the cached response to the client
            print("The URL is found in the cache.")
            cached_data = self.cache[url]['response']
            client_socket.send(cached_data)
            print("URL sent from the cache.")
        else:
            print("The URL is not found in the cache or the cached response is expired.")
    
    def cache_response(self, url, response):
        # Cache the response and timestamp
        current_time = datetime.datetime.now()
        self.cache[url] = {
            'response': response,
            'timestamp': current_time
        }

        # Check the cache size limit and evict entries if necessary
        self.check_cache_size_limit()
    
    def is_cached_response_valid(self, url):
        # Implement a more complex caching policy here
        if url in self.cache:
            entry = self.cache[url]
            current_time = datetime.datetime.now()

            # Check if the response has exceeded a certain time limit (e.g., 5 minutes)
            time_limit = datetime.timedelta(minutes=5)
            if (current_time - entry['timestamp']) < time_limit:
                return True

        return False
    
    def check_cache_size_limit(self):
        # Implement logic to check and evict entries if the cache size exceeds the limit
        current_size = sum(len(response) for response, _ in self.cache.values())
        while current_size > self.cache_size_limit:
            # Find and evict the oldest entry
            oldest_entry_url = min(self.cache, key=lambda k: self.cache[k][1]['date'])
            del self.cache[oldest_entry_url]
            current_size = sum(len(response) for response, _ in self.cache.values())
       
    def parse_headers(self,response):
        headers = {}
        lines = response.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]

        for line in lines:
            key, value = line.split(b": ", 1)
            headers[key] = value

        return headers
    
    def extract_request_data(self,request):
        # Split the request by CRLF ("\r\n") to separate headers from the request line
        request_lines = request.split(b"\r\n")

        # The first line is the request line
        request_line = request_lines[0]
        print(f"Request Line: {request_line.decode('utf-8')}")

        # Extract method, URL, and HTTP version from the request line
        method, url, http_version = request_line.split()
        print(f"Method: {method.decode('utf-8')}")
        print(f"URL: {url.decode('utf-8')}")
        print(f"HTTP Version: {http_version.decode('utf-8')}")

        # Extract the Host header
        host = None
        for header in request_lines[1:]:
            if header.startswith(b"Host:"):
                host = header.split(b":", 1)[1].strip().decode('utf-8')
                print(f"Host: {host}")
                break

        return method.decode('utf-8'), url.decode('utf-8'), http_version.decode('utf-8'), host




def main():
       server = ProxyServer()
       try: 
           server.listen()
       except KeyboardInterrupt:
           print('Stopping...')
       finally:
           server.shutdown()
           return


#def index():
 #   return 'Hello, this is your Flask app!'
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'


################################################################################### LOGIN


# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Hardcoded user data
users = {
    "admin": generate_password_hash("password")
}
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

###################################################################################
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        try:
            # Validate the URL before attempting to fetch
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL provided.")
            
            response, headers = fetch_via_proxy(url)
            return render_template('result.html', url=url, body=response, headers=headers)
        except Exception as e:
            # Redirect to the error page with the error message
            return render_template('error.html', error_message=str(e))
    return render_template('index.html')

def fetch_via_proxy(url):
    proxy_server_address = ('127.0.0.1', 8080)  # Your proxy server's IP and port
    response_body = ''
    response_headers = ''

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            # Connect to the proxy server
            client_socket.connect(proxy_server_address)

            # Parse the URL to obtain the path and the host
            parsed_url = urlparse(url)
            path = parsed_url.path if parsed_url.path else '/'
            query = f"?{parsed_url.query}" if parsed_url.query else ""
            request = f"GET {path}{query} HTTP/1.1\r\nHost: {parsed_url.netloc}\r\nConnection: close\r\n\r\n"
            client_socket.sendall(request.encode())

            # Receive the response from the proxy server
            response = b''
            while True:
                part = client_socket.recv(4096)
                if not part:
                    break  # No more data to read
                response += part

            # Decode the response to a string
            response = response.decode('utf-8', errors='ignore')

            # Separate headers and body
            header_data, _, body_data = response.partition('\r\n\r\n')
            response_headers = header_data
            response_body = body_data

            # If there is a <head> tag, insert the <base> tag inside it
            head_end_index = response_body.lower().find('</head>')
            base_tag = f'<base href="{url}">'
            if head_end_index != -1:
                response_body = response_body[:head_end_index] + base_tag + response_body[head_end_index:]
            if not response:
                raise ValueError("No response received from the server.")
            else:
                # If no <head> tag is present, prepend the <base> tag
                response_body = base_tag + response_body

    except Exception as e:
        print(f"Error in fetch_via_proxy: {e}")
        # Return an error message in the response body and empty headers
        response_body = f"Error fetching the URL: {e}"
        response_headers = ""

    return response_body, response_headers

if __name__ == '__main__':
    # Start the Flask app in a separate thread
    flask_thread = threading.Thread(target=app.run, kwargs={'port': 5000, 'threaded': True}, daemon=True)
    flask_thread.start()

    # Start the proxy server in a separate thread
    proxy = ProxyServer('127.0.0.1', 8080)  # Replace 8080 with your desired port number
    proxy_thread = threading.Thread(target=proxy.listen, daemon=True)
    proxy_thread.start()

    # Wait for threads to finish
    flask_thread.join()
    proxy_thread.join()

    print("All threads stopped. Exiting.")





