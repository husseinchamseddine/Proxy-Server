HTTP Proxy Website
This project implements a multi-threaded HTTP proxy web application and server in Python using Flask and sockets.

Overview
The proxy server provides a web interface that allows users to:

Register a new account
Login
Enter any URL
Fetch the content via the proxy
View the returned HTTP response headers and body
proxy.py
This file contains the following components:

HTTP Proxy Server

A high performance HTTP proxy implemented using sockets for forwarding requests/responses between clients and servers.

Website Backend

A Flask web application that provides the user interface and manages user accounts.

Key pages:

Homepage - Enter a URL and fetch the result
Login - Login with registered users
Register - Create a new user account
Threading

The proxy server and Flask app run concurrently in separate daemon threads to handle multiple client connections.

Usage
To start the web application:

Run python proxy.py
Navigate to http://localhost:5000 in a web browser
Register a new user or login
Enter a URL in the input field on the homepage
Click fetch to retrieve the URL via the proxy
The page will display the response headers and body
