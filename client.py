import socket

# Replace these values with the actual IP address and port of your proxy server
server_address = ('127.0.0.1', 8080)

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the server
    client_socket.connect(server_address)
    print("Connected to the server")

    # Send a sample request
    requestStr = "GET /wireshark-labs/HTTP-wireshark-file4.html HTTP/1.1\r\nHost: gaia.cs.umass.edu\r\n\r\n"
    request = requestStr.encode('utf-8')
    client_socket.sendall(request)
    
    print("Request sent")

    # Receive the response
    response = client_socket.recv(1024)
    print("Received response:")
    print(response.decode('utf-8'))


    print(" TRYING ANOTHER TIME")

    client_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     # Connect to the server
    client_socket2.connect(server_address)
    print("Connected to the server")

    # Send a sample request
    requestStr = "GET /wireshark-labs/HTTP-wireshark-file4.html HTTP/1.1\r\nHost: gaia.cs.umass.edu\r\n\r\n"
    request = requestStr.encode('utf-8')
    client_socket2.sendall(request)
    
    print("Request sent")

    # Receive the response
    response2 = client_socket2.recv(1024)
    print("Received response:")
    print(response2.decode('utf-8'))
    print("ARE RESPONSES EQUAL?" + str(response==response2))

    

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the socket
    client_socket.close()
    print("Socket closed")
