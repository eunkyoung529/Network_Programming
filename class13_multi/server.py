# imports
import socket
import threading


class ChatServer:
    clients_list = []

    last_received_message = b""

    def __init__(self):
        self.server_socket = None
        self.create_listening_server()

    # listen for incoming connection
    def create_listening_server(self):

        self.server_socket = socket.socket(socket.AF_INET,
                                           socket.SOCK_STREAM)  # create a socket using TCP port and ipv4
        local_ip = '127.0.0.1'
        local_port = 12345
        # this will allow you to immediately restart a TCP server
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # this makes the server listen to requests coming from other computers on the network
        self.server_socket.bind((local_ip, local_port))
        print("Listening for incoming messages..")
        self.server_socket.listen(5)  # listen for incomming connections / max 5 clients
        self.receive_messages_in_a_new_thread()

    # fun to receive new msgs
    def receive_messages(self, so):
        while True:
            # 1) 먼저 8바이트 헤더를 읽는다: [4바이트 타입][4바이트 길이]
            header = b''
            while len(header) < 8:
                chunk = so.recv(8 - len(header))
                if not chunk:
                    #클라이언트 연결 종료
                    so.close()
                    return
                header += chunk
            # 타입, 길이 파싱
            msg_type = int.from_bytes(header[:4], 'big')
            length  = int.from_bytes(header[4:], 'big')
            # 2) length만큼 바디를 정확히 읽기
            body = b''
            while len(body) < length:
                chunk = so.recv(length - len(body))
                if not chunk:
                    so.close()
                    return
                body += chunk
        so.close()

    # broadcast the message to all clients
    def broadcast_to_all_clients(self, senders_socket):
        for client in self.clients_list:
            socket, (ip, port) = client
            if socket is not senders_socket:
                socket.sendall(self.last_received_message)

    def receive_messages_in_a_new_thread(self):
        while True:
            client = so, (ip, port) = self.server_socket.accept()
            self.add_to_clients_list(client)
            print('Connected to ', ip, ':', str(port))
            t = threading.Thread(target=self.receive_messages, args=(so,))
            t.start()

    # add a new client
    def add_to_clients_list(self, client):
        if client not in self.clients_list:
            self.clients_list.append(client)


if __name__ == "__main__":
    ChatServer()