# imports
import socket
import threading
import requests
from cryptography.fernet import Fernet

class ChatServer:
    clients_list = []

    last_received_message = b""

    def __init__(self):
        self.SECRET_KEY = b'rBs0r1foj7jenqz_DdJivFK6I14s-Cn67M0nPgN9Vd0='
        self.cipher = Fernet(self.SECRET_KEY)
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
            incoming_buffer = so.recv(4096)  # initialize the buffer
            if not incoming_buffer:
                break
            self.last_received_message = incoming_buffer
            #평문 복호화 시도
            try:
                plain = self.cipher.decrypt(incoming_buffer).decode('utf-8')
            except Exception:
                plain = ""
                print("(서버) 복호화 실패")
            print("(서버) 수신 평문:", plain)

            # /bot 명령처리
            if plain.startswith("/bot"):
                # "/bot" 뒤의 텍스트를 LLM 프롬프트로 사용
                user_prompt = plain[4:].strip()
                bot_text = self.ai_chat_reply(user_prompt)

                reply_plain = "ChatBot: " + bot_text

                #서버도 클라이언트와 같은 Fernet 키로 암호화해서 전송
                reply_cipher = self.cipher.encrypt(reply_plain.encode('utf-8'))

                #ChatBot 메시지를 모든 클라이언트에게 전송
                self.last_received_message = reply_cipher
                self.broadcast_to_all_clients(senders_socket=None)
            else:
                # 일반 채팅 메시지는 기존처럼 암호문 그대로 중계
                self.broadcast_to_all_clients(so) # send to all clients
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

    # Ollama 호출 함수 추가
    def ai_chat_reply(self, user_prompt: str) -> str:
        try:
            url = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3",
                "prompt": user_prompt,
                "stream": False
            }
            resp = requests.post(url, json=payload, timeout=300)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except Exception as e:
            print("[서버] Ollama 호출 오류:", e)
            return "챗봇 호출 중 오류가 발생했습니다. 서버 로그를 확인하세요."


if __name__ == "__main__":
    ChatServer()