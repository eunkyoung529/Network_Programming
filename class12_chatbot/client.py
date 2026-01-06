from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, \
    messagebox  # Tkinter Python Module for GUI
import socket  # Sockets for network connection
import threading  # for multiple proccess
from cryptography.fernet import Fernet


class GUI:
    client_socket = None
    last_received_message = None

    def __init__(self, master):
        self.root = master
        self.chat_transcript_area = None
        self.name_widget = None
        self.enter_text_widget = None
        self.join_button = None

        # 암호화 키
        self.SECRET_KEY = b'rBs0r1foj7jenqz_DdJivFK6I14s-Cn67M0nPgN9Vd0='
        self.cipher = Fernet(self.SECRET_KEY)

        self.initialize_socket()
        self.initialize_gui()
        self.listen_for_incoming_messages_in_a_thread()

    def initialize_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # initialazing socket with TCP and IPv4
        remote_ip = '127.0.0.1'  # IP address
        remote_port = 12345  # TCP port
        self.client_socket.connect((remote_ip, remote_port))  # connect to the remote server

    def initialize_gui(self):  # GUI initializer
        self.root.title("Socket Chat")
        self.root.resizable(0, 0)
        self.display_chat_box()
        self.display_name_section()
        self.display_chat_entry_box()

    def listen_for_incoming_messages_in_a_thread(self):
        thread = threading.Thread(target=self.receive_message_from_server,
                                  args=(self.client_socket,))  # Create a thread for the send and receive in same time
        thread.start()

    # function to recieve msg
    def receive_message_from_server(self, so):
        while True:
            buffer = so.recv(4096)
            if not buffer:
                break

            try:
                # 암호문 → 평문 디코딩
                message = self.cipher.decrypt(buffer).decode('utf-8')
            except Exception:
                message = "[복호화 오류]"

            if "joined" in message:
                user = message.split(":")[1]
                message = user + " has joined"
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)
            else:
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)

        so.close()

    def display_name_section(self):
        frame = Frame()
        Label(frame, text='Enter your name:', font=("Helvetica", 16)).pack(side='left', padx=10)
        self.name_widget = Entry(frame, width=50, borderwidth=2)
        self.name_widget.pack(side='left', anchor='e')
        self.join_button = Button(frame, text="Join", width=10, command=self.on_join).pack(side='left')
        frame.pack(side='top', anchor='nw')

    def display_chat_box(self):
        frame = Frame()
        Label(frame, text='Chat Box:', font=("Serif", 12)).pack(side='top', anchor='w')
        self.chat_transcript_area = Text(frame, width=60, height=10, font=("Serif", 12))
        scrollbar = Scrollbar(frame, command=self.chat_transcript_area.yview, orient=VERTICAL)
        self.chat_transcript_area.config(yscrollcommand=scrollbar.set)
        self.chat_transcript_area.bind('<KeyPress>', lambda e: 'break')
        self.chat_transcript_area.pack(side='left', padx=10)
        scrollbar.pack(side='right', fill='y')
        frame.pack(side='top')

    def display_chat_entry_box(self):
        frame = Frame()
        Label(frame, text='Enter message:', font=("Serif", 12)).pack(side='top', anchor='w')
        #기존 채팅 입력창
        self.enter_text_widget = Text(frame, width=60, height=3, font=("Serif", 12))
        self.enter_text_widget.pack(side='left', pady=15)
        self.enter_text_widget.bind('<Return>', self.on_enter_key_pressed)

        # AI Bot 버튼 추가 : 현재 입력을 /bot 명령으로 전송
        ai_button = Button(frame, text="AI Bot", width=10, command=self.send_to_bot)
        ai_button.pack(side='left', padx=5, pady=15)

        frame.pack(side='top')

    def send_to_bot(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror("Enter your name", "Enter your name to send a message")
            return
        # 입력 텍스트 가져오기
        data = self.enter_text_widget.get(1.0, 'end').strip()
        if not data:
            return
        #서버에서 인식할 수 있게 평문을 '/bot' 로 시작하게 만듦
        bot_plain = "/bot" + data

        #채팅창에는 '내가 봇에게 보낸 내용'을 표시
        self.chat_transcript_area.insert('end', f"[나->봇] {data}\n")
        self.chat_transcript_area.yview(END)

        #Fernet으로 암호화해서 서버로 전송
        ciphertext = self.cipher.encrypt(bot_plain.encode('utf-8'))
        self.client_socket.sendall(ciphertext)

        #입력창 비우기
        self.enter_text_widget.delete(1.0, 'end')


    def on_join(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return
        self.name_widget.config(state='disabled')

        plain = "joined:" + self.name_widget.get()
        ciphertext = self.cipher.encrypt(plain.encode('utf-8'))
        self.client_socket.sendall(ciphertext)

    def on_enter_key_pressed(self, event):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror("Enter your name", "Enter your name to send a message")
            return
        self.send_chat()
        self.clear_text()

    def clear_text(self):
        self.enter_text_widget.delete(1.0, 'end')

    def send_chat(self):
        senders_name = self.name_widget.get().strip() + ": "
        data = self.enter_text_widget.get(1.0, 'end').strip()

        if not data:
            return 'break'
        plain = senders_name + data
        # 화면에는 평문 출력
        self.chat_transcript_area.insert('end', plain + '\n')
        self.chat_transcript_area.yview(END)
        # 네트워크로는 암호문 전송
        ciphertext = self.cipher.encrypt(plain.encode('utf-8'))
        self.client_socket.sendall(ciphertext)
        self.enter_text_widget.delete(1.0, 'end')
        return 'break'

    def on_close_window(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            self.client_socket.close()
            exit(0)


# the mail function
if __name__ == '__main__':
    root = Tk()
    gui = GUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_close_window)
    root.mainloop()