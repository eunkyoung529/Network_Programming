from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, \
    messagebox , filedialog # Tkinter Python Module for GUI
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

        self.file_counter = 0


    def recv_exact(selfself, so, n):
        buf = b''
        while len(buf) < n:
            chunk = so.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


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
            header = self.recv_exact(so, 8)
            if not header:
                break

            msg_type = int.from_bytes(header[:4], 'big')
            length = int.from_bytes(header[4:], 'big')

            # 2) body
            body = self.recv_exact(so, length)
            if body is None:
                break

            if msg_type == 0:
                try:
                    message = self.cipher.decrypt(body).decode('utf-8')
                except Exception:
                    message = "[복호화 오류]"

                if "joined" in message:
                    user = message.split(":", 1)[1]
                    message = user + " has joined"
                self.chat_transcript_area.insert('end', message + "\n")
                self.chat_transcript_area.yview(END)
            elif msg_type == 1:
                try:
                    file_bytes = self.cipher.decrypt(body)
                except Exception:
                    self.chat_transcript_area.insert('end', "[파일 복호화 오류]\n")
                    self.chat_transcript_area.yview(END)
                    continue
                #파일 저장
                filename = f"received_image_{self.file_counter}.png"
                self.file_counter += 1

                with open(filename, "wb") as f:
                    f.write(file_bytes)

                self.chat_transcript_area.insert('end', f"[이미지 수신] {filename} 저장 완료\n")
                self.chat_transcript_area.yview(END)

            else:
                self.chat_transcript_area.insert('end', "[알 수 없는 메시지 타입 수신]\n")
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
        self.enter_text_widget = Text(frame, width=60, height=3, font=("Serif", 12))
        self.enter_text_widget.pack(side='left', pady=15)
        self.enter_text_widget.bind('<Return>', self.on_enter_key_pressed)

        #이미지 파일 전송 버튼
        file_button = Button(frame, text="Send File", width=10, command=self.send_file)
        file_button.pack(side='left', padx=5, pady=15)

        frame.pack(side='top')

    def on_join(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return
        self.name_widget.config(state='disabled')

        plain = "joined:" + self.name_widget.get()

        body = self.cipher.encrypt(plain.encode('utf-8'))
        msg_type = 0
        header = msg_type.to_bytes(4, 'big') + len(body).to_bytes(4, 'big')

        self.client_socket.sendall(header + body)

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
        body = self.cipher.encrypt(plain.encode('utf-8'))
        msg_type = 0
        header = msg_type.to_bytes(4, 'big') + len(body).to_bytes(4, 'big')
        self.client_socket.sendall(header + body)

        self.enter_text_widget.delete(1.0, 'end')
        return 'break'

    def send_file(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror("Enter your name", "Enter your name first.")
            return
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except Exception as e:
            messagebox.showerror("File Error", f"파일을 읽을 수 없습니다:\n{e}")
            return
        #파일 바이트 암호화
        body = self.cipher.encrypt(raw)
        msg_type = 1
        header = msg_type.to_bytes(4, 'big') + len(body).to_bytes(4, 'big')
        self.client_socket.sendall(header + body)
        self.chat_transcript_area.insert('end', f"[이미지 전송] {file_path}\n")
        self.chat_transcript_area.yview(END)


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