#!/usr/bin/env python3

import json
import socket
import threading
import tkinter as tk
from tkinter import ttk

HOST = "0.0.0.0"
PORT = 5555

client_socket = None


class Dashboard:

    def __init__(self, root):
        self.root = root
        self.root.title("HSM SIEM Dashboard")
        self.root.geometry("650x450")

        title = tk.Label(
            root,
            text="OP-TEE HSM Security Dashboard",
            font=("Arial", 18, "bold")
        )
        title.pack(pady=10)

        self.status_var = tk.StringVar(value="DISCONNECTED")
        self.logs_var = tk.StringVar(value="0")
        self.jitter_var = tk.StringVar(value="0 ms")
        self.i2c_var = tk.StringVar(value="False")

        frame = ttk.Frame(root)
        frame.pack(pady=10)

        ttk.Label(frame, text="Device Status:", font=("Arial", 12)).grid(row=0, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.status_var, font=("Arial", 12, "bold")).grid(row=0, column=1)

        ttk.Label(frame, text="Tamper Logs:", font=("Arial", 12)).grid(row=1, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.logs_var, font=("Arial", 12)).grid(row=1, column=1)

        ttk.Label(frame, text="Heartbeat Jitter:", font=("Arial", 12)).grid(row=2, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.jitter_var, font=("Arial", 12)).grid(row=2, column=1)

        ttk.Label(frame, text="I2C Compromised:", font=("Arial", 12)).grid(row=3, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.i2c_var, font=("Arial", 12)).grid(row=3, column=1)

        self.logbox = tk.Text(root, height=12, width=75)
        self.logbox.pack(pady=10)

        self.zeroize_button = tk.Button(
            root,
            text="REMOTE ZEROIZE",
            bg="red",
            fg="white",
            font=("Arial", 13, "bold"),
            command=self.zeroize
        )
        self.zeroize_button.pack(pady=10)

    def append_log(self, text):
        self.logbox.insert(tk.END, text + "\n")
        self.logbox.see(tk.END)

    def update_dashboard(self, packet):

        self.status_var.set(packet.get("status", "UNKNOWN"))
        self.logs_var.set(str(packet.get("tamper_logs", 0)))
        self.jitter_var.set(f"{packet.get('jitter',0)} ms")
        self.i2c_var.set(str(packet.get("i2c_compromised", False)))

        self.append_log(json.dumps(packet))

    def zeroize(self):

        global client_socket

        if client_socket is None:
            return

        try:
            client_socket.sendall(b"ZEROIZE")
            self.append_log(">>> ZEROIZE command sent.")
        except Exception as e:
            self.append_log(str(e))


def server_thread():

    global client_socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(1)

    dashboard.append_log(f"Listening on {HOST}:{PORT}")

    while True:

        client_socket, addr = server.accept()
        dashboard.append_log(f"Connected: {addr}")

        try:

            while True:

                data = client_socket.recv(1024)

                if not data:
                    break

                try:
                    packet = json.loads(data.decode())
                    root.after(0, dashboard.update_dashboard, packet)
                except Exception as e:
                    root.after(0, dashboard.append_log, str(e))

        except Exception as e:
            root.after(0, dashboard.append_log, str(e))

        dashboard.append_log("Client disconnected.")

        try:
            client_socket.close()
        except:
            pass

        client_socket = None


root = tk.Tk()

dashboard = Dashboard(root)

threading.Thread(target=server_thread, daemon=True).start()

root.mainloop()