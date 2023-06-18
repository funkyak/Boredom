from  paramiko import SSHClient, AutoAddPolicy
import time
import re
import base64
server = "bandit.labs.overthewire.org" # Hostname
port_bandit = "2220"  # port
counter = 0
time.sleep(4)

for counter in range(0, 34):
    ################################################################ Level 0
    username_bandit = "bandit0"
    Key = "bandit0" # password
    cmd= "cat readme"  #command

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""
    time.sleep(4)
    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    Key= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    for line in stdout:
        Key=Key+line
    if Key!="":
        print("Password for {} : {}".format(username_bandit, Key))

    Key = Key.strip()
    counter +=1
    ################################################################ Level 1 
    username_bandit = "bandit{}".format(counter) # Username
    cmd= "cat ./-"  #command

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    for line in stdout:
        Key=Key+line
    if Key!="":
        print("Password for {} : {}".format(username_bandit, Key))

    time.sleep(3)
    Key = Key.strip()
    counter += 1
    ################################################################ Level 2 
    username_bandit = "bandit{}".format(counter) # Username
    cmd= "cat 'spaces in this filename'"  #command

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    for line in stdout:
        Key=Key+line
    if Key!="":
        print("Password for {} : {}".format(username_bandit, Key))

    time.sleep(3)
    Key = Key.strip()
    counter += 1
    ################################################################ Level 3 
    username_bandit = "bandit{}".format(counter) # Username
    cmd= "cat inhere/.hidden"  #command

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    for line in stdout:
        Key=Key+line
    if Key!="":
        print("Password for {} : {}".format(username_bandit, Key))
    Key = Key.strip()
    counter += 1
    ################################################################ Level 4 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='cd inhere; for i in $(seq -w 0 9); do filename="./-file0$i"; cat "$filename"| iconv -f UTF-8; content=$(cat "$filename"); [ ${#content} -eq 32 ] && echo "Content: $content" | iconv -f UTF-8; done'

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    pattern = r"Content: (.{32})"

    matches = re.findall(pattern, "".join(stdout))
    for match in matches:
        #print(match)
        pass
    # Add magic
    for line in match:
        Key=Key+line
    if Key!="":
        pass
        print("Password for {} : {}\n".format(username_bandit, Key))
    Key = Key.strip()
    counter += 1
    ################################################################ Level 5 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='''find inhere/ -type f -size 1033c -exec sh -c 'file "{}" | grep -q "ASCII text" && cat "{}"' \;'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    pattern = r'^[!-~]{32}$'

    matches = []
    for element in stdout:
        if isinstance(element, str):
            match = re.findall(pattern, element)
            matches.extend(match)

    for line in matches:
        Key=Key+line
        if Key!="":
            
            print("Password for {} : {}\n".format(username_bandit, Key))
    Key = Key.strip()
    counter += 1
    ################################################################ Level 6 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='''find / -type f -user bandit7 -group bandit6 -size 33c -exec cat {} \;'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()
    pattern = r"Content: (.{32})"

    matches = re.findall(pattern, "".join(stdout))
    for match in matches:
        print(match)
        #pass

    for line in stdout:
        Key=Key+line
    if Key!="":
        pass
        print("Password for {} : {}".format(username_bandit, Key))
    Key = Key.strip()
    counter += 1
    ################################################################ Level 7 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='''awk '/millionth/ {print $2}' data.txt'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()
    

    for line in stdout:
        Key=Key+line
    if Key!="":
        pass
        print("Password for {} : {}".format(username_bandit, Key))
    Key = Key.strip()
    counter += 1
    ################################################################ Level 8 
    username_bandit = "bandit{}".format(counter) # Username
    cmd=''' sort data.txt | uniq -u'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()


    for line in stdout:
        Key=Key+line
    if Key!="":
        pass
        print("Password for {} : {}".format(username_bandit, Key))
    Key = Key.strip()
    
    counter += 1
    ################################################################ Level 9 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='''strings data.txt | grep "=.\{33,\}"'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""

    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()


    pattern = r"[^0-9a-zA-Z\s]+"

    # Assuming `stdout` is a list of strings
    clean_string = ''.join(stdout)  # Convert the list to a string
    clean_string = re.sub(pattern, "", clean_string)

    Key = ""
    for line in clean_string:
        Key += line
        if len(Key) == 33:
            print("Password for {}: {}\n".format(username_bandit, Key))
    Key = Key.strip()
    
    counter += 1
    ################################################################ Level 10 
    username_bandit = "bandit{}".format(counter) # Username
    cmd='''strings data.txt'''

    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    Key=""
    decoded_lines = []
    passwords = []
    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout= ssh_stdout.readlines()

    time.sleep(2)
    client.close()

    for line in stdout:
        decoded_line = base64.b64decode(line)
        decoded_lines.append(decoded_line.decode())


    for line in decoded_lines:
        password = re.search(r'\b\w{32}\b', line)
        if password:
            passwords.append(password.group())
    if passwords:
        for password in passwords:
            
            Key=password
    
    print("Password for {}: {}\n".format(username_bandit, Key))
    Key = Key.strip()
    
    counter += 1
    ################################################################ Level 11
    username_bandit = "bandit{}".format(counter) # Username
    cmd = "cat data.txt"

    # Establish SSH connection
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)
    
    Key=""
    # Execute the command and retrieve output
    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout = ssh_stdout.readlines()
    time.sleep(2)
    client.close()

    # Extract the key
    text = re.search(r'\b\w{32}\b', ''.join(stdout))
    if text:
        Key = text.group(0)

    # ROT13 decryption for the key
    def decrypt_rot13(ciphertext):
        decrypted_text = ""
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                decrypted_char = chr((ord(char) - ascii_offset + 13) % 26 + ascii_offset)
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text

    # Decrypt the key using ROT13
    Key = decrypt_rot13(Key)

    # Output the decrypted key and original key
    print("Password for {}: {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 12
    username_bandit = "bandit{}".format(counter) # Username
    cmd = '''tmp_dir=$(mktemp -d) ; cd "$tmp_dir" ; cp ~/data.txt . ; xxd -r data.txt > file1.bin ;zcat file1.bin > file2;bzcat file2 > file3 ;zcat file3 > file4 ;tar -xvf file4;tar -xvf data5.bin;bzcat data6.bin > file7;tar -xvf file7;zcat data8.bin > output.txt;cat output.txt'''

    # Establish SSH connection
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the command and retrieve output
    ssh_stdin, ssh_stdout, ssh_stderr = client.exec_command(cmd)
    stdout = ssh_stdout.readlines()
    time.sleep(2)
    client.close()
    text = re.search(r'\b\w{32}\b', ''.join(stdout))
    if text:
        Key = text.group(0)

    print("Password for {} : {}".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    
    ################################################################ Level 13
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = 'ssh -o "StrictHostKeyChecking=no" bandit14@localhost -p 2220 -i sshkey.private cat /etc/bandit_pass/bandit14'

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    time.sleep(2)
    client.close()

    print("Password for {} : {}".format(username_bandit, Key))

    Key = Key.strip()
