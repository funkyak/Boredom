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

    print("Password for {} : {}\n".format(username_bandit, Key))

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

    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 14
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = 'nc localhost 30000 <<< $(cat /etc/bandit_pass/bandit14)'

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()

    # Extract the second line from the Key string
    key_lines = Key.split('\n')
    if len(key_lines) >= 2:
        Key = key_lines[1]
        print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 15
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = 'password=$(cat /etc/bandit_pass/bandit15); openssl s_client -quiet -connect localhost:30001 <<< "$password"'

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()

    # Extract the second line from the Key string
    key_lines = Key.split('\n')
    correct_index = key_lines.index('Correct!') if 'Correct!' in key_lines else -1

    if correct_index != -1 and correct_index + 1 < len(key_lines):
        Key = key_lines[correct_index + 1]
        print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 16
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = """
    port_number=$(nmap -p 31000-32000 -sV -T4 localhost | grep -Eo '^[0-9]+/tcp open\s+ssl/unknown' | grep -Eo '^[0-9]+');
    password=$(cat /etc/bandit_pass/bandit16);
    echo $password;
    private_key=$(echo "$password" | openssl s_client -quiet -connect localhost:$port_number 2>/dev/null | awk '/Correct!/ {flag=1; next} flag {print}');
    echo $private_key;
    random_folder_name="/tmp/random_$(date +%s)";
    mkdir "$random_folder_name";
    private_key_file="$random_folder_name/private_key.pem";
    echo "$private_key" > "$private_key_file" && chmod 700 "$private_key_file";
    ssh -o "StrictHostKeyChecking=no" -i $private_key_file bandit17@bandit.labs.overthewire.org -p 2220 "cat /etc/bandit_pass/bandit17"
    """

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    # Extract the second line from the Key string
    Key = Key.split('\n')[-1].strip()

    
    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 17
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = "diff passwords.old passwords.new | grep '>' | awk '{print $2}'"

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    
    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 18
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = "cat readme"

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    
    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 19
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = "./bandit20-do cat /etc/bandit_pass/bandit20"

    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    
    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1
    ################################################################ Level 20
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = """random_folder_name="/tmp/random_$(date +%s)";mkdir "$random_folder_name";script="$random_folder_name/script.sh"; echo -e 'echo -n "{}" | nc -l -p 1234 &\nsleep 2\n/home/bandit20/suconnect 1234' > $script && chmod 777 "$script"; bash $random_folder_name/script.sh""".format(Key)
    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()

    non_useful_words = ["Read", "Password"]  # Add your non-useful words to this list

    # Assuming 'Key' is a multiline string
    lines = Key.split('\n')
    filtered_lines = [line for line in lines if not any(word in line for word in non_useful_words)]
    filtered_key = '\n'.join(filtered_lines)
    Key = ""
    Key = filtered_key

    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1 

    ################################################################ Level 21
    username_bandit = "bandit{}".format(counter) # Username
    cmd_remote = '''random_folder_name="/tmp/random_$(date +%s)"; folder_path="/tmp/$random_folder_name"; mkdir -p "$folder_path"; script="$folder_path/script.sh"; echo -e 'cron_dir="/etc/cron.d"; desired_cron_level=22; check_directory() { local dir="$1"; if [ ! -d "$dir" ]; then echo "Directory not found: $dir"; exit 1; fi }; extract_and_display_file_info() { local line="$1"; local file_location=$(echo "$line" | awk "{print \$7}"); if [ -f "$file_location" ]; then echo "    Command runs file: $file_location"; example_command=$(cat "$file_location"); get_file_paths "$example_command"; fi }; get_file_paths() { local command="$1"; file_paths=$(echo "$command" | awk "{for(i=1;i<=NF;i++) if(\$i ~ /^\//) print \$i}"); for file_path in $file_paths; do cat_file_if_readable "$file_path"; done }; cat_file_if_readable() { local file_path="$1"; if [ -r "$file_path" ]; then cat "$file_path"; fi }; process_cron_file() { local file="$1"; local level="$2"; local commands=$(grep -E "^[^#].*$level" "$file" 2>/dev/null); if [ -n "$commands" ]; then echo "$commands" | while IFS= read -r line; do echo "  Cron Job: $line"; extract_and_display_file_info "$line"; done; fi }; cron_files=$(ls "$cron_dir"); check_directory "$cron_dir"; for cron_file in $cron_files; do if [ -f "$cron_dir/$cron_file" ]; then process_cron_file "$cron_dir/$cron_file" "$desired_cron_level"; fi; done' >"$script" && chmod 777 "$script" && bash "$script"'''
    # Establish SSH connection to remote server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(server, username=username_bandit, password=Key, port=port_bandit)

    # Execute the remote SSH command to retrieve file from local machine
    stdin, stdout, stderr = client.exec_command(cmd_remote)
    Key = stdout.read().decode().strip()
    Key = Key.split('\n')[-1].strip()
    print("Password for {} : {}\n".format(username_bandit, Key))

    Key = Key.strip()
    counter += 1 

##################### END 
    print("")
    print("END OF LOOP")
    break 
