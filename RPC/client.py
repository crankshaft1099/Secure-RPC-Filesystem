from socket import socket, AF_INET, SOCK_STREAM
from cryptography.fernet import Fernet
import random 
from cmd import Cmd
import getpass

HOST = '127.0.0.1'
PORT = 65432

def convert_to_bytes(request):
    request=bytes(request,'utf-8')
    return request

def decode(request):
    request=request.decode('utf-8')
    return request

def decrypt(obj,request):
    request=obj.decrypt(convert_to_bytes(request))
    return request

def encrypt(obj,request):
    request=obj.encrypt(convert_to_bytes(request))
    return request

def decrypt_and_decode(obj,request):
    request=obj.decrypt(convert_to_bytes(request))
    request=decode(request)
    return request

def error_msg(key):
    msg="Error Occurred"
    msg=encrypt(key,msg)
    return msg
 
class MyPrompt(Cmd):
    def __init__(self,sock,key_c_fs):
        self.sock=sock
        self.key_c_fs=key_c_fs
        super(MyPrompt,self).__init__()

    def do_com(self, inp):
        if inp[0:3]=="pwd":
            operation=encrypt(self.key_c_fs,inp)
            self.sock.sendall(operation)
            request=self.sock.recv(1024)
            request=decode(request)
            request=decrypt_and_decode(self.key_c_fs,request)
            print("Output of the command: ",request)
        elif inp[0:2]=="ls":
            operation=encrypt(self.key_c_fs, inp)
            self.sock.sendall(operation)
            request=self.sock.recv(1024)
            request=decode(request)
            request=decrypt_and_decode(self.key_c_fs,request)
            request=request.split(',')                
            print("Output of the command: ",request)
        elif inp[0:3]=="cat":
            operation=encrypt(self.key_c_fs, inp[0:3])
            self.sock.sendall(operation)
            file_name=inp[4:]
            file_name=encrypt(self.key_c_fs, file_name)
            self.sock.sendall(file_name)
            request=self.sock.recv(1024)
            request=decode(request)
            request=decrypt_and_decode(self.key_c_fs,request)
            print("Output of the command: ",request)
        elif inp[0:2]=="cp":
            operation=encrypt(self.key_c_fs, inp[0:2])
            self.sock.sendall(operation)
            files=inp[3:]
            files=encrypt(self.key_c_fs, files)
            self.sock.sendall(files)
            request=self.sock.recv(1024)
            request=decode(request)
            request=decrypt_and_decode(self.key_c_fs,request)                
            print("Output of the command: ",request)
        else:
            operation=encrypt(self.key_c_fs, inp)
            self.sock.sendall(operation)
            print("Exiting Connection")
            return True
 

def ns_auth():
    print("Username: ",end='')
    username=input()
    password=getpass.getpass()
    address=(HOST,PORT)
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(address)
        client_msg=b"Register_Client"
        request="{},{},{}".format(client_msg, username,password)
        request=convert_to_bytes(request)

        #Step 1
        sock.sendall(request)

        #Step 2
        key=sock.recv(1024)
        key=decode(key)
        unique_id=sock.recv(1024)
        unique_id=decode(unique_id)

        if int(unique_id)==-1:
            print("Client Not Authenticated",end='')
            exit()

        print("Client Unique ID: ",unique_id)
        print("Client Key with KDC: ",key)
        # value of key is assigned to a variable 
        f= Fernet(key)
        return int(unique_id),f


def communicate(fs_id,client_id,f):
    address=(HOST,PORT)
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(address)
        #Step 3
        Ra= random.randrange(1, 1000, 1)
        request2 = "{},{},{}".format(convert_to_bytes(str(Ra)), client_id, fs_id)
        request2 = convert_to_bytes(request2)
        sock.sendall(request2)

        #Step 4
        request= sock.recv(1024)
       
        request=decode(request)
        
        enc_Ra, enc_fs_id, enc_key_c_fs, enc_A, enc_enc_key_c_fs, fs_host, fs_port = request.split(',')

        enc_Ra=enc_Ra[2:-1]
        enc_fs_id=enc_fs_id[2:-1]
        enc_key_c_fs=enc_key_c_fs[2:-1]
        enc_A=enc_A[2:-1]
        enc_enc_key_c_fs=enc_enc_key_c_fs[2:-1]
        print("Server listening on host and port: ",fs_host,fs_port)
#decrypt all=========================================================
        new_Ra=decrypt_and_decode(f,enc_Ra)
        new_Ra=int(new_Ra)

        if new_Ra!=Ra:
            print("Authentication Failed")
            return

        new_fs_id=decrypt_and_decode(f,enc_fs_id)
        
        key_c_fs=decrypt_and_decode(f,enc_key_c_fs)

        new_A=decrypt_and_decode(f,enc_A)

        enc_key_c_fs=decrypt_and_decode(f,enc_enc_key_c_fs)
#=============================================================================
        
        #print("Ra, enc_fs_id, enc_key_c_fs, enc_A, enc_enc_key_c_fs\n")
        #print(enc_Ra+" "+enc_fs_id+" "+enc_key_c_fs+" "+enc_A+" "+enc_enc_key_c_fs)

        #Step 5 (Change connection to file server)
        sock.close()

        fs_port=int(fs_port)
        fs_addr=(fs_host, fs_port)
        print("Session Key with Server: ",key_c_fs)
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect(fs_addr)
            Ra2= random.randrange(1, 1000, 1)
            Random_num=Ra2
            key_c_fs=Fernet(key_c_fs)
            Ra2=encrypt(key_c_fs,str(Ra2))
            request3 = "{},{},{}".format(Ra2, new_A, enc_key_c_fs)
            request3 = convert_to_bytes(request3)
            
            sock.sendall(request3)
            request=sock.recv(1024)
            request=decode(request)
            confirm, Ra3=request.split(',')
            Ra3=int(Ra3)
            confirm=confirm[2:-1]
            confirm=decrypt_and_decode(key_c_fs,confirm)

            confirm=int(confirm)
            if confirm!=(Random_num-1):
                print("Authentication Failed")
                return
#last step===========================================================
            Ra3=encrypt(key_c_fs,str(Ra3-1))
            sock.sendall(Ra3)

            MyPrompt(sock,key_c_fs).cmdloop()

if __name__ == "__main__":
    client_id,f=ns_auth()
    while True:
        print("Enter File Server Id to communicate with: ")
        fs_id=(int)(input())
        communicate(fs_id,client_id,f)