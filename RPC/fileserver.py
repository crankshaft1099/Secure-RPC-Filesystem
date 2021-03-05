from socket import socket, AF_INET, SOCK_STREAM
from cryptography.fernet import Fernet
import random 
import os

HOST = '127.0.0.1'
PORT = 65432

FS_HOST = '127.0.0.2'
FS_PORT = 65433

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

def ns_auth():
    address=(HOST,PORT)
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(address)
        server_msg=b"Register_Server"
       
        request="{},{},{}".format(server_msg, FS_HOST,FS_PORT)
        request = convert_to_bytes(request)
        #Step 1
        sock.sendall(request)

        #Step 2
        key=sock.recv(1024)
        key=decode(key)
        unique_id=sock.recv(1024)
        unique_id=decode(unique_id)
        print("Server Unique ID: ",unique_id)
        print("Server Key with KDC: ",key)
        # value of key is assigned to a variable 
        f= Fernet(key)
        sock.close()
        return f

def inf_listen(f):
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((FS_HOST, FS_PORT))
        while True:
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                print('FS connection from address: ', addr)
                request = conn.recv(1024)
                # save extracted public key as local file
                request=decode(request)
                Ra2, client_id, key_c_fs = request.split(',')
                Ra2=Ra2[2:-1]

#decrypt all===================================================
                client_id=decrypt(f,client_id)
                client_id=decode(client_id)
                key_c_fs=decrypt(f,key_c_fs)
                key_c_fs=decode(key_c_fs)
                key_c_fs=Fernet(key_c_fs)
                Ra2=decrypt(key_c_fs,Ra2)
                Ra2=decode(Ra2)
                Ra2=int(Ra2)
#==================================================================
                confirm=encrypt(key_c_fs,str(Ra2-1))
                Ra3= random.randrange(1, 1000, 1)
                request = "{},{}".format(confirm, str(Ra3))
                request = convert_to_bytes(request)
                conn.sendall(request)
#===================================================================

                request=conn.recv(1024)
                request=key_c_fs.decrypt(request)
                request=decode(request)
                request=(int)(request)
                if request!=(Ra3-1):
                    print("Authentication Failed")
                    break

#=================================================================
                while True:
                    request=conn.recv(1024)
                    
                    request=decode(request)   
                    
                    request=decrypt(key_c_fs,request)

                    request=decode(request)
                    print(request,"command requested from client.")
                    if request=="pwd":
                        import os
                        cur_dir=os.getcwd()
                        cur_dir=encrypt(key_c_fs,cur_dir)
                        conn.sendall(cur_dir)
                    elif request=="cat":
                        file_name=conn.recv(1024)
                        file_name=decode(file_name)     
                        file_name=decrypt(key_c_fs,file_name)
                        file_name=decode(file_name)
                        if os.path.isfile(file_name):
                            f_obj = open(file_name, "r")
                            text = f_obj.read()
                            f_obj.close()
                            text=encrypt(key_c_fs,text)
                            conn.sendall(text)
                        else:
                            text="File not found"
                            text=encrypt(key_c_fs,text)
                            conn.sendall(text)
                    elif request=="ls":
                        import os
                        arr = os.listdir()
                        listToStr = ','.join([str(elem) for elem in arr]) 
                        listToStr=encrypt(key_c_fs, listToStr)
                        conn.sendall(listToStr)
                    elif request=="cp":
                        from shutil import copyfile 
                        files=conn.recv(1024)
                        files=decode(files)     
                        files=decrypt_and_decode(key_c_fs,files)
                        file1, file2=files.split(' ')   
                        if os.path.isfile(file1):                 
                            copyfile(file1, file2)
                            confirm="Files copied"
                            confirm=encrypt(key_c_fs,confirm)
                            conn.sendall(confirm)     
                        else:
                            confirm="File not found"
                            confirm=encrypt(key_c_fs,confirm)
                            conn.sendall(confirm)
                    else:
                        break          

                
if __name__ == "__main__":
    f=ns_auth()
    inf_listen(f)