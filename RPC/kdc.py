from socket import socket, AF_INET, SOCK_STREAM
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 65432
client_cnt=1
server_cnt=1
server={}
client={}
fs_addr={}
fs_addr_rev={}
client_username={}

def convert_to_bytes(request):
    request=bytes(request,'utf-8')
    return request

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt(obj,request):
    request=obj.encrypt(convert_to_bytes(request))
    return request

def error_msg(key):
    msg="Error Occurred"
    msg=encrypt(key,msg)
    return msg

def read_file():
    global client_username
    with open("database.txt") as fp:
        for i in fp.readlines():
            line=i.strip()
            username,password=line.split(',')
            client_username[username]=password


def ns_auth():
    global client_cnt,server_cnt,server,client,client_username,fs_addr,fs_addr_rev
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        while True:
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                print('KDC: connection from address', addr)
                request = conn.recv(1024)
                if not request:
                    break
                # save extracted public key as local file
                request=request.decode('utf-8')
                msg,p1,p2 = request.split(',')
                msg=msg[2:-1]

                if msg=="Register_Client":
                    key=generate_key()
                    conn.sendall(key)
                    if p1 not in client_username.keys() or client_username[p1]!=p2:
                        unique_id=bytes(str(-1),'utf-8')
                        conn.sendall(unique_id)
                    else:
                        unique_id=bytes(str(client_cnt),'utf-8')
                        client[client_cnt]=key
                        client_cnt+=1
                        conn.sendall(unique_id)
                elif msg=="Register_Server":
                    fs_host, fs_port =  p1,p2
                    if (fs_host,fs_port) in fs_addr_rev.keys():
                        uid=fs_addr_rev[(fs_host,fs_port)]
                        ukey=server[uid]
                        conn.sendall(ukey)
                        unique_id=bytes(str(uid),'utf-8')
                        conn.sendall(unique_id)
                    else:
                        key=generate_key()
                        conn.sendall(key)
                        unique_id=bytes(str(server_cnt),'utf-8')
                        conn.sendall(unique_id)
                        server[server_cnt]=key
                        fs_addr[server_cnt]=(fs_host, fs_port)
                        fs_addr_rev[(fs_host,fs_port)]=server_cnt
                        server_cnt+=1
                else:
                    Ra, client_id, fs_id = msg,p1,p2
                    f=Fernet(client[(int)(client_id)])
                    print("Client Id and Server Id that want to communicate are: ",client_id,fs_id)

                    #Step 4
                    enc_Ra=f.encrypt(bytes(Ra, 'utf-8'))
                    enc_fs_id=f.encrypt(bytes(fs_id, 'utf-8'))
                    key_c_fs=generate_key()
                    enc_key_c_fs=f.encrypt(key_c_fs)

                    fs_kdc_key=server[int(fs_id)]
                    #============================================

                    fs_kdc_key=Fernet(fs_kdc_key)
                    enc_A=f.encrypt(fs_kdc_key.encrypt(bytes(client_id, 'utf-8')))
                    enc_enc_key_c_fs=f.encrypt(fs_kdc_key.encrypt(key_c_fs))
                    #host and port encrypt
                    fs_host=fs_addr[int(fs_id)][0]
                    fs_port=fs_addr[int(fs_id)][1]
                    response2 = "{},{},{},{},{},{},{}".format(enc_Ra, enc_fs_id, enc_key_c_fs, enc_A, enc_enc_key_c_fs, fs_host, fs_port)
                    response2 = bytes(response2, 'utf-8')
                    conn.sendall(response2) 

                    
                
if __name__ == "__main__":
    read_file()
    ns_auth()    