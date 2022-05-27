from flask import Flask, render_template, url_for, request, redirect
import sys,requests,random
import socket
import json
import hashlib
import binascii
from pprint import pprint
import time
from threading import Thread
import json
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

address = '15iL4YKh2yMSnbmnz4zBJC2efeevtoYz5e'
dd=True


#https://solo.ckpool.org/users/15iL4YKh2yMSnbmnz4zBJC2efeevtoYz5e
nonce   = hex(random.randint(0,2**32-1))[2:].zfill(8)

host    = 'solo.ckpool.org'
port    = 3333

# print("address:{} nonce:{}".format(address,nonce))
# print("host:{} port:{}".format(host,port))

sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host,port))

#server connection
sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
lines = sock.recv(1024).decode().split('\n')
response = json.loads(lines[0])
sub_details,extranonce1,extranonce2_size = response['result']

#authorize workers
sock.sendall(b'{"params": ["'+address.encode()+b'", "password"], "id": 2, "method": "mining.authorize"}\n')

#we read until 'mining.notify' is reached
response = b''
while response.count(b'\n') < 4 and not(b'mining.notify' in response):
    response += sock.recv(1024)


#get rid of empty lines
responses = [json.loads(res) for res in response.decode().split('\n') if len(res.strip())>0 and 'mining.notify' in res]
# pprint(responses)

job_id,prevhash,coinb1,coinb2,merkle_branch,version,nbits,ntime,clean_jobs \
    = responses[0]['params']

target = (nbits[2:]+'00'*(int(nbits[:2],16) - 3)).zfill(64)
# print('nbits:{} target:{}\n'.format(nbits,target))

# extranonce2 = '00'*extranonce2_size
extranonce2 = hex(random.randint(0,2**32-1))[2:].zfill(2*extranonce2_size)      # create random

coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

# print('coinbase:\n{}\n\ncoinbase hash:{}\n'.format(coinbase,binascii.hexlify(coinbase_hash_bin)))
merkle_root = coinbase_hash_bin
for h in merkle_branch:
    merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

merkle_root = binascii.hexlify(merkle_root).decode()

#little endian
merkle_root = ''.join([merkle_root[i]+merkle_root[i+1] for i in range(0,len(merkle_root),2)][::-1])

# print('merkle_root:{}\n'.format(merkle_root))
t = time.localtime(time.time()+10800)
current_time = time.strftime("%Y-%m-%d %H:%M:%S", t)
blockheader = version + prevhash + merkle_root + nbits + ntime + 'random' +\
    '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
@app.route('/')
def index():
    # extranonce2 = '00'*extranonce2_size
    extranonce2 = hex(random.randint(0,2**32-1))[2:].zfill(2*extranonce2_size)      # create random
    
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()
    
    # print('coinbase:\n{}\n\ncoinbase hash:{}\n'.format(coinbase,binascii.hexlify(coinbase_hash_bin)))
    merkle_root = coinbase_hash_bin
    for h in merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()
    
    merkle_root = binascii.hexlify(merkle_root).decode()
    
    #little endian
    merkle_root = ''.join([merkle_root[i]+merkle_root[i+1] for i in range(0,len(merkle_root),2)][::-1])
    
    # print('merkle_root:{}\n'.format(merkle_root))
    blockheader = version + prevhash + merkle_root + nbits + ntime + 'random' +\
        '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
    return '{"header":"'+blockheader+'", "lasttime":"'+current_time+'", "target":"'+target+'", "extranonce2":"'+extranonce2+'", "secuental":"off", "logs":"on"}'

@app.route('/key/<id>')
def dogeapi(id):
    xyz = str(id).split("_")
    noncen   = xyz[0]
    extranonce2n = xyz[1]
    payload = bytes('{"params": ["'+address+'", "'+job_id+'", "'+extranonce2n \
        +'", "'+ntime+'", "'+noncen+'"], "id": 1, "method": "mining.submit"}\n', 'utf-8')
    sock.sendall(payload)
    print(payload)
    return str(sock.recv(1024).decode())+""


def run():
    app.run()
def keep_alive():
    server = Thread(target=run)
    server.start()
if __name__ == "__main__":
  app.run()

