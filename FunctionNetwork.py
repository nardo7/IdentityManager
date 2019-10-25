import BlockChain
from BlockChain import Identity, Block
import socket
from time import localtime, sleep
import serpent
from threading import Thread, Lock
import threading
import pickle

NODE_NETWORK = 2
WALLET = 4
FULL_NODE = 8
MINER_NODE = 16
PORT = 3500
MAX_NODES = 20
Kill = False


class Connetcion:
    def __init__(self, ip, port, sock=None, is_connected=0):
        self.ip = ip
        self.port = port
        self.is_connected = is_connected
        if sock is not None:
            self.s = sock
            return
        self.s = socket.socket()
        try:
            #print("trying to connect to", ip, port)
            self.s.connect((ip, port))
           # print("succesfull connection")
            self.is_connected = True
        except Exception as e:
            print("no se pudo conectar ", str(e))
            self.s.close()
            self.s = None

    def connect(self):
        if self.is_connected:
            return
        else:
            self.s = socket.socket()
            try:
                #print("trying to connect to", self.ip, self.port)
                self.s.connect((self.ip, self.port))
                #print("succesfull connection")
                self.is_connected = True
            except:
                print("no se pudo conectar")
                self.s = None

    def close(self):
        self.s.close()
        print("connection closed", self.ip)
        self.s = None
        self.is_connected = False

    def send(self, bytes):
        if self.is_connected == False:
            self.connect()
        if self.s == None:
            self.connect()
            if self.s == None:
                self.is_connected = False
                return
        sent = 0
        count = int(len(bytes))
        # print("sending "+str(count)+"bytes... ")
        self.s.send(count.to_bytes(4, 'big'))
        try:
            if count<=10 and bytes.decode()=="lock":
                print(bytes)
            sent = self.s.send(bytes)
        except Exception as e:
            print("solo se pudo enviar" + str(sent) + " de " + str(len(bytes)), e)
            # print("success!")

    def recv(self):
        if self.is_connected == False:
            print("no estas conectado para poder recibir")

        count = self.s.recv(4)
        count = int.from_bytes(count, 'big')
        # print("recieving " + str(count) + "bytes... ")
        total_rcv = 0
        msg = bytes()
        while count > total_rcv:
            try:
                msg += self.s.recv(count - total_rcv)
                total_rcv = len(msg)
            except:
                print("error reciviendo " + str(total_rcv))
        # print("success!")
        return msg


class node:
    def __init__(self, blockChain, ip=None, port=0, addr_seed_node=None, is_seed=0, full_node=0):
        self.port = port
        if ip is None:
            self.ip = "0.0.0.0"
        else:
            self.ip = ip
        self.neighbors = {}
        self.nodes = []
        self.is_full_node = full_node
        self.buffer_hashes = []
        self.identity_pool = {}
        self.lock = Lock()
        self.dictreturn = {}
        self.currentBlock = []
        self.lock_sync = Lock()
        self.lock_buffer = Lock()
        self.lock_sql=Lock()
        # self.dir_BlockChain=dir_blockChain
        self.BlockChain = blockChain
        self.addr_seeds = []
        self.addr_seeds.append(addr_seed_node)
        self.is_seed = is_seed
        self.serializer = serpent.Serializer()
        if addr_seed_node != None:
            ip_seed, port_seed = addr_seed_node
            con = self.add_neighbor(addr_seed_node)
            if con is not None:
                self.add_node((ip_seed, port_seed))
                nodes = self.introduce_newly_into_net(con)
                self.introduce_newly_into_net(con)
        lst = Thread(target=self.__listen_nodes)
        chk = Thread(target=self.__checking_nodes)
        lst.start()
        chk.start()

    def init_net(self, seeds):
        # if len(self.nodes)<1 and len(seeds)<1:
        #   print("FATAL ERROR no se pudo inicializar red")
        #  return
        self.lock_sync = Lock()
        self.lock = Lock()
        self.lock_buffer = Lock()
        self.lock_sql=Lock()
        for seed in seeds:
            ip, port = seed
            if seed not in self.nodes:
                self.nodes.append(seed)
        con = None

        for node in self.nodes:
            con = Connetcion(node[0], node[1])
            if con.s != None:
                break
        if con != None and con.s != None:
            con.send(self.serializer.serialize((self.ip, self.port)))
            con.recv()
            if len(self.nodes) < MAX_NODES:
                con.send("getaddrs".encode())
                nodes = serpent.loads(con.recv())
                con.close()
                self._booststrap(nodes)
            con.connect()
            if con.s != None:
                con.send("getblock".encode())
                msg = con.recv()
                con.send(self.BlockChain.height.to_bytes(4, 'big'))
                count = int.from_bytes(msg, 'big')
                if count > self.BlockChain.height:
                    self._recv_hashs(con)
                    self.sync()
                th = Thread(target=self.__listen_nodes)
                chk = Thread(target=self.__checking_nodes)
                th.start()
                chk.start()
            else:
                self.init_net([])
        elif self.is_seed != 1:
            print("no se pude inicializar la red")
        else:
            th = Thread(target=self.__listen_nodes)
            chk = Thread(target=self.__checking_nodes)
            th.start()
            chk.start()

    def sync(self):
        if len(self.buffer_hashes) == 0:
            return
        count = int(len(self.buffer_hashes) / len(self.nodes))
        rest = len(self.buffer_hashes) % len(self.nodes)

        i = -1
        threads = []
        hashes = []
        hashes.append(self.buffer_hashes[0])
        lenBuf = len(self.buffer_hashes)
        if count > len(self.nodes):
            for node in self.nodes:
                i += 1
                self.lock_buffer.acquire()
                if lenBuf > len(self.buffer_hashes):
                    lenBuf = len(self.buffer_hashes)
                    i = 0
                    hashes.append(self.buffer_hashes[0])
                hashes.extend(self.buffer_hashes[count * i + 1:count * (i + 1)])
                if i == 1:
                    print(i)
                self.lock_buffer.release()
                if self.nodes.index(node) == len(self.nodes) - 1 and rest != 0:
                    hashes.extend(self.buffer_hashes[count * (i + 1):len(self.buffer_hashes)])
                if self.dictreturn.get(self.nodes.index(node)) == None:
                    self.dictreturn[self.nodes.index(node)] = ([], count * i + 1, count * (i + 1))
                th = Thread(target=self.get_blocks, args=[node, hashes, self.nodes.index(node)])
                th.start()
                th.join()
                threads.append(th)
                hashes = []
            for t in threads:
                if t.is_alive():
                    t.join()
        else:
            if self.dictreturn.get(0) == None:
                self.dictreturn[0] = ([], count * i + 1, count * (i + 1))
            th = Thread(target=self.get_blocks, args=[self.nodes[0], self.buffer_hashes, 0])
            th.start()
            th.join()
        if len(self.buffer_hashes) > 0:
            self.sync()
        else:
            for value in self.dictreturn.values():
                self.into_blockchain(value[0])
            self.dictreturn.clear()

    def into_blockchain(self, blocks):
        self.BlockChain.add_blocks(blocks)

    def get_blocks(self, node, hashes, i):
        ip, port = node
        con = Connetcion(ip, port)
        if con.s == None:
            self.nodes.remove(node)
            return
        if self.is_full_node:
            con.send("getdata".encode())
        else:
            con.send("getheaders".encode())
        con.send(self.serializer.serialize(hashes))
        msg = con.recv()
        blocks = []
        while msg.islower() == False:
            # blockdict=serpent.loads(msg)
            # print(msg)
            try:
                block = Block.decode(msg)
            except Exception as e:
                print(e)
            blocks.append(block)
            msg = con.recv()
        if len(blocks) == 0:
            con.close()
            self.nodes.remove(node)
        self.lock_sync.acquire()
        blocks_local, init, end = self.dictreturn[i]
        if len(blocks_local) > 0:
            for value in self.dictreturn.values():
                blocks_local, init, end = value
                if len(blocks_local) > 0:
                    hash = blocks_local[-1].get_hash()
                    if hash == blocks[0].header.previous_block_hash:
                        blocks_local.extend(blocks)
                        break
        else:
            blocks_local.extend(blocks)
        self.lock_buffer.acquire()
        for hash in hashes:
            self.buffer_hashes.remove(hash)
        self.lock_buffer.release()
        self.lock_sync.release()

    def _make_version_msg(self, con):
        version_msg = {}
        version_msg["services"] = NODE_NETWORK
        version_msg["nTime"] = localtime()
        version_msg["addru"] = (con.ip, con.port)
        version_msg["addrm"] = (self.ip, self.port)
        version_msg["bestheight"] = self.BlockChain.height
        return version_msg

    # introducirse en la red
    def introduce_newly_into_net(self, con):
        version_msg = self._make_version_msg(con)
        file = self.serializer.serialize(version_msg)
        con.send(file)
        msg = con.recv()
        if msg.decode() == "ok":
            msg = con.recv()
            version_msg = serpent.loads(msg)
            ip, port = version_msg["addru"]
            if self.ip != ip:
                self.ip = ip
            msg = con.recv()
            nodes = serpent.loads(msg)
            self._booststrap(nodes)
            if version_msg["bestheight"] > self.BlockChain.height:
                con.send("inv".encode())
                self._recv_hashs(con)
            con.send("ok".encode())
            con.close()

            return nodes
        con.close()

    def _recv_hashs(self, con):
        msg = con.recv()
        while msg.decode() != "finish":
            print(msg)
            try:
                self.buffer_hashes.extend(serpent.loads(msg))
            except Exception as e:
                print(e)
            self.sync()

            msg = con.recv()
            if len(msg) == 0:
                con.close()
                con.connect()
                con.send("getblock".encode())
                msg = con.recv()
                con.send(self.BlockChain.height.to_bytes(4, 'big'))
                count = int.from_bytes(msg, 'big')
                if count <= self.BlockChain.height:
                    return
                msg = con.recv()

    # propagar por la red hasta tener max nodes
    def _booststrap(self, nodes):
        i = 0
        if len(self.neighbors) >= MAX_NODES or len(nodes) < 1:
            return
        for addr in nodes:
            ip, port = addr
            if (ip + str(port)) != (self.ip + str(self.port)) and (ip + str(port)) not in self.neighbors:
                con = self.add_neighbor(addr)
                if con != None:
                    self.add_node(addr)
                    new_nodes = self._introduce(con)
                    self._booststrap(new_nodes)

    # introducir un nodo
    def _introduce(self, con):
        file = self.serializer.serialize((self.ip, self.port))
        print("introducing a new node")
        con.send(file)
        msg = con.recv()
        if msg.decode() == "ok":
            print("ok")
            if len(self.neighbors) < MAX_NODES:
                con.send("getaddrs".encode())
                msg = con.recv()
                nodes = serpent.loads(msg)
                return nodes
        else:
            con.send("ok")
            return []

    # escuchar para nodos
    def __listen_nodes(self):
        self.sock_listening = socket.socket()
        self.sock_listening.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_listening.bind((self.ip, self.port))
        self.sock_listening.listen()
        while 1:
            print("listening at ", self.ip, self.port)
            sock, addr = self.sock_listening.accept()
            ip, port = addr
            con = Connetcion(ip, port, sock, 1)
           # print("hello ", addr)
            Thread(target=self._comunicate, args=[con]).start()

    # revisar que quiere el nodo
    def _comunicate(self, con):
        msg = con.recv()
        if msg.decode() == "ok":
            msg = con.recv()
            node = pickle.loads(msg)
            if node in self.nodes:
                return
            else:
                self.nodes.append(node)
            con.close()
            return
        if msg.decode() == "getblock":
            con.send(self.BlockChain.height.to_bytes(4, 'big'))
            msg = con.recv()
            count = int.from_bytes(msg, 'big')
            if count < self.BlockChain.height:
                self.send_hashs(con, count)
            con.close()
            return
        if msg.decode() == "getdata":
            self.__send_blocks(con)
            con.close()
            return
        if msg.decode() == "getheaders":
            self.__send_blocks(con, False)
            con.close()
            return
        if msg.decode() == "id":
            self.__recv_id(con)
            con.close()
            return
        if msg.decode() == "block":
            self.__recv_block(con)
            con.close()
        else:
            obj = serpent.loads(msg)
            if type(obj) is tuple:
                if obj not in self.nodes:
                    self.lock.acquire()
                    self.add_node(obj)
                    self.lock.release()
                con.send("ok".encode())
                msg = con.recv()
                if msg.decode() == "getaddrs":
                    self.lock.acquire()
                    msg = self.serializer.serialize(self.nodes)
                    self.lock.release()
                    con.send(msg)
                    con.close()
            else:
                self.introduce_new_node(con, obj)

    def __recv_block(self, con):
        file = con.recv()
        block = Block.decode(file)
        self.lock_sync.acquire()
        self.currentBlock.append(block)
        self.lock_sync.release()

    def __checking_nodes(self):
        import pickle
        while 1:
            tmp = []
            for node in self.nodes:
                con = Connetcion(node[0], node[1])
                if con.s != None:
                    con.send("ok".encode())
                    con.send(pickle.dumps((self.ip, self.port)))
                    tmp.append(node)
            self.nodes = tmp

            sleep(4)

    def __recv_id(self, con):
        file = con.recv()
        import pickle
        ident = pickle.loads(file)
        # ident=Identity.decode(file)
        self.identity_pool[ident.get_hash()] = ident

    def send_block_to_net(self, block):
        tmp=[]
        for node in self.nodes:
            con = Connetcion(node[0], node[1])
            if con.s != None:
                tmp.append(node)
                self.send_block(con, block)
        self.nodes=tmp
        
    def send_block(self, con, block, hash=None):
        if block != None:
            con.send('block'.encode())
            con.send(block.encode())
        else:

            block = self.BlockChain.get_block(hash)

            if block != None:
                con.send(block.encode())
            else:
                con.send("notexist".encode())

    def send_id(self, id):
        for node in self.nodes:
            con = Connetcion(node[0], node[1])
            if con.s == None:
                self.nodes.remove(node)
            else:
                self.__send_id__(con, id)

    def __send_id__(self, con, id):
        con.send("id".encode())
        import pickle
        byte = pickle.dumps(id)
        # byte=self.serializer.serialize(id)
        con.send(byte)
        con.close()

    def __send_blocks(self, con, full_block=True):
        msg = con.recv()
        hashes = serpent.loads(msg)
        if hashes != None:
            for hash in hashes:

                block = self.BlockChain.get_block(hash)

                if block != None:
                    if full_block == False:
                        block = block.to_ligthweightL()
                    file = block.encode()
                    con.send(file)
                else:
                    con.send("notexist")
            con.send("finish".encode())

    # introduce un nuevo nodo a la red
    def introduce_new_node(self, con, version_msgu):
        ip = con.ip
        ip_old, port = version_msgu["addrm"]
        self.add_node((ip, port))

        con.send("ok".encode())
        version_msg = self._make_version_msg(con)
        con.send(self.serializer.serialize(version_msg))
        self.__send_nodes(con)
        msg = con.recv()
        if msg.decode() == "inv":
            height = version_msgu["bestheight"]
            self.send_hashs(con, height)
        msg = con.recv()
        con.close()

    def __send_nodes(self, con):
        msg = self.serializer.serialize([node for node in self.nodes])
        con.send(msg)

    def send_hashs(self, con, start, hash=None):
        if hash != None:
            con.send(hash.encode())
        else:
            count = start
            while count < self.BlockChain.height:

                hashs = self.BlockChain.get_hash_from(count)

                if len(hashs) <= 0:
                    con.send("finish".encode())
                    return
                con.send(self.serializer.serialize(hashs))
                count += len(hashs)
            con.send("finish".encode())

    # agrega un nodo nuevo para saber su existencia
    def add_node(self, addr):
        ip, port = addr
        if hasattr(self, "nodes") == False:
            self.nodes = []
        if addr not in self.nodes:
            self.nodes.append(addr)
        else:
            print("the address already exists")

    # agrega una conexion nueva
    def add_neighbor(self, addr, sock=None, is_connected=False):
        ip_seed, port_seed = addr
        print("adding node", ip_seed)
        con = Connetcion(ip_seed, port_seed, sock, is_connected)
        if con.s is not None:
            self.neighbors[ip_seed + str(port_seed)] = con
            print("success!")
            return con
        print("failed adding node")
