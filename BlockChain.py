__author__ = 'Nardo'
from hashlib import sha256
from pycoin import ecdsa, key, merkle, block, encoding
from pycoin.serialize import b2h
import sqlite3
import os.path as p
import serpent
import pickle
import io, os.path
import Trie

from threading import Lock
class Date:
    def __init__(self, day, month, year):
        self.day = day
        self.month = month
        self.year = year

    def __str__(self):
        return str(self.day) + "/" + str(self.month) + "/" + str(self.year)


class Identity:
    def __init__(self, name, last_name, ID, date, sex, public_key):
        self.name = name
        self.last_name = last_name
        self.ID = ID
        list = str.split(date, '/')
        self.date = Date(list[0], list[1], list[2])
        if str.lower(sex) == 'm':
            self.sex = 1
        else:
            self.sex = 0
        self.public_key = public_key

    def __str__(self):
        return self.name + " " + self.last_name + " " + self.ID

    def get_hash(self):
        if hasattr(self, "hash"):
            return self.hash
        full_data = ""
        full_data += str(self.name + self.last_name + str(self.sex) + str(self.date) + self.ID)

        self.hash = encoding.hash160(full_data.encode())
        print(self.hash)
        return self.hash

    @classmethod
    def decode(self, file):
        id_dict = serpent.loads(file)
        id = Identity(0, 0, 0, 0, 0, 0)
        id.__dict__ = id_dict
        return id


class Auth:
    def __init__(self, data, signature, issuer_public_key):
        self.data = data
        self.signature = signature
        self.issuer_public_key = issuer_public_key

    def seal(self):
        self.hash = sha256(self.data)
        return self.hash


class BlockHeader:
    def __init__(self, previous_block_hash, merkle_root, merkle_root_auths, creator_address):
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.merkle_root_auths = merkle_root_auths
        self.creator_address = creator_address


class Block:
    def __init__(self, previous_block_hash, merkle_root_identities, merkle_root_auths, creator_address):
        self.header = BlockHeader(previous_block_hash, merkle_root_identities, merkle_root_auths, creator_address)
        self.identities = []
        self.auths = []

    # dos merkle root distintos, para auth y otro pa ident
    def set_identities(self, identities):
        calculated_hash = merkle.merkle([id.get_hash() for id in identities], merkle.double_sha256)
        if calculated_hash != self.header.merkle_root:
            raise block.BadMerkleRootError(
                "calculated %s but block contains %s" % (b2h(calculated_hash), b2h(self.header.merkle_root)))
        else:
            self.identities = identities

    def set_auths(self, auths):
        calculated_hash = merkle.merkle([auth.get_hash() for auth in auths], merkle.double_sha256)
        if calculated_hash != self.header.merkle_root_auths:
            raise block.BadMerkleRootError(
                "calculated %s but block contains %s" % (b2h(calculated_hash), b2h(self.header.merkle_root_auths)))
        else:
            self.auths = auths

    def get_hash(self):
        if hasattr(self, "hash"):
            return self.hash
        all = str(self.header.previous_block_hash) + str(self.header.creator_address) + str(
            self.header.merkle_root) + str(self.header.merkle_root_auths)
        self.hash = sha256(all.encode()).hexdigest()
        return self.hash

    def to_ligthweightL(self):
        b = Block(0, 0, 0, 0)
        b.header = self.header
        return b

    @classmethod
    def decode(self, file):
        block = pickle.loads(file)
        return block

    def encode(self):
        return pickle.dumps(self)


class BlockChain:
    CREATE_BLOCK_TABLE = "create table if not EXISTS  Blocks (Id_hash text primary key, height int not null, isTip boolean, file Binary not NULL, previous_block_hash text not NULL );"
    UPDATE_TIP_TO_0 = "update Blocks set isTip=0 where isTip=1"
    UPDATE="update Blocks set isTip=? where Id_hash=?"
    CREATE_INDEX = "create index if not EXISTS Block_hash on Blocks(Id_hash);"
    INSERT_BLOCK = "insert INTO Blocks VALUES (?,?,?,?,?)"
    GET_BLOCK = "select file FROM blocks where Id_hash=(?)"

    def __init__(self, path=None):
        self.path = path
        self.lock=Lock()
        if path is None:
            self.db = sqlite3.connect(p.curdir + "/BlockChain.sqlite3")
            self.path = p.curdir + "/BlockChain.sqlite3"
        else:
            self.db = sqlite3.connect(path)
        if os.path.exists("./trie"):
            file = io.open("./trie", 'rb')
            self.trie = Trie.Trie('$')
            id = file.read(11)
            while len(id) == 11:
                self.trie.insert(id.decode())
                id = file.read(11)
            file.close()
        else:
            self.db.cursor().execute("drop table if exists Blocks")
            io.open("./trie", 'xb')
            self.trie = Trie.Trie('$')
        self.tip2 = []
        self.init_db()
        self.db.close()

    def init_db(self):
        cursor = self.db.cursor()
        cursor.execute(self.CREATE_BLOCK_TABLE)
        cursor.execute(self.CREATE_INDEX)
        row = cursor.execute("select file from Blocks where isTip=1")
        file = row.fetchone()
        if file != None:
            self.tip = pickle.loads(file[0])
            # dict=serpent.loads(file[0])
            # self.tip=BlockChain.load_block(dict)
            count = cursor.execute("select count(*) from Blocks")
            self.tip2.append(self.get_block(self.tip.header.previous_block_hash))
            self.__dict__["height"] = count.fetchone()[0]
        else:
            self.__dict__["height"] = 0

    def __setattr__(self, key, value):
        if key == "height":
            raise Exception("height can not be modifided")
        else:
            return super.__setattr__(self, key, value)

    @classmethod
    def load_block(self, blockdict):
        block = Block(0, 0, 0, 0)
        header = BlockHeader(0, 0, 0, 0)
        header.__dict__ = blockdict["header"]
        block.__dict__ = blockdict
        block.header = header
        return block

    def contains(self, block):
        self.open_db()
        cursor = self.db.cursor()
        row = cursor.execute("select Id_hash from Blocks where Id_hash=?", [str(block.get_hash())])
        if row.fetchone() != None:
            return True
        else:
            return False

    def add_block(self, block):
        self.lock.acquire()
        self.db = sqlite3.connect(self.path)
        if hasattr(self, "tip") and block.header.previous_block_hash != self.tip.get_hash():
            if self.tip2[-1].get_hash() == block.header.previous_block_hash:
                self.tip2.append(block)
                if len(self.tip2) >= 3:
                    cursor = self.db.cursor()
                    self.tip2=[self.tip2[1],self.tip2[2]]
                    for block in self.tip2:
                        if hasattr(block, "identities"):
                            file = io.open("./trie", 'ab')
                            for identity in block.identities:
                                self.trie.insert(identity.ID)
                                file.write(identity.ID.encode())
                            file.close()
                        file = pickle.dumps(block)
                        cursor.execute(self.INSERT_BLOCK,
                                       [block.get_hash(), self.__dict__["height"], 0, file,
                                        block.header.previous_block_hash])
                    cursor.execute(self.UPDATE_TIP_TO_0)
                    cursor.execute(self.UPDATE, [1, self.tip2[-1].get_hash()])
                    tip2 = self.tip2[-2]
                    self.tip = self.tip2[-1]
                    self.tip2.clear()
                    self.tip2.append(tip2)
            self.lock.release()
            return
        if hasattr(self,"tip"):
            self.tip2.clear()
            tip = self.tip
            self.tip2.append(tip)
        self.tip = block

        if hasattr(block, "identities"):
            file = io.open("./trie", 'ab')
            for identity in block.identities:
                self.trie.insert(identity.ID)
                file.write(identity.ID.encode())
            file.close()
        file = pickle.dumps(block)
        cursor = self.db.cursor()
        id = block.get_hash()
        cursor.execute(self.UPDATE_TIP_TO_0)
        cursor.execute(self.INSERT_BLOCK, [id, self.__dict__["height"], 1, file, block.header.previous_block_hash])

        self.__dict__["height"] += 1
        self.db.commit()
        self.db.close()
        self.lock.release()

    def add_blocks(self, blocks):
        self.lock.acquire()
        self.open_db()
        for block in blocks:

            if hasattr(self, "tip") and block.header.previous_block_hash != self.tip.get_hash():
                pass
            self.tip = block
            if hasattr(block, "identities"):
                file = io.open("./trie", 'ab')
                for identity in block.identities:
                    self.trie.insert(identity.ID)
                    file.write(identity.ID.encode())
                file.close()
            file = pickle.dumps(block)
            cursor = self.db.cursor()
            id = block.get_hash()
            cursor.execute(self.INSERT_BLOCK,
                           [id, self.__dict__["height"], 1, file, str(block.header.previous_block_hash)])
            cursor.execute(self.UPDATE, [0, block.header.previous_block_hash])
            self.__dict__["height"] += 1
        self.db.commit()
        self.db.close()
        self.lock.release()

    def open_db(self):
        self.db = sqlite3.connect(self.path)

    def get_block(self, hash):
        self.lock.acquire()
        self.open_db()
        cursor = self.db.cursor()
        row = cursor.execute(self.GET_BLOCK, [str(hash)])
        file = row.fetchone()
        if file is None:
            print("no existe el bloque " + hash)
            self.db.close()
            self.lock.release()
            return
        block = pickle.loads(file[0])
        # serializer=serpent.Serializer()
        # blockdict=serpent.loads(file[0])
        # block=BlockChain.load_block(blockdict)
        self.db.close()
        self.lock.release()
        return block

    def get_hash_from(self, start):
        self.lock.acquire()
        self.open_db()
        cursor = self.db.cursor()
        rows = cursor.execute("select Id_hash from Blocks where height>=" + str(start) + " limit 500")
        hashs = [row[0] for row in rows.fetchall()]
        self.db.close()
        self.lock.release()
        return hashs