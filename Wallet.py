import random
from pycoin import key
import BlockChain
import io
import os
import pickle


class Wallet:
    def __init__(self):
        if os.path.exists("./Wallet.dat"):
            f = io.open("./Wallet.dat", mode='rb')
            if len(f.read(1))>0:
               print('leer')
               f.seek(0)
               wallet = pickle.load(f)
               self.my_identity = wallet.my_identity
               self.my_key = wallet.my_key
               self.signature = wallet.my_identity.signature
               f.close()
        else:
            self.my_key = key.Key(random.randrange(1.158 * (10 ** 77)))
        """if os.path.exists("./private_key.dat"):
			f=io.open("private_key.dat",mode='rb')
			print('leer')
			self.my_key=pickle.load(f)
			f.close()
		else:
			print('escribir')
			f=io.open("./private_key.dat",mode='xb')
			self.my_key = key.Key(random.randrange(1.158*(10**77)))
			p=pickle.Pickler(f)
			p.bin=True
			p.dump(self.my_key)
			f.close()"""
        print(self.my_key)

    def create_identity(self, name, last_name, ID, birth_date, sex):
        self.my_identity = BlockChain.Identity(name, last_name, ID, birth_date, sex, self.my_key.public_pair())
        self.my_identity.signature = self.sign(self.my_identity.get_hash())
        if not os.path.exists("./Wallet"):
            f = io.open("./Wallet.dat", 'xb')
        else:
            f=f = io.open("./Wallet.dat", 'wb')
        pickle.dump(self, f)
        f.close()

    def sign(self, h):
        return self.my_key.sign(h)


def create_identity_from_interface(wallet):
    print('Enter name:')
    name = input()
    print('Enter last name:')
    last_name = input()
    print('Enter ID:')
    ID = input()
    print('Enter BirthDate:')
    birth_date = input()
    print('Enter sex:')
    sex = input()
    wallet.create_identity(name, last_name, ID, birth_date, sex)


def randseq(seq, len):
    res = ''
    for i in range(0, len):
        res = res + random.choice(seq)
    return res


def generate_random_wallet_with_identity_inside():
    name = randseq('qwertyuiopasdfghjklzxcvbnm', 10)
    last_name = randseq('qwertyuiopasdfghjklzxcvbnm', 10)
    ID = randseq('1234567890', 11)
    birth_date = randseq('1234567890', 6)
    sex = randseq('MF', 1)
    wallet = Wallet()
    wallet.create_identity(name, last_name, ID, birth_date, sex)
    wallet.my_identity.signature = wallet.sign(wallet.my_identity.get_hash())
    return wallet

# w = generate_random_wallet_with_identity_inside()













