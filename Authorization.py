import BlockChain
from pycoin import ecdsa, merkle
from pycoin.encoding import from_bytes_32
from pycoin.tx.script.der import sigencode_der, sigdecode_der


class Authorization:
    def __init__(self, blockchain, trie):
        self.blockchain = blockchain
        self.trie = trie
        self.phantom_identities = {}
        self.identity_pool = {}

    def validate(self, identity):
        # if identity.ID not in self.identity_pool:

        if self.trie.contains(identity.ID) == True:
            print("identity is already in the blockchain")
            # self.phantom_identities[identity.public_key]=identity
            return False
        if type(identity.name) != str or len(identity.name) > 50:
            print("identity is bad")
            return False
        if type(identity.last_name) != str or len(identity.last_name) > 50:
            print("identity is bad")
            return False
        if type(identity.ID) != str:
            print("identity is bad")
            return False
        if type(identity.date) != BlockChain.Date:
            print("identity is bad")
            return False
        if identity.sex > 1 or identity.sex < 0:
            print("identity is bad")
            return False
        if hasattr(identity, "signature") == False:
            print("identity has not signature")
            return False
        sign = sigdecode_der(identity.signature)
        val = from_bytes_32(identity.get_hash())
        if ecdsa.verify(ecdsa.generator_secp256k1, identity.public_key, val, sign) == False:
            print("identity' signature is incorrect")
            return False

        self.identity_pool[identity.ID] = identity
        return True

    def validate_block(self, block, trusted_parties):
        if type(block.header.creator_address) is not tuple or len(block.header.creator_address) < 1 or len(
                block.header.creator_address) > 2:
            return False
        if block.header.creator_address not in trusted_parties:
            return False
        if hasattr(block, "identities"):
            for identity in block.identities:
                if self.validate(identity) == False:
                    return False
                    # if self.phantom_identities.get(identity.public_key):
                    #   self.phantom_identities.__delitem__((identity.public_key,identity))
                self.identity_pool.pop(identity.ID)
                self.trie.insert(identity.ID)
        return True

    def generate_block(self, previous_block_hash, creator_address):
        hash = []
        identities = []
        i = 0
        for value in self.identity_pool.values():
            if i == 1000:
                break
            hash.append(value.get_hash())
            identities.append(value)
            self.trie.insert(value.ID)
            i += 1
        if len(identities) > 0:
            block = BlockChain.Block(previous_block_hash, merkle.merkle(hash),
                                     "0", creator_address)
            block.set_identities(identities)
        else:
            block = BlockChain.Block(previous_block_hash, merkle.merkle("0"), "0", creator_address)
        if len(self.identity_pool) < 1000:
            self.identity_pool.clear()
        else:
            for ident in identities:
                self.identity_pool.pop(ident.ID)

        return block
