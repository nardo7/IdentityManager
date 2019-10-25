import FunctionNetwork as Net
import BlockChain
import Wallet
from pycoin import merkle
bc=BlockChain.BlockChain()
#bc.add_block(BlockChain.Block("0",1,0,0))
w=Wallet.Wallet()
w.create_identity("ale","nardo","95042429425","24/4/1995","m")
b=BlockChain.Block("0",merkle.merkle([w.my_identity.get_hash()]),"0","0")
b.set_identities([w.my_identity])
bc.add_block(b)

bc.add_block(BlockChain.Block(bc.tip.get_hash(),1,0,0))
a=Net.node(blockChain=bc,ip="127.0.0.1",port=Net.PORT,is_seed=1)