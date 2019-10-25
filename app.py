import os, pickle,io,BlockChain,FunctionNetwork,Authorization, sys, signal
import threading
from time import sleep
import Wallet

trusted_parties=[("10.6.123.65",FunctionNetwork.PORT),("10.6.123.65",FunctionNetwork.PORT-1),("10.6.123.65",FunctionNetwork.PORT-2)]
ip="10.6.123.65"
port=FunctionNetwork.PORT
kill=False
bc=BlockChain.BlockChain("./BlockChain.sqlite3")
trie=bc.trie

addrSeed=("10.6.123.65",FunctionNetwork.PORT)


if os.path.exists("./netData")==False:
    file_net=io.open("./netData",'xb')
    seed=0
    full=0
    print("desea ser un full node s/n: ")
    s=input()
    if s == "s":
        full=1
    elif s=="n":
        full=0
    else:
        print("\n argumento incorrecto")
        exit(0)


    net=FunctionNetwork.node(bc,ip=ip,port=port,is_seed=seed,full_node=full,addr_seed_node=addrSeed)

else:

    file_net=io.open("./netData",'rb')
    if len(file_net.read(1))>0:
        file_net.seek(0)
        net=pickle.load(file_net)
        net.BlockChain=bc
        net.init_net([addrSeed])
        file_net.close()
    else:
        net=FunctionNetwork.node(bc,ip=ip,port=port,is_seed=0,full_node=1,addr_seed_node=addrSeed)
auth=Authorization.Authorization(bc,trie)
print("\ndesea crear una identidad y registrarla? s/n")
s=input()
if s == "s":
    wallet=Wallet.Wallet()
    Wallet.create_identity_from_interface(wallet)
    net.send_id(wallet.my_identity)

index=-2
if (net.ip,net.port) in trusted_parties:
    index=trusted_parties.index((net.ip,net.port))

def verification_blocks(net, auth,bc):
    i = 0
    print("verifiying block")
    while 1:
        sleep(3)
        if kill:
            exit(0)

        net.lock_sync.acquire()
        if len(net.currentBlock) > 0:
            print("here is a block")
            for block in net.currentBlock:
                if bc.contains(block) == False:
                    if auth.validate_block(block, trusted_parties):
                        print("block was succesfull validated")
                        bc.add_block(block)
                        print("block is in blockchain.... sending it to net")
                        net.send_block_to_net(block)
                        i = trusted_parties.index(block.header.creator_address)
                        if block.header.creator_address not in net.nodes:
                            net.nodes.append(block.header.creator_address)
                        i += 1
                        if i >= len(trusted_parties):
                            i = 0
                    else:
                        print("block was not succesfull validated")
            net.currentBlock.clear()
        net.lock_sync.release()
        if len(net.nodes) == 0 and net.is_seed==False:
             print("nodo aislado, cerrando")
             os.kill(os.getpid(), signal.SIGKILL)
        if index >= 0 and index==i:
            AuthNode(net, auth, bc, i)
            i+=1
            if i >= len(trusted_parties):
                i = 0
        if trusted_parties[i] not in net.nodes:
            i+=1
            if i >= len(trusted_parties):
                i = 0


def verification_identities(net,auth):
    while 1:
        if kill:
            exit(0)
        for ident in net.identity_pool.values():
            print("validating indentity " + ident.__str__() + "...")
            if ident.ID not in auth.identity_pool:
                if auth.validate(ident):
                    print("identity was validated... sending it to net")

                    net.send_id(ident)
            else:
                print("identity unvalidated")
        net.identity_pool.clear()
        sleep(1)

def create_block(net,auth,bc):
    print("creating block...")
    block=auth.generate_block(bc.tip.get_hash(),(net.ip,net.port))
    print("succesfull created... sending it to net")

    net.send_block_to_net(block)
    if len(net.nodes) == 0 and net.is_seed == False:
        print("nodo aislado, cerrando")
        os.kill(os.getpid(), signal.SIGKILL)
    bc.add_block(block)
ths=[]
ths.append(threading.Thread(target=verification_blocks,args=(net,auth,bc)))

ths.append(threading.Thread(target=verification_identities,args=(net,auth)))
ths[0].start()
ths[1].start()

def mantenimiento():
    while not kill:
        for i in range(0,1):
            if not ths[i].is_alive():
                ths[i]=threading.Thread(target=verification_blocks,args=(net,auth,bc))
                ths[i].start()
        sleep(3)

threading.Thread(target=mantenimiento).start()

def AuthNode(net,auth,bc,i):
       # if i==index:
            sleep(10)
            create_block(net,auth,bc)

while 1:
    data=input()
    if data=="close":
        net.lock=None
        net.lock_sync=None
        net.neighbors.clear()
        file_net=io.open("./netData",'wb')
        net.sock_listening=None
        pickle.dump(net,file_net)
        file_net.close()
        kill=True
        os.kill(os.getpid(),signal.SIGKILL)

