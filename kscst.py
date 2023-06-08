from getpass import getpass
from core import ZK, ZKSignature, ZKParameters, ZKData, ZKProof
from queue import Queue
from threading import Thread


def client(iq: Queue, oq: Queue):
    client_zk = ZK.new(curve_name="secp256k1", hash_alg="sha3_256")

    signature = client_zk.create_signature(getpass("Enter Password: "))
    oq.put(signature.to_json())
    print(signature.to_json())

    token = iq.get()

    proof = client_zk.sign(getpass("Enter Password Again: "), token).to_json()

    oq.put(proof)
    print(proof)
    print("Success!" if iq.get() else "Failure!")


def server(iq: Queue, oq: Queue):
    server_password = "SecretServerPassword"
    server_zk = ZK.new(curve_name="secp384r1", hash_alg="sha3_512")
    server_signature: ZKSignature = server_zk.create_signature("SecureServerPassword")

    sig = iq.get()
    client_signature = ZKSignature.from_json(sig)
    client_zk = ZK(client_signature.params)

    token = server_zk.sign("SecureServerPassword", client_zk.token())
    oq.put(token.to_json())

    proof = ZKData.from_json(iq.get())
    token = ZKData.from_json(proof.data)

    if not server_zk.verify(token, server_signature):
        oq.put(False)
    else:
        oq.put(client_zk.verify(proof, client_signature, data=token))


def main():
    q1, q2 = Queue(), Queue()
    threads = [
        Thread(target=client, args=(q1, q2)),
        Thread(target=server, args=(q2, q1)),
    ]
    for func in [Thread.start, Thread.join]:
        for thread in threads:
            func(thread)


if __name__ == "__main__":
    main()