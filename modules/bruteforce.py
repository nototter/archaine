import httpx
import hashlib
import threading
from concurrent.futures import ThreadPoolExecuter

"""
TODO: enter = show info (tries, current hash on thread #, )
TODO: numba or cpu processing
TODO: sha1-512, ntlm, etc cracking
TODO: finish online endpoint cracking
"""

class online:
    def endpoint(url, headers, data, json):
        """
        temp
        """

class system:
    hash = []
    finished = False
    hash_amount = 32
    threads = 5

    def autothread(target:object, threads:int, args=(), wait=False, daemon=True):
        thread_List = []
        
        for x in range(threads):
            thread_List.append(threading.Thread(target=target, args=args, daemon=daemon))

        for thread in thread_List:
            thread.start()

        if wait:
            for thread in thread_List:
                thread.join()

        return thread_List

    def hash_crack(function:object, wordlist:list, target:str, threads=5):
        a = system.chunk(wordlist, round(len(wordlist) / threads))

        threadlist = []

        try:
            with ThreadPoolExecuter(max_threads=threads) as pool:
                for x in a: pool.submit(function, target, x)
        except KeyboardInterrupt:
            system.finished = True
            print("ctrl+c")
            return False
        

    def chunk(lst:list, n:int):
        full = []
        for i in range(0, len(lst), n):
            full.append(lst[i:i + n])
        return full

    def list_to_dict(lst:list, value=1):
        """
        turning a list to a dictionary (absurdly) makes it faster to iterate over
        """
        d = {}
        for x in lst:
            d[x] = value
        return d
        

class hash:
    def sha1(target:str, wordlist:list):
        """
        SHA1 cracking
        """

    def sha224(target:str, wordlist:list):
        """
        SHA224 cracking
        """

        stdout_hash = ''.join([target[x] for x in range(system.hash_amount)]) + "..." #minimize characters used
        
        for hash in system.list_to_dict(wordlist):
            if system.finished: return
            encrypted = hashlib.sha224(hash.encode('ascii')).hexdigest() #encrypt

            if str(encrypted) == target: # if the newly encrypted hash matches our target
                print(f"[!] found hash: {hash} [{encrypted}]")
                system.finished = True
                return hash
            else:
                print(f"[X] {hash} != {stdout_hash}")
                pass

    def sha256(target:str, wordlist:list):
        """
        SHA256 cracking
        """
        
        stdout_hash = ''.join([target[x] for x in range(system.hash_amount)]) + "..." # minimized version of the hash to reduce amount of screen taken
        
        for hash in system.list_to_dict(wordlist):
            if system.finished: return
            encrypted = hashlib.sha256(hash.encode('ascii')).hexdigest() #encrypt

            if str(encrypted) == target:
                if system.finished: return
                print(f"[!] found hash: {hash} [{encrypted}]")
                system.finished = True
                return hash
            else:
                if system.finished: return
                print(f"[X] {hash} != {stdout_hash}")
                pass
    
    def sha384(target:str, wordlist:list):
        """
        SHA384 cracking
        """

    def sha512(target:str, wordlist:list):
        """
        SHA512 cracking
        """



def functions():
    return (
        [],
        {

        }
    )