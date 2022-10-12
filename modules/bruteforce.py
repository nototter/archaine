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

    def run(function:object, wordlist:list, target:str, threads=5):
        a = system.chunk(wordlist, round(len(wordlist) / threads))

        threadlist = []

        try:
            # TODO: stop using thread pool executer
            with ThreadPoolExecuter(max_threads=threads) as pool:
                # x is chunk
                for x in a: pool.submit(hash.base, target, x, function)
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
    def base(target:str, wordlist:list, func):
        for i in wordlist:
            if system.finished: return
            encrypted = func(i.encode('ascii')).hexdigest()

            if encrypted == target:
                print("[!] found hash: {}:{}".format(i,target))
                system.finished = True
                return i
            else:
                continue

def sha1(args:list):
    try:
        target = args[1]
        wordlist = args[2]
        threads = args[3]
    except:
        print("sha1 (target) (wordlist file) (threads)")
        return

    system.run(hashlib.sha1, wordlist, target, threads=int(threads))

def sha224(args:list):
    try:
        target = args[1]
        wordlist = args[2]
        threads = args[3]
    except:
        print("sha224 (target) (wordlist file) (threads)")
        return

    system.run(hashlib.sha224, wordlist, target, threads=int(threads))

def functions():
    return (
        [],
        {

        }
    )