import httpx
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
import binascii
import json

"""
TODO: enter = show info (tries, current hash on thread #, )
TODO: numba or cpu processing
TODO: sha1-512, ntlm, etc cracking
TODO: finish online endpoint cracking
"""

class onlineCrack:
    def __init__(self, useSession=True):
        if useSession:
            self.session = httpx.Client()
        else:
            self.session = None

    def endpoint(self, wordlist, *args, requestType='GET', success=200, verbose=True, **kwargs):
        """
        requestType = GET, HEAD, or POST (defaults to get)
        
        if success kwarg is an integer, it will check the request status code
        else if success kwarg is a string, it will check the request response
        
        if it matches success kwarg, return a tuple of items

        replace password key with &&&&, it will replace it automatically

        example: bruteforce.onlineCrack(useSession=True).endpoint([str(x) for x in string.ascii_letters], "http://127.0.0.1:5000", requestType="POST", success=200, json={"password": "&&&&"})
        """

        if self.session is None:
            manager = httpx
        else:
            manager = self.session

        try:
            kwargsData = kwargs["data"] # backups
        except KeyError:
            kwargsData = None

        try:
            kwargsJson = kwargs["json"] # backups
        except KeyError:
            kwargsJson = None


        for pwd in wordlist:

            if kwargsData is not None:
                if "&&&&" in kwargsData:
                    kwargs["data"] = kwargsData.replace("&&&&", pwd)
            if kwargsJson is not None:
                for key in kwargsJson:
                    if "&&&&" in kwargsJson[key]:
                        kwargs["json"][key] = kwargsJson[key].replace("&&&&", pwd)

            if requestType.upper() == 'GET': request = manager.get(*args, **kwargs)
            elif requestType.upper() == 'POST': request = manager.post(*args, **kwargs)
            elif requestType.upper() == 'HEAD': request = manager.head(*args, **kwargs)
            else: # default to post
                request = manager.post(*args, **kwargs)

            if type(success) == int:
                if request.status_code == success:
                    return (pwd, request)
                else:
                    if verbose: print("[X] {}:{}:{}".format(request.url, pwd, request.status_code))

            elif type(success) == str:
                if success in request.text:
                    return (pwd, request)
                else:
                    if verbose: print("[X] {}:{}:{}".format(request.url, pwd, request.status_code))



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
            with ThreadPoolExecutor(max_threads=threads) as pool:
                # x is chunk
                for x in a: pool.submit(hash.base, target, x, function)
        except KeyboardInterrupt:
            system.finished = True
            print("ctrl+c")
            return False

    def runALT(function:object, wordlist:list, target:str, threads=5):
        a = system.chunk(wordlist, round(len(wordlist) / threads))

        threadlist = []

        try:
            # TODO: stop using thread pool executer
            with ThreadPoolExecutor(max_threads=threads) as pool:
                # x is chunk
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

    def md4(target:str, wordlist:list):
        for i in wordlist:
            if system.finished: return
            encrypted = binascii.hexlify(hashlib.new('md4', i.encode('utf-16le')).digest())

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

def sha384(args:list):
    try:
        target = args[1]
        wordlist = args[2]
        threads = args[3]
    except:
        print("sha384 (target) (wordlist file) (threads)")
        return

    system.run(hashlib.sha384, wordlist, target, threads=int(threads))

def sha512(args:list):
    try:
        target = args[1]
        wordlist = args[2]
        threads = args[3]
    except:
        print("sha512 (target) (wordlist file) (threads)")
        return

    system.run(hashlib.sha512, wordlist, target, threads=int(threads))

def md4(args:list):
    try:
        target = args[1]
        wordlist = args[2]
        threads = args[3]
    except:
        print("md4 (target) (wordlist file) (threads)")
        return

    system.runALT(hash.md4, wordlist, target, threads=int(threads))

def onlineBrute(args:list):
    threadList = []

    try:
        url = args[1]
        _json = args[2]
        requestType = args[3]
        wordlist = args[4]
        success = args[5]
        threads = args[6]
    except:
        print("onlineBrute (url) (json) (wordlist file)")
        return

    try:
        success = int(success) # check if it's status code or not
    except:
        pass
    
    
    for l in system.chunk(open(wordlist, "r").read().split(), int(threads)):
        threadList.append(threading.Thread(target=onlineCrack(useSession=True).endpoint, args=(l, url,), kwargs={"requestType":requestType.upper(), "success":success, "json":json.loads(_json)}))

    for thread in threadList:
        thread.start()

    for thread in threadList:
        thread.join()

    #onlineCrack(useSession=True).endpoint(l, url, requestType=requestType.upper(), success=200, json=json.loads(_json))

def functions():
    return {
            "sha1": "sha1 crack; sha1 (target) (wordlist file) (threads)",
            "sha224": "sha224 crack; sha224 (target) (wordlist file) (threads)",
            "sha384": "sha384 crack; sha384 (target) (wordlist file) (threads)",
            "sha512": "sha512 crack; sha512 (target) (wordlist file) (threads)",
            "md4": "md4 crack; md4 (target) (wordlist file) (threads)",
            "onlineBrute": "spam an http endpoint with a bunch of login requests, until we get our desired response; onlineBrute (url) (json data with password replaced with &&&& and no spaces) (GET, HEAD, or POST) (wordlist file) (success string or int) (threads)"
        }