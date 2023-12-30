#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ctfd_parser.py
# Author             : Podalirius (@podalirius_)
# Last Update        : 28 December 2023

import argparse
import json
import requests
import re
import os
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
import json
import shutil

ROOT = os.path.dirname(__file__)

FILE_MAX_SIZE_MO = 100 

def os_filename_sanitize(s:str) -> str:
    filtred = ['/', ';', ' ', ':']
    for char in filtred:
        s = s.replace(char, '_')
    s = re.sub('__*', '_', s)
    return s

class CTFdParser(object):

    def __init__(self:object, target:str, login:str,password:str,basedir:str="Challenges",initfile:str=False) -> None:
        super(CTFdParser, self).__init__()
        self.target = target
        self.basedir = basedir
        self.initfile = initfile
        self.challenges = {}
        self.credentials = {
            'user': login,
            'password': password
        }
        self.session = requests.Session()
        
        self.psolve = os.path.join(ROOT, "template", "solve.py")
        self.pwu = os.path.join(ROOT, "template", "writeup.md")

    def login(self:object) -> bool:
        r = self.session.get(self.target + '/login')
        matched = re.search(
            b"""('csrfNonce':[ \t]+"([a-f0-9A-F]+))""", r.content)
        nonce = ""
        if matched is not None:
            nonce = matched.groups()[1]
        r = self.session.post(
            self.target + '/login',
            data={
                'name': self.credentials['user'],
                'password': self.credentials['password'],
                '_submit': 'Submit',
                'nonce': nonce.decode('UTF-8')
            }
        )

        return 'Your username or password is incorrect' not in r.text

    def get_challenges(self:object, threads:int=8) -> dict:
        r = self.session.get(self.target + "/api/v1/challenges")

        if r.status_code == 200:
            json_challs = json.loads(r.content)
            if json_challs is not None:
                if json_challs['success']:
                    self.challenges = json_challs['data']
                    self._parse(threads=threads)
                else:
                    print("[warn] An error occurred while requesting /api/v1/challenges")
            return json_challs
        else:
            return None

    def _parse(self:object, threads:int=8) -> None:
        # Categories
        self.categories = [chall["category"] for chall in self.challenges]
        self.categories = sorted(list(set(self.categories)))

        print(f'\x1b[1m[\x1b[93m+\x1b[0m\x1b[1m]\x1b[0m Found {len(self.categories)} categories !')

        # Parsing challenges
        for category in self.categories:
            print(f"\x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m Parsing challenges of category : \x1b[95m{category}\x1b[0m")

            challs_of_category = [c for c in self.challenges if c['category'] == category]

            # Waits for all the threads to be completed
            with ThreadPoolExecutor(max_workers=min(threads, len(challs_of_category))) as tp:
                for challenge in challs_of_category:
                    tp.submit(self.dump_challenge, category, challenge)

    def dump_challenge(self:object, category:str, challenge:dict)->None:
        if challenge["solved_by_me"]:
            print(f"   \x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m \x1b[1;92m✅\x1b[0m \x1b[96m{challenge['name']}\x1b[0m")
        else:
            print(f"   \x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m \x1b[1;91m❌\x1b[0m \x1b[96m{challenge['name']}\x1b[0m")

        folder = os.path.sep.join([self.basedir, os_filename_sanitize(category), os_filename_sanitize(challenge["name"])])
        if not os.path.exists(folder):
            os.makedirs(folder)
            
        #template files
        
        if self.initfile:
            shutil.copy(self.psolve, folder)
            shutil.copy(self.pwu, folder)

        # Readme.md
        f = open(folder + os.path.sep + "README.md", 'w')
        f.write(f"# {challenge['name']}\n\n")
        f.write(f"**Category** : {challenge['category']}\n")
        f.write(f"**Points** : {challenge['value']}\n\n")

        chall_json = self.get_challenge_by_id(challenge["id"])["data"]
        f.write(f"{chall_json['description']}\n\n")

        connection_info = chall_json["connection_info"]
        if connection_info is not None:
            if len(connection_info) != 0:
                f.write(f"{connection_info}\n\n")

        # Get challenge files
        if len(chall_json["files"]) != 0:
            f.write("## Files : \n")
            for file_url in chall_json["files"]:
                if "?" in file_url:
                    filename = os.path.basename(file_url.split('?')[0])
                else:
                    filename = os.path.basename(file_url)

                r = self.session.head(self.target + file_url, allow_redirects=True)
                if "Content-Length" in r.headers.keys():
                    size = int(r.headers["Content-Length"])
                    if size < (FILE_MAX_SIZE_MO * 1024 * 1024):  # 50 Mb
                        r = self.session.get(self.target + file_url, stream=True)
                        with open(folder + os.path.sep + filename, "wb") as fdl:
                            for chunk in r.iter_content(chunk_size=16 * 1024):
                                fdl.write(chunk)
                    else:
                        print(f"Not Downloading {filename}, filesize too big.")

                else:
                    r = self.session.get(self.target + file_url, stream=True)
                    with open(folder + os.path.sep + filename, "wb") as fdl:
                        for chunk in r.iter_content(chunk_size=16 * 1024):
                            fdl.write(chunk)

                f.write(f" - [{filename}](./{filename})\n")

        f.write("\n\n")
        f.close()

    def get_challenge_by_id(self:object, chall_id:int) -> dict:
        """Documentation for get_challenge_by_id"""
        r = self.session.get(self.target + f'/api/v1/challenges/{chall_id}')
        json_chall = None
        if r.status_code == 200:
            json_chall = json.loads(r.content)
        return json_chall


def header() -> None:
    print(r"""       _____ _______ ______  _   _____
      / ____|__   __|  ____|| | |  __ \
     | |       | |  | |__ __| | | |__) |_ _ _ __ ___  ___ _ __
     | |       | |  |  __/ _` | |  ___/ _` | '__/ __|/ _ \ '__|    v1.1
     | |____   | |  | | | (_| | | |  | (_| | |  \__ \  __/ |
      \_____|  |_|  |_|  \__,_| |_|   \__,_|_|  |___/\___|_|       @podalirius_
""")

def parseArgs() -> dict:
    header()
    parser = argparse.ArgumentParser(description="CTFdParser")
    parser.add_argument("-t", "--target", required=True, help="CTFd target (domain or ip)")
    parser.add_argument("-o", "--output", required=False, help="Output directory")
    parser.add_argument("-u", "--user", required=True, help="Username to login to CTFd")
    parser.add_argument("-p", "--password", required=False, help="Password to login to CTFd (default: interactive)")
    parser.add_argument("-T", "--threads", required=False, default=8, type=int, help="Number of threads (default: 8)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-I", "--initfile", default=False, action="store_true", help="Init default files. (solve.py / writeup.md)")
    args = parser.parse_args()
    
    config = {}
    config['url'] = args.target
    config['user'] = args.user
    config['password'] = args.password
    config['verbose'] = args.verbose
    config['threads'] = args.threads
    config["output"] = args.output
    config['initfile'] = args.initfile
    
    return config

def checkConfig() -> dict:
    
    pconfig = os.path.join(ROOT, "config.json")
    if not os.path.exists(pconfig):
        return None
    
    with open(pconfig,"rb") as f:
        dconfig = f.read()
        f.close()
        
    if not dconfig:
        return None
         
    config = json.loads(dconfig)
      
    if not config.get("url") or not config.get("user") or not config.get("password"):
        return None
    
    if not config.get("verbose"):
        config["verbose"] = False
    if not config.get("threads"):
        config["threads"] = 8
    if not config.get("output"):
        config["output"] = None
    if not config.get("initfile"):
        config["initfile"] = None
            
    return config

def main() -> int:
    config = checkConfig()
    args = None
    if not config:
        config = parseArgs()    
    
    target = config['url']
    output = config['output']
    password = config['password']
    user = config['user']
    threads = config['threads']
    initfile = config['initfile']
    
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    target = target.rstrip('/')
    
    if config['verbose']:
        print(f"[>] Target URL: {target}")
        
    if output is None:
        output = os.path.join(ROOT, "Challenges")
    if password is None:
        password = getpass("Password: ")

    cp = CTFdParser(target, user, password, output, initfile)
    if cp.login():
        cp.get_challenges(threads=threads)
    else:
        print("[-] Login failed")
        return -1
    
    return 0

if __name__ == '__main__':
    main()
    
