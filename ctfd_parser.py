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
import io
import sys
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
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

    def get_json(self:object, url:str):
        rdata = None
        r = self.session.get(self.target + url)
        if r.status_code == 200:
            rdata = json.loads(r.content)
        else:
            print(f'HTTP STATUS: {r.status_code}', file=sys.stderr)
            print(r.content.decode('UTF-8'), file=sys.stderr)
            raise RuntimeError('Something went wrong :(')
        return rdata

    def write_json(self:object, folder:str, filename:str, data):
        with io.open(folder + os.path.sep + filename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(data, ensure_ascii=False))

    def dump_challenges(self:object, folder:str) -> None:
        challenges = self.get_json(f'/api/v1/challenges')['data']
        self.write_json(folder, 'challenges.json', challenges)

    def dump_teams(self:object, folder:str) -> list:
        next_page = 1
        teams = []
        while next_page != None:
            rdata = self.get_json(f'/api/v1/teams?page={next_page}')
            next_page = rdata['meta']['pagination']['next']
            teams += rdata['data']

        self.write_json(folder, 'teams.json', teams)
        return teams

    def dump_users(self:object, folder:str) -> list:
        next_page = 1
        users = []
        while next_page != None:
            rdata = self.get_json(f'/api/v1/users?page={next_page}')
            next_page = rdata['meta']['pagination']['next']
            users += rdata['data']

        self.write_json(folder, 'users.json', users)
        return users

    def dump_scoreboard(self:object, folder:str) -> None:
        scoreboard = self.get_json(f'/api/v1/scoreboard')['data']
        self.write_json(folder, 'scoreboard.json', scoreboard)
        scoreboard_detailed = self.get_json(f'/api/v1/scoreboard/top/1000000')['data']
        self.write_json(folder, 'scoreboard_detailed.json', scoreboard_detailed)
        scoreboard_split = self.get_json(f'/api/v1/split_scores/top/1000000')['data']
        self.write_json(folder, 'scoreboard_split.json', scoreboard_split)

    def dump_team_solves(self:object, folder:str, teams:list) -> None:
        team_solves = {}
        for team in teams:
            team_solves[team['id']] = self.get_json(f'/api/v1/teams/{team['id']}/solves')['data']

        self.write_json(folder, 'team_solves.json', team_solves)

    def invoke_command(self:object, threads:int, dump:bool) -> None:
        if dump:
            folder = os.path.sep.join([self.basedir, 'Data'])
            if not os.path.exists(folder):
                os.makedirs(folder)

            self.dump_challenges(folder)
            teams = self.dump_teams(folder)
            users = self.dump_users(folder)
            try:
                self.dump_scoreboard(folder)
            except RuntimeError as e:
                print(e, file=sys.stderr)

            try:
                self.dump_team_solves(folder, teams)
            except RuntimeError as e:
                print(e, file=sys.stderr)
        else:
            self.get_challenges(threads)


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
    parser.add_argument("-u", "--user", required=False, help="Username to login to CTFd")
    parser.add_argument("-p", "--password", required=False, help="Password to login to CTFd (default: interactive)")
    parser.add_argument("-T", "--threads", required=False, default=8, type=int, help="Number of threads (default: 8)")
    parser.add_argument("-D", "--dump", required=False, action="store_true", help="Dump info like users, teams and scoreboard (default: False)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-I", "--initfile", default=False, action="store_true", help="Init default files. (solve.py / writeup.md)")
    args = parser.parse_args()
    
    config = {}
    config['url'] = args.target
    config['user'] = args.user
    config['password'] = args.password
    config['verbose'] = args.verbose
    config['dump'] = args.dump
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

    if not config.get("dump"):
        config["dump"] = False
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
    dump = config['dump']
    initfile = config['initfile']
    
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    target = target.rstrip('/')
    
    if config['verbose']:
        print(f"[>] Target URL: {target}")
        
    if output is None:
        output = os.path.join(ROOT, "Challenges")
    if user is not None and password is None:
        password = getpass("Password: ")

    cp = CTFdParser(target, user, password, output, initfile)
    if(user is not None):
        if cp.login():
            cp.invoke_command(threads=threads, dump=dump)
        else:
            print("[-] Login failed")
            return -1
    cp.invoke_command(threads=threads, dump=dump)
    return 0

if __name__ == '__main__':
    main()
    
