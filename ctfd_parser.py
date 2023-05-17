#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ctfd_parser.py
# Author             : Podalirius (@podalirius_)
# Date created       : 26 Mar 2022

import argparse
import json
import requests
import re
import os
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass


def os_filename_sanitize(s):
    filtred = ['/', ';', ' ', ':']
    for char in filtred:
        s = s.replace(char, '_')
    s = re.sub('__*', '_', s)
    return s


class CTFdParser(object):

    max_size_in_mo = 50

    def __init__(self, target, login, password, basedir="Challenges"):
        super(CTFdParser, self).__init__()
        self.target = target
        self.basedir = basedir
        self.challenges = {}
        self.credentials = {
            'user': login,
            'password': password
        }
        self.session = requests.Session()

    def login(self):
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

    def get_challenges(self, threads=8):
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

    def _parse(self, threads=8):
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
        return None

    def dump_challenge(self, category, challenge):
        if challenge["solved_by_me"]:
            print(f"   \x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m \x1b[1;92m✅\x1b[0m \x1b[96m{challenge['name']}\x1b[0m")
        else:
            print(f"   \x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m \x1b[1;91m❌\x1b[0m \x1b[96m{challenge['name']}\x1b[0m")

        folder = os.path.sep.join([self.basedir, os_filename_sanitize(category), os_filename_sanitize(challenge["name"])])
        if not os.path.exists(folder):
            os.makedirs(folder)

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
                    if size < (self.max_size_in_mo * 1024 * 1024):  # 50 Mb
                        r = self.session.get(self.target + file_url, stream=True)
                        with open(folder + os.path.sep + filename, "wb") as fdl:
                            for chunk in r.iter_content(chunk_size=16 * 1024):
                                fdl.write(chunk)
                    else:
                        # Size too big
                        pass

                else:
                    r = self.session.get(self.target + file_url, stream=True)
                    with open(folder + os.path.sep + filename, "wb") as fdl:
                        for chunk in r.iter_content(chunk_size=16 * 1024):
                            fdl.write(chunk)

                f.write(f" - [{filename}](./{filename})\n")

        f.write("\n\n")
        f.close()

    def get_challenge_by_id(self, chall_id: int):
        """Documentation for get_challenge_by_id"""
        r = self.session.get(self.target + f'/api/v1/challenges/{chall_id}')
        json_chall = None
        if r.status_code == 200:
            json_chall = json.loads(r.content)
        return json_chall


def header():
    print(r"""       _____ _______ ______  _   _____
      / ____|__   __|  ____|| | |  __ \
     | |       | |  | |__ __| | | |__) |_ _ _ __ ___  ___ _ __
     | |       | |  |  __/ _` | |  ___/ _` | '__/ __|/ _ \ '__|    v1.1
     | |____   | |  | | | (_| | | |  | (_| | |  \__ \  __/ |
      \_____|  |_|  |_|  \__,_| |_|   \__,_|_|  |___/\___|_|       @podalirius_
""")
    return


def parseArgs():
    header()
    parser = argparse.ArgumentParser(description="CTFdParser")
    parser.add_argument("-t", "--target", required=True, help="CTFd target (domain or ip)")
    parser.add_argument("-o", "--output", required=False, help="Output directory")
    parser.add_argument("-u", "--user", required=True, help="Username to login to CTFd")
    parser.add_argument("-p", "--password", required=False, help="Password to login to CTFd (default: interactive)")
    parser.add_argument("-T", "--threads", required=False, default=8, type=int, help="Number of threads (default: 8)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    return parser.parse_args()


if __name__ == '__main__':
    args = parseArgs()

    if not args.target.startswith("http://") and not args.target.startswith("https://"):
        args.target = "https://" + args.target
    args.target = args.target.rstrip('/')

    if args.verbose:
        print(f"[>] Target URL: {args.target}")

    if args.output is None:
        args.output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Challenges")
    if args.password is None:
        args.password = getpass("Password: ")

    cp = CTFdParser(args.target, args.user, args.password, args.output)
    if cp.login():
        cp.get_challenges(threads=args.threads)
    else:
        print("[-] Login failed")
