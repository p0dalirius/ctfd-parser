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


def os_filename_sanitize(s):
    filtred = ['/', ';', ' ', ':']
    for char in filtred:
        s = s.replace(char, '_')
    s = re.sub('__*', '_', s)
    return s


class CTFdParser(object):
    """docstring for CTFdParser."""

    def __init__(self, target, login, password, basedir="Challenges"):
        super(CTFdParser, self).__init__()
        self.target = target
        self.basedir = basedir
        self.credentials = {
            'user': login,
            'password': password
        }
        self.session = requests.Session()

    def login(self):
        r = self.session.get(self.target + '/login')

        matched = re.search(b"""('csrfNonce':[ \t]+"([a-f0-9A-F]+))""", r.content)

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

        if r.status_code == 200:
            pass
        else:
            pass

    def get_challenges(self):
        """Documentation for get_challenges"""
        r = self.session.get(self.target + "/api/v1/challenges")

        json_challs = None
        if r.status_code == 200:
            json_challs = json.loads(r.content)
            if json_challs is not None:
                if json_challs['success'] == True:
                    self.challenges = json_challs['data']
                    self._parse()
                else:
                    print("[warn] An error occurred while requesting /api/v1/challenges")
            return json_challs
        else:
            return None

    def _parse(self):
        # Categories
        self.categories = list(set([chall["category"] for chall in self.challenges]))

        print('\x1b[1m[\x1b[93m+\x1b[0m\x1b[1m]\x1b[0m Found %d categories !' % len(self.categories))

        # Parsing challenges
        for category in self.categories:
            print("\x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m Parsing challenges of category : \x1b[95m%s\x1b[0m" % category)
            challs_of_category = [c for c in self.challenges if c['category'] == category]

            for chall in challs_of_category:
                print("   \x1b[1m[\x1b[93m>\x1b[0m\x1b[1m]\x1b[0m Parsing challenge : \x1b[96m%s\x1b[0m" % chall["name"])

                folder = os.path.sep.join([self.basedir, os_filename_sanitize(category), os_filename_sanitize(chall["name"])])
                if not os.path.exists(folder):
                    os.makedirs(folder)

                # Readme.md
                f = open(folder + os.path.sep + "README.md", 'w')
                f.write("# %s\n\n" % chall["name"])
                f.write("**Category** : %s\n" % chall["category"])
                f.write("**Points** : %s\n\n" % chall["value"])

                chall_json = self.get_challenge_by_id(chall["id"])["data"]
                f.write("%s\n\n" % chall_json["description"])

                # Get challenge files
                if len(chall_json["files"]) != 0:
                    f.write("## Files : \n")
                    for file_url in chall_json["files"]:
                        r = self.session.head(self.target + file_url, allow_redirects=True)
                        size = int(r.headers["Content-Length"])
                        if "?" in file_url:
                            filename = os.path.basename(file_url.split('?')[0])
                        else:
                            filename = os.path.basename(file_url)
                        #
                        f.write(" - [%s](./%s)\n" % (filename, filename))
                        if size < (50 * 1024 * 1024):  # 50 Mo
                            r = self.session.get(self.target + file_url, stream=True)
                            with open(folder + os.path.sep + filename, "wb") as fdl:
                                for chunk in r.iter_content(chunk_size=16 * 1024):
                                    fdl.write(chunk)
                        else:
                            r = self.session.get(self.target + file_url, stream=True)
                            with open(folder + os.path.sep + filename, "wb") as fdl:
                                for chunk in r.iter_content(chunk_size=16 * 1024):
                                    fdl.write(chunk)
                f.write("\n\n")
                f.close()
        return

    def get_challenge_by_id(self, chall_id: int):
        """Documentation for get_challenge_by_id"""
        r = self.session.get(self.target + '/api/v1/challenges/%d' % chall_id)

        json_chall = None
        if r.status_code == 200:
            json_chall = json.loads(r.content)
        return json_chall


def header():
    print("""   _____ _______ ______  _   _____
  / ____|__   __|  ____|| | |  __ \\
 | |       | |  | |__ __| | | |__) |_ _ _ __ ___  ___ _ __
 | |       | |  |  __/ _` | |  ___/ _` | '__/ __|/ _ \ '__|
 | |____   | |  | | | (_| | | |  | (_| | |  \__ \  __/ |
  \_____|  |_|  |_|  \__,_| |_|   \__,_|_|  |___/\___|_|
""")
    return


def parseArgs():
    header()
    parser = argparse.ArgumentParser(description="CTFdParser")
    parser.add_argument("-t", "--target", required=True, help="CTFd target (domain or ip)")
    parser.add_argument("-u", "--user", required=True, help="Username to login to CTFd")
    parser.add_argument("-p", "--password", required=True, help="Password to login to CTFd")
    parser.add_argument("-T", "--threads", required=False, default=8, help="Number of threads (default: 8)")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    return parser.parse_args()


if __name__ == '__main__':
    args = parseArgs()

    if not args.target.startswith("http://") and not args.target.startswith("https://"):
        args.target = "https://" + args.target
    args.target = args.target.rstrip('/')

    if args.verbose:
        print("[>] Target URL: %s" % args.target)

    cp = CTFdParser(args.target, args.user, args.password)
    cp.login()
    cp.get_challenges()
