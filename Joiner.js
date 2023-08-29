const prompt = require("prompt-sync")();
const choice = prompt("Choice: ");
const { execSync } = require("child_process");
if (choice == 1) {
    const pythonCode = `
    import random
    import tls_client as tlsclient
    import websocket
    import threading
    import base64
    import httpx
    import os
    import json
    import time
    
    # displaynames = open('usernames.txt','r',encoding='utf-8').read().splitlines()
    def getproxy():
        with open("proxies.txt") as proxy_file:
            proxies = proxy_file.readlines()
    
        # Load the last used proxy index from a file or default to 0
        try:
            with open("last_used_proxy.txt", "r") as f:
                last_used_proxy_index = int(f.read())
        except:
            last_used_proxy_index = 0
    
        # Select the next proxy in the list
        capproxy = random.choice(proxies).rstrip('\n')
        proxy = str('http://' + capproxy)
    
        # Increment the last used proxy index and save to a file
        last_used_proxy_index += 1
        if last_used_proxy_index >= len(proxies):
            last_used_proxy_index = 0
        with open("last_used_proxy.txt", "w") as f:
            f.write(str(last_used_proxy_index))
        return proxy
    class console:
        def log(log):t=time.strftime("%H:%M:%S");print(f"\x1b[0;37m[\x1b[0;90m{t}\x1b[0;37m]\x1b[0;37m {log}")
    proxy = getproxy()
    class Client:
        def __init__(self):
            self.session = tlsclient.Session(client_identifier='chrome_113',random_tls_extension_order=True)
        def client(self):
            return self.session, {'authority': 'discord.com','accept': '*/*','accept-language': 'it,it-IT;q=0.9','content-type': 'application/json','origin': 'https://discord.com','referer': 'https://discord.com','sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36','x-debug-options': 'bugReporterEnabled','x-discord-locale': 'en-GB','x-super-properties': Utility().build_x_super_prop(build_num)}, self.__cookies()
        def __cookies(self):
            r = self.session.get(url='https://discord.com')
            cs = {};c = r.cookies
            for ck in c:cs[ck.name] = ck.value
            return cs
        
    class Utility:
        def __init__(self):
            pass
        def discord_build_num(self):
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36','Accept': '*/*','Accept-Language': 'en-US,en;q=0.5','Accept-Encoding': 'gzip, deflate, br','Alt-Used': 'discord.com','Connection': 'keep-alive','Referer': 'https://discord.com/','Sec-Fetch-Dest': 'script','Sec-Fetch-Mode': 'no-cors','Sec-Fetch-Site': 'same-origin','Pragma': 'no-cache','Cache-Control': 'no-cache','TE': 'trailers'}
            try:
                html = httpx.get(f"https://discord.com/app?_={(time.time() * 1000)}", proxies={'http://': proxy}, headers=headers).text
                prefetched_script = html[html.rfind('/assets/'):html.find('"', html.rfind('/assets/'))]
                buildnum = httpx.get(f'https://discord.com{prefetched_script}', proxies={'http://': proxy}, headers=headers).text.split("buildNumber:\"")[1].split("\"")[0]
                return buildnum
            except:return 203239
        def build_x_super_prop(self,build_num):
            decoded = {"os":"Windows","browser":"Discord Client","device":"","system_locale":"it-IT","browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9013 Chrome/108.0.5359.215 Electron/22.3.2 Safari/537.36","browser_version":"113.0.0.0","os_version":"10","referrer":"https://link.mattupham.com/","referring_domain":"link.mattupham.com","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":build_num,"client_event_source":None}
            return base64.b64encode((json.dumps(separators=(',', ':'), obj=decoded)).encode()).decode()
    build_num = Utility().discord_build_num()
    
    class WebsocketClient:
        def __init__(self):
            self.ws = websocket.WebSocket()
        def __connect_ws(self):
            self.ws.connect('wss://gateway.discord.gg/?v=6&encoding=json')
            self.hello = json.loads(self.ws.recv())
            self.heartbeat_interval = self.hello['d']['heartbeat_interval']
        def __identify_ws(self, token):
            payload = {
                "op": 2,
                "d": {
                    "token": token,
                    "capabilities": 8189,
                    "properties": {
                        "os": "Windows",
                        "browser": "Discord Client",
                        "device": "",
                        "system_locale": "en-GB",
                        "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                        "browser_version": "114.0.0.0",
                        "os_version": "10",
                        "referrer": "",
                        "referring_domain": "",
                        "referrer_current": "",
                        "referring_domain_current": "",
                        "release_channel": "stable",
                        "client_build_number": build_num,
                        "client_event_source": None,
                        "design_id": 0
                    },
                    "presence": {
                        "activities": [],
                        "status": "online",
                        "since": 0,
                        "afk": False
                    },
                    "compress": False,
                    "client_state": {
                        "guild_versions": {},
                        "highest_last_message_id": "0",
                        "read_state_version": 0,
                        "user_guild_settings_version": -1,
                        "user_settings_version": -1,
                        "private_channels_version": "0",
                        "api_code_version": 0
                    }
                },
            }
            self.ws.send(json.dumps(payload))
        def close_ws(self):
            self.ws.close()
        def get_session_id(self):
            for i in range(5):
                try:recv = self.ws.recv();sessionid = json.loads(recv)['d']['session_id'];return sessionid
                except:pass
            return
        def run_websocket(self, token):
            self.__connect_ws()
            self.__identify_ws(token)
        
    class Discord:
        def __init__(self):
            pass
        def __fetch_invite(self, invite, headers, session, cookies):
            return session.get(f"https://discord.com/api/v9/invites/{invite}?inputValue={invite}&with_counts=true&with_expiration=true", proxy=proxy, headers=headers, cookies=cookies,  ).json()
        def join(self, token, invite):
            try:
              console.log('\x1b[0;92m[JOINING...]\x1b[0;37m {}****'.format(token[:30]))
              ws = WebsocketClient();ws.run_websocket(token);session_id = ws.get_session_id() 
              session, headers, cookies = Client().client()
              headers['authorization']=token
              invitedata = self.__fetch_invite(invite, headers, session, cookies)
              #displayname = random.choice(displaynames)
              #session.patch('https://discord.com/api/v9/users/@me',headers=headers,cookies=cookies,json={'global_name': displayname})
              #session.patch('https://discordapp.com/api/v9/users/@me', headers=headers,cookies=cookies, json={"avatar":"data:image/png;base64,"+base64.b64encode(cv2.imencode('.jpg', cv2.imread('avatars/'+random.choice(os.listdir('avatars'))))[1]).decode('utf-8')})
              #session.patch('https://discord.com/api/v9/users/@me/profile', headers=headers,cookies=cookies, json={'bio': random.choice(open("bios.txt", encoding="utf-8").read().splitlines())})
              headers["x-context-properties"] = base64.b64encode(json.dumps({"location": "Join Guild","location_guild_id": invitedata['guild']['id'],"location_channel_id": invitedata['channel']['id'],"location_channel_type": int(invitedata['channel']['type'])}).encode()).decode()
              res = session.post(f'https://discord.com/api/v9/invites/{invite}', proxy=proxy, headers=headers, json={'session_id':session_id}, cookies=cookies, )
              if res.status_code in [200,204]:
                  console.log('\x1b[0;92m[JOINED]\x1b[0;37m {}****'.format(token[:30]))
              elif 'cloudflare' in res.text.lower():
                  console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m(ratelimited by cloudflare)\x1b[0;37m'.format(token[:30]))
              elif 'captcha' in res.text.lower():
                  console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m(captcha detected)\x1b[0;37m'.format(token[:30]))
              else:
                  console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m({})\x1b[0;37m'.format(token[:30],res.text))
            except Exception as e:
                console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m({})\x1b[0;37m'.format(token[:30], e))
        def leave(self, token, guild_id):
            try:
              session, headers, cookies = Client().client()
              headers['authorization']=token
              res = session.delete(f"https://discord.com/api/v9/users/@me/guilds/{guild_id}",proxy=proxy, headers=headers,cookies=cookies,json={"lurking": False}, )
              if res.status_code in [200,204]:
                  console.log('\x1b[0;92m[LEFT]\x1b[0;37m {}****'.format(token[:30]))
              else:
                  console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m(code {})\x1b[0;37m'.format(token[:30],str(res.status_code)))
            except Exception as e:
              console.log('\x1b[1;31m[FAILED]\x1b[0;37m {}**** \x1b[0;90m({})\x1b[0;37m'.format(token[:30], e))
        
    invite = input('server invite code -> ')
    def join(token,_):
              Discord().join(token,invite)
    tokens = open('tokens.txt','r').read().splitlines()
    for token in tokens:
            threading.Thread(target=join, args=(token,True)).start()
        
        
    `
    try {
        const output = execSync(`echo "${pythonCode}" | python -`).toString();
        console.log(output);
      } catch (error) {
        console.error(`Error executing Python code: ${error.message}`);
      }
}
    
