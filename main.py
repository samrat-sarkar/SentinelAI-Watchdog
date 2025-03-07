import ipaddress
import os
import subprocess
import psutil
import requests
import google.generativeai as genai
import time
import sqlite3
from datetime import datetime
import random
import hashlib
import re
import getpass
from tkinter import *
import threading
import sys
from tkinter import Tk, PhotoImage, Label, Button, messagebox
from pystray import Icon, MenuItem, Menu
from PIL import Image
import pefile
import joblib
import numpy as np

model = joblib.load("malware_model.pkl")

def extract_features(file_path):
    try:
        with open(file_path, "rb") as f:
            pe = pefile.PE(data=f.read(), fast_load=True)
        features = [
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.NumberOfSections,
            pe.FILE_HEADER.TimeDateStamp,
            pe.FILE_HEADER.PointerToSymbolTable,
            pe.FILE_HEADER.Characteristics,
            pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfImage,
            pe.OPTIONAL_HEADER.SizeOfHeaders,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.SizeOfStackReserve,
            pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        ]
        return features
    except Exception:
        return None

def virustotal(processPath):
    API_KEY = 'API-KEY'
    UPLOAD_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
    REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

    WAIT_TIME_SUBMIT = 15
    WAIT_TIME_REPORT = 40
    POLLING_INTERVAL = 3
    DETECTION_THRESHOLD = 7
    MAX_RETRIES = 3

    append_text_to_display("Waiting Time: {} Seconds".format(WAIT_TIME_SUBMIT))
    time.sleep(WAIT_TIME_SUBMIT)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with open(processPath, 'rb') as file_to_scan:
                files = {'file': (processPath, file_to_scan)}
                params = {'apikey': API_KEY}
                response = requests.post(UPLOAD_URL, files=files, params=params)

                response.raise_for_status()
                upload_result = response.json()

                if 'scan_id' not in upload_result:
                    append_text_to_display("Error: No scan_id returned")
                    return None

                scan_id = upload_result['scan_id']
                append_text_to_display(f"VirusTotal File ({processPath}) submitted successfully")
                break
        except Exception as e:
            append_text_to_display(f"Error during file submission: {e}")
            if attempt < MAX_RETRIES:
                wait_time = random.uniform(1, 5)
                append_text_to_display(f"Retrying upload in {wait_time:.2f} seconds...")
                time.sleep(wait_time)
            else:
                return None

    append_text_to_display("Waiting Time: {} Seconds".format(WAIT_TIME_REPORT))
    time.sleep(WAIT_TIME_REPORT)

    params = {'apikey': API_KEY, 'resource': scan_id}
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(REPORT_URL, params=params)
            response.raise_for_status()
            report_result = response.json()

            if report_result.get('response_code') == 1:
                positives = report_result.get('positives', 0)
                total_engines = report_result.get('total', 0)

                if total_engines > 0:
                    detection_ratio = (positives / total_engines) * 100
                    if detection_ratio > DETECTION_THRESHOLD:
                        return 'Unsafe'
                    else:
                        return 'Safe'
            else:
                append_text_to_display("Error: Report not ready yet")
                append_text_to_display("Waiting Time: {} Seconds".format(POLLING_INTERVAL))
                time.sleep(POLLING_INTERVAL)
        except Exception as e:
            append_text_to_display(f"Error during report retrieval: {e}")
            if attempt < MAX_RETRIES:
                wait_time = random.uniform(1, 5)
                append_text_to_display(f"Retrying report fetch in {wait_time:.2f} seconds...")
                time.sleep(wait_time)
            else:
                return None


def gemini_scan(processName, processPath):
    api_key = "API-KEY"
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(
        f"{processName} is running in Task Manager, having file location {processPath}. Is it safe, suspicious, unsafe, or unknown? Tell me in a single word.")
    response_text = response.text
    append_text_to_display("Waiting Time: 4 Seconds")
    time.sleep(4)
    return response_text


def gemini_about(processName, processPath):
    api_key = "API-KEY"
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(
        f"{processName} is running in Task Manager, having file location {processPath}. If you know then Tell me in about it exact 20 words else Predict and tell me in exact 20 words.")
    response_text = response.text
    modified_text = response_text.replace(".exe", "")
    cleaned_text = re.sub(r'[\'\"*`,.]', '', modified_text)
    append_text_to_display("Waiting Time: 4 Seconds")
    time.sleep(4)
    return cleaned_text

def format_memory(memory_bytes):
    if memory_bytes >= 1024 * 1024 * 1024:
        return f"{memory_bytes / (1024 * 1024 * 1024):.2f} GB"
    elif memory_bytes >= 1024 * 1024:
        return f"{memory_bytes / (1024 * 1024):.2f} MB"
    elif memory_bytes >= 1024:
        return f"{memory_bytes / 1024:.2f} KB"
    else:
        return f"{memory_bytes} bytes"


def calculate_sha256(file_path):
    try:
        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256()
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def initialize_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS processes (
        pid INTEGER PRIMARY KEY,
        pname TEXT,
        sha256 TEXT,
        memory TEXT,
        path TEXT,
        time TEXT
    )''')
    conn.commit()
    conn.close()


def add_new_processes_to_sqlite(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
        try:
            if proc.info['status'] == psutil.STATUS_RUNNING:
                pid = proc.info['pid']
                name = proc.info['name']
                memory_usage = format_memory(proc.info['memory_info'].rss)

                try:
                    path = proc.exe()
                    sha256_hash = calculate_sha256(path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    path = 'Access Denied'
                    sha256_hash = None

                if sha256_hash is not None:
                    cursor.execute('SELECT sha256 FROM processes WHERE sha256 = ?', (sha256_hash,))
                    if cursor.fetchone() is None:
                        cursor.execute('''INSERT INTO processes (pid, pname, sha256, memory, path, time)
                                          VALUES (?, ?, ?, ?, ?, ?)''',
                                       (pid, name, sha256_hash, memory_usage, path, current_time))
                        append_text_to_display(f"Inserted process '{name}' with PID {pid} and SHA-256 hash {sha256_hash} into the database.")
                    else:
                        append_text_to_display(f"Process '{name}' with hash {sha256_hash} already exists in the database.")
                else:
                    print(f"Skipping process '{name}' (PID: {pid}) because its SHA-256 hash could not be calculated.")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    conn.commit()
    conn.close()


def check_internet(url='http://www.google.com'):
    try:
        requests.get(url, timeout=5)
        return True
    except requests.ConnectionError:
        return False


def make_request_with_retry(url, retries=3):
    for attempt in range(retries):
        response = requests.get(url)
        if response.status_code == 429:
            delay = random.randint(1, 3)
            append_text_to_display(f"Rate limit exceeded. Retrying in {delay} seconds...")
            time.sleep(delay)
        else:
            return response
    raise Exception("Max retries exceeded")

def get_serial_number():
    try:
        result = subprocess.run(['powershell', '-command','Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber'],stdout=subprocess.PIPE, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if lines and lines[0] != "0":
            formatted_lines = lines[0].replace('-', '')
            hash = hashlib.md5(formatted_lines.encode()).hexdigest()
            return hash
        else:
            hostname_result = subprocess.run(['powershell', '-command', 'hostname'], stdout=subprocess.PIPE, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            hostname = hostname_result.stdout.strip()
            formatted_hostname = hostname.replace('-', '')
            hash = hashlib.md5(formatted_hostname.encode()).hexdigest()
            return hash
    except Exception as e:
        append_text_to_display(f"Failed to retrieve serial number: {e}")


def i_am_online(id):
    while True:
        try:
            if check_internet():
                requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/api/online.php?id={id}')
                append_text_to_display(f"Online status sent for ID: {id}")
        except Exception as e:
            append_text_to_display(f"Failed to send online status: {e}")
        time.sleep(10)

def PC_Online():
    db_path = 'running_process_info.db'
    initialize_database(db_path)

    serial_number = get_serial_number()
    username = getpass.getuser()

    CheckID = requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/api/exist.php?id={serial_number}')
    if CheckID.text.strip() == "True":
        with open("LOGIN_PASSWORD.txt", "w") as file:
            file.write(serial_number)
        append_text_to_display("User is already registered.")
    elif CheckID.text.strip() == "False":
        append_text_to_display("New user registered.")
        requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/api/register.php?id={serial_number}&u={username}')
        with open("LOGIN_PASSWORD.txt", "w") as file:
            file.write(serial_number)
        append_text_to_display("User registration completed.")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT pname, sha256, memory, path, time FROM processes')
    rows = cursor.fetchall()

    for row in rows:
        processName = row[0]
        processSha256 = row[1]
        processMemory = row[2]
        processPath = row[3]
        processTime = row[4]
        check_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/check.php?id={serial_number}&pH={processSha256}'

        CheckReq = make_request_with_retry(check_url)
        if CheckReq.text.strip() == "True":
            append_text_to_display(f"Process '{processName}' exists in the online database.")
        elif CheckReq.text.strip() == "False":
            append_text_to_display(f"New process '{processName}' Adding to the online database.")
            features = extract_features(processPath)
            if features is None:
                append_text_to_display("Gemini Scan API is called.")
                response_text_1 = gemini_scan(processName, processPath)
                append_text_to_display("Got Response from Gemini Scan API.")
                append_text_to_display("Gemini About API is called.")
                aboutProcess = gemini_about(processName, processPath)
                append_text_to_display("Got Response from Gemini About API.")
                final_response_text = response_text_1.replace(".", "").replace(",", "").replace("*", "").strip()
                if final_response_text in ["Suspicious", "Unsafe", "Unknown"]:
                    append_text_to_display("VirusTotal API is called.")
                    final_response_text = virustotal(processPath)
                    append_text_to_display("Got Response from VirusTotal API.")
                    final_response_text = final_response_text.replace(".", "").replace(",", "").replace("*", "").strip()
                    insert_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/insert.php?a={aboutProcess}&id={serial_number}&pN={processName}&pS={final_response_text}&pP={processPath}&pH={processSha256}&pM={processMemory}&pT={processTime}'
                    make_request_with_retry(insert_url)
                else:
                    final_response_text = final_response_text.replace(".", "").replace(",", "").replace("*", "").strip()
                    insert_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/insert.php?a={aboutProcess}&id={serial_number}&pN={processName}&pS={final_response_text}&pP={processPath}&pH={processSha256}&pM={processMemory}&pT={processTime}'
                    make_request_with_retry(insert_url)
                append_text_to_display(f"Process '{processName}' added to the online database with SHA-256 hash {processSha256}.")
            else:
                append_text_to_display("Sentinel AI Watchdog Scan is called.")
                features = np.array(features).reshape(1, -1)
                probability = model.predict_proba(features)[0][1]
                append_text_to_display(f"Process: '{processName}' | Score: {probability}.")
                if probability > 0.60:
                    response_text_1 = "Unsafe"
                    append_text_to_display("Gemini About API is called.")
                    aboutProcess = gemini_about(processName, processPath)
                    append_text_to_display("Got Response from Gemini About API.")
                    final_response_text = response_text_1.replace(".", "").replace(",", "").replace("*", "").strip()
                    insert_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/insert.php?a={aboutProcess}&id={serial_number}&pN={processName}&pS={final_response_text}&pP={processPath}&pH={processSha256}&pM={processMemory}&pT={processTime}'
                    make_request_with_retry(insert_url)
                    append_text_to_display(f"Process '{processName}' added to the online database with SHA-256 hash {processSha256}.")
                else:
                    append_text_to_display("Gemini Scan API is called.")
                    response_text_1 = gemini_scan(processName, processPath)
                    append_text_to_display("Got Response from Gemini Scan API.")
                    append_text_to_display("Gemini About API is called.")
                    aboutProcess = gemini_about(processName, processPath)
                    append_text_to_display("Got Response from Gemini About API.")
                    final_response_text = response_text_1.replace(".", "").replace(",", "").replace("*", "").strip()
                    if final_response_text in ["Suspicious", "Unsafe", "Unknown"]:
                        append_text_to_display("VirusTotal API is called.")
                        final_response_text = virustotal(processPath)
                        append_text_to_display("Got Response from VirusTotal API.")
                        final_response_text = final_response_text.replace(".", "").replace(",", "").replace("*",
                                                                                                            "").strip()
                        insert_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/insert.php?a={aboutProcess}&id={serial_number}&pN={processName}&pS={final_response_text}&pP={processPath}&pH={processSha256}&pM={processMemory}&pT={processTime}'
                        make_request_with_retry(insert_url)
                    else:
                        final_response_text = final_response_text.replace(".", "").replace(",", "").replace("*",
                                                                                                            "").strip()
                        insert_url = f'https://samratsarkar.in/sentinelaiwatchdog/api/insert.php?a={aboutProcess}&id={serial_number}&pN={processName}&pS={final_response_text}&pP={processPath}&pH={processSha256}&pM={processMemory}&pT={processTime}'
                        make_request_with_retry(insert_url)
                    append_text_to_display(f"Process '{processName}' added to the online database with SHA-256 hash {processSha256}.")
    conn.close()
    add_new_processes_to_sqlite(db_path)

def PC_Offline():
    db_path = 'running_process_info.db'
    initialize_database(db_path)
    add_new_processes_to_sqlite(db_path)
    append_text_to_display("All running processes have been evaluated and added to the SQLite database.")

def is_bogon_ip(ip: str) -> bool:
    bogon_ranges = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
        "::/128", "::1/128", "::ffff:0:0/96", "100::/64", "2001:10::/28", "2001:db8::/32",
        "fc00::/7", "fe80::/10", "ff00::/8"
    ]

    ip_obj = ipaddress.ip_address(ip)

    for bogon in bogon_ranges:
        if ip_obj in ipaddress.ip_network(bogon, strict=False):
            return True

    return False

def gather_and_store_connections():
    while True:
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            netstat_output = result.stdout
            established_connections = re.findall(r'TCP\s+\S+:(\d+)\s+(\S+):\d+\s+ESTABLISHED\s+(\d+)', netstat_output)
            connections = []
            for conn in established_connections:
                remote_ip = conn[1]
                if is_bogon_ip(remote_ip):
                    continue
                exe_name = get_executable_name(conn[2])
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                connections.append((remote_ip, exe_name, timestamp))

            conn = sqlite3.connect('established_connections.db')
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    ip TEXT,
                    exe_name TEXT,
                    timestamp TEXT,
                    UNIQUE(ip, exe_name)  -- Ensure uniqueness based on ip and exe_name
                )
            ''')

            for ip, exe_name, timestamp in connections:
                try:
                    cursor.execute('INSERT OR IGNORE INTO connections (ip, exe_name, timestamp) VALUES (?, ?, ?)',
                                   (ip, exe_name, timestamp))
                except Exception as e:
                    print(f"Error inserting into database: {str(e)}")

            conn.commit()
            conn.close()
            add_ip_to_db(serial_number)
        except Exception as e:
            print(f"Error gathering connections: {str(e)}")
        append_text_to_display("Waiting Time: 5 Seconds")
        time.sleep(5)

def get_executable_name(pid):
    try:
        ps_command = f"(Get-Process -Id {pid}).ProcessName"
        result = subprocess.run(
            ['powershell', '-Command', ps_command],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        exe_name = result.stdout.strip()
        if exe_name:
            return exe_name + ".exe"
        else:
            print(f"Warning: No name found for PID {pid}. PowerShell output: {result.stdout.strip()}")

        tasklist_result = subprocess.run(
            ['tasklist', '/FI', f'PID eq {pid}'],
            capture_output=True, text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        match = re.search(r'(\S+\.exe)', tasklist_result.stdout)
        if match:
            exe_name = match.group(1)
            print(f"Fallback: Using tasklist for PID {pid}, found exe_name: {exe_name}")
            return exe_name
    except Exception as e:
        print(f"Error fetching executable name for PID {pid}: {str(e)}")

    return None

def add_ip_to_db(serial_number):
    if check_internet():
        conn = sqlite3.connect('established_connections.db')
        cursor = conn.cursor()
        try:
            cursor.execute('SELECT DISTINCT ip, exe_name, timestamp FROM connections')
            rows = cursor.fetchall()

            for ip, exe_name, timestamp in rows:
                check_ip_exist = f'https://samratsarkar.in/sentinelaiwatchdog/api/ip_exist.php?id={serial_number}&Ip={ip}&exe={exe_name}'
                check_req = make_request_with_retry(check_ip_exist)

                if not check_req:
                    append_text_to_display(f"Failed to check IP '{ip}' in online database.")
                    continue

                if check_req.text.strip() == "True":
                    append_text_to_display(f"IP '{ip}' exists in the online database.")
                elif check_req.text.strip() == "False":
                    append_text_to_display(f"New IP '{ip}' is not in the online database. Adding it.")

                    insert_ip_to_db = (
                        f'https://samratsarkar.in/sentinelaiwatchdog/api/insert_ip.php'
                        f'?id={serial_number}&Ip={ip}&exe={exe_name}&t={timestamp}'
                    )

                    make_request_with_retry(insert_ip_to_db)
                    append_text_to_display(f"New IP '{ip}' has been added to the online database.")

        except sqlite3.Error as e:
            append_text_to_display(f"Database error: {str(e)}")
        finally:
            conn.close()

def background_loop(serial_number):
    count = 0
    while True:
        count += 1
        try:
            if check_internet():
                append_text_to_display("PC is Online..........")
                PC_Online()
            else:
                append_text_to_display("PC is Offline..........")
                PC_Offline()
            append_text_to_display(f"Iteration Count:({count})")
            if count == 5:
                clear_text_box()
                count = 0
        except Exception as e:
            append_text_to_display(f"An error occurred: {e}")
            try:
                requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/api/logs.php?id={serial_number}&l={e}')
            except Exception as log_error:
                print(f"Unable to send logs: {log_error}")

def StartTK():
    global Tkt
    Tkt = Tk()

def stop_program():
    print("Stopping the program...")
    Tkt.quit()
    sys.exit()

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def append_text_to_display(message):
    global text_box
    text_box.config(state=NORMAL)
    text_box.insert(END, message + "\n")
    text_box.see(END)
    text_box.config(state=DISABLED)

def clear_text_box():
    global text_box
    text_box.config(state=NORMAL)
    text_box.delete(1.0, END)
    text_box.config(state=DISABLED)

def hide_window():
    Tkt.withdraw()
    icon.visible = True

def show_window(icon, item):
    Tkt.deiconify()
    icon.visible = False

def on_exit(icon, item):
    stop_program()

def Home():
    global bg, text_box
    bg = PhotoImage(file=resource_path("bg.png"))
    bgimg = Label(Tkt, image=bg)
    bgimg.place(x=0, y=0)

    Tkt.title("SentinelAI Watchdog")
    icon_path = resource_path("icon.ico")
    Tkt.iconbitmap(icon_path)

    Tkt.geometry("800x450")

    label1 = Label(Tkt, text="Sentinel AI Watchdog", borderwidth=10, relief="solid",
                   bg='#283747', fg='#F7F9F9', font=('Verdana', 30, 'bold'))
    label1.pack(pady=20)

    label2 = Label(Tkt, text='Stay One Step Ahead with AI-Driven Threat Detection',
                   fg='#1C2833', bg='#F2F3F4', font=('Arial', 15, 'italic'))
    label2.pack(pady=15)

    hide_button = Button(Tkt, text="Hide/Run in background", command=hide_window,
                         bg='#5DADE2', fg='white', font=('Arial', 12, 'bold'))
    hide_button.pack(pady=10)

    stop_button = Button(Tkt, text="Stop Program", command=stop_program,
                         bg='#E74C3C', fg='white', font=('Arial', 12, 'bold'))
    stop_button.pack(pady=10)

    text_box_frame = Frame(Tkt)
    text_box_frame.pack(fill=BOTH, expand=True)

    scrollbar = Scrollbar(text_box_frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    text_box = Text(text_box_frame, wrap=WORD, yscrollcommand=scrollbar.set, bg='black', fg='lime', font=('Arial', 10))
    text_box.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=text_box.yview)
    text_box.config(state=DISABLED)

    Tkt.eval('tk::PlaceWindow . center')
    Tkt.resizable(False, False)

    serial_number = get_serial_number()
    threading.Thread(target=background_loop, args=(serial_number,), daemon=True).start()

    Tkt.mainloop()

if __name__ == "__main__":
    StartTK()

    icon_path = resource_path("icon.ico")
    icon_image = Image.open(icon_path)
    icon = Icon("SentinelAI Watchdog", icon_image, "SentinelAI Watchdog", menu=Menu(
        MenuItem("Show", show_window),
        MenuItem("Exit", on_exit)
    ))

    threading.Thread(target=icon.run, daemon=True).start()

    threading.Thread(target=gather_and_store_connections, daemon=True).start()
    serial_number = get_serial_number()
    threading.Thread(target=i_am_online, args=(serial_number,), daemon=True).start()

    Home()

