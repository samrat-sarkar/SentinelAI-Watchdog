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
from tkinter import Tk, PhotoImage, Label, Button
from pystray import Icon, MenuItem, Menu
from PIL import Image, ImageDraw

def virustotal(processPath):
    api_key = 'key1'
    upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

    append_text_to_display("Waiting Time: 15 Seconds")
    time.sleep(15)
    with open(processPath, 'rb') as file_to_scan:
        files = {'file': (processPath, file_to_scan)}
        params = {'apikey': api_key}
        response = requests.post(upload_url, files=files, params=params)
        upload_result = response.json()
        scan_id = upload_result.get('scan_id')
        append_text_to_display(f"VirusTotal File ({processPath}) submitted successfully")

    append_text_to_display("Waiting Time: 30 Seconds")
    time.sleep(30)
    params = {'apikey': api_key, 'resource': scan_id}
    while True:
        response = requests.get(report_url, params=params)
        report_result = response.json()
        if report_result.get('response_code') == 1:
            positives = report_result.get('positives', 0)
            total_engines = report_result.get('total', 0)
            if total_engines > 0:
                detection_ratio = (positives / total_engines) * 100
                if detection_ratio > 50:
                    return 'Unsafe'
                else:
                    return 'Safe'


def gemini_scan(processName, processPath):
    api_key = "key2"
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(
        f"{processName} is running in Task Manager, having file location {processPath}. Is it safe, suspicious, unsafe, or unknown? Tell me in a single word.")
    response_text = response.text
    append_text_to_display("Waiting Time: 4 Seconds")
    time.sleep(4)
    return response_text


def gemini_about(processName, processPath):
    api_key = "key3"
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
            print(f"Rate limit exceeded. Retrying in {delay} seconds...")
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
        print(f"Failed to retrieve serial number: {e}")


def i_am_online(id):
    while True:
        try:
            if check_internet():
                requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/api/online.php?id={id}')
                append_text_to_display(f"Online status sent for ID: {id}")
        except Exception as e:
            print(f"Failed to send online status: {e}")
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
        RegisterID = requests.get(
            f'https://samratsarkar.in/sentinelaiwatchdog/api/register.php?id={serial_number}&u={username}')
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
            append_text_to_display(f"New process '{processName}' is not in the online database. Adding to the online database.")

            append_text_to_display("Gemini Scan API is called.")
            response_text_1 = gemini_scan(processName, processPath)
            append_text_to_display("Got Response from Gemini Scan API.")

            append_text_to_display("Gemini About API is called.")
            aboutProcess = gemini_about(processName, processPath)
            append_text_to_display("Got Response from Gemini About API.")

            final_response_text = response_text_1.replace(".", "").strip()

            if final_response_text in ["Suspicious", "Unsafe", "Unknown"]:
                append_text_to_display("VirusTotal API is called.")
                final_response_text = virustotal(processPath)
                append_text_to_display("Got Response from VirusTotal API.")

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
            append_text_to_display(f"-------------Iteration Count:({count})-------------")
            if count == 5:
                clear_text_box()
                count = 0
        except Exception as e:
            print(f"An error occurred: {e}")
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

    text_box = Text(text_box_frame, wrap=WORD, yscrollcommand=scrollbar.set,
                    bg='black', fg='lime', font=('Arial', 12))
    text_box.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar.config(command=text_box.yview)
    text_box.config(state=DISABLED)

    Tkt.eval('tk::PlaceWindow . center')
    Tkt.resizable(False, False)

    serial_number = get_serial_number()
    threading.Thread(target=background_loop, args=(serial_number,), daemon=True).start()

    Tkt.mainloop()

def hide_window():
    Tkt.withdraw()
    icon.visible = True

def show_window(icon, item):
    Tkt.deiconify()
    icon.visible = False

def on_exit(icon, item):
    stop_program()

if __name__ == "__main__":
    StartTK()
    icon_path = resource_path("icon.ico")
    icon_image = Image.open(icon_path)

    icon = Icon("SentinelAI Watchdog", icon_image, "SentinelAI Watchdog", menu=Menu(
        MenuItem("Show", show_window),
        MenuItem("Exit", on_exit)
    ))

    threading.Thread(target=icon.run, daemon=True).start()
    serial_number = get_serial_number()
    threading.Thread(target=i_am_online, args=(serial_number,), daemon=True).start()
    Home()

