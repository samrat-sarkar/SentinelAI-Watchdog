import subprocess
import psutil
import requests
import google.generativeai as genai
import threading
import time
import sqlite3
from datetime import datetime

api_key = "..............................."
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-1.5-flash")


def format_memory(memory_bytes):
    if memory_bytes >= 1024 * 1024 * 1024:
        return f"{memory_bytes / (1024 * 1024 * 1024):.2f} GB"
    elif memory_bytes >= 1024 * 1024:
        return f"{memory_bytes / (1024 * 1024):.2f} MB"
    elif memory_bytes >= 1024:
        return f"{memory_bytes / 1024:.2f} KB"
    else:
        return f"{memory_bytes} bytes"


def add_new_processes_to_sqlite(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processes (
            pid INTEGER,
            pname TEXT,
            memory TEXT,
            path TEXT,
            time TEXT
        )
    ''')

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
        try:
            if proc.info['status'] == psutil.STATUS_RUNNING:
                pid = proc.info['pid']
                name = proc.info['name']
                memory_usage = format_memory(proc.info['memory_info'].rss)

                try:
                    path = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    path = 'Access Denied'

                cursor.execute('SELECT pname FROM processes WHERE pname = ?', (name,))
                if cursor.fetchone() is None:
                    cursor.execute('''
                        INSERT INTO processes (pid, pname, memory, path, time)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (pid, name, memory_usage, path, current_time))
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


def i_am_online(id):
    while True:
        SendReq = requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/online.php?id={id}')
        print(f"Online status sent for {id}")
        time.sleep(10)


if __name__ == "__main__":
    def get_serial_number():
        result = subprocess.run(['wmic', 'bios', 'get', 'serialnumber'], stdout=subprocess.PIPE, text=True)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            return lines[1]
        else:
            return None

    serial_number = get_serial_number()

    online_thread = threading.Thread(target=i_am_online, args=(serial_number,))
    online_thread.start()

    CheckID = requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/exist.php?id={serial_number}')
    if CheckID.text.strip() == "True":
        print("User is already registered")
    elif CheckID.text.strip() == "False":
        print("New User registered")
        RegisterID = requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/register.php?id={serial_number}')

    db_path = 'running_process_info.db'
    while True:
        add_new_processes_to_sqlite(db_path)
        print("All processes added to sqlite locally")
        if check_internet():
            conn = sqlite3.connect('running_process_info.db')
            cursor = conn.cursor()
            cursor.execute('SELECT pname, path FROM processes')
            rows = cursor.fetchall()
            for row in rows:
                processName = row[0]
                processPath = row[1]
                CheckReq = requests.get(f'https://samratsarkar.in/sentinelaiwatchdog/check.php?pName={processName}')
                if CheckReq.text.strip() == "True":
                    print(f"{processName} Exists !!!!")
                elif CheckReq.text.strip() == "False":
                    print(f"New process {processName} added to Online database")
                    response = model.generate_content(
                        f"{processName} is running in Task Manager, Having file location {processPath}. Is it safe, suspicious, unsafe, or unknown? Tell me in a single word.")
                    response_text = response.text
                    InsertReq = requests.get(
                        f'https://samratsarkar.in/sentinelaiwatchdog/insert.php?id={serial_number}&pName={processName}&pS={response_text}')
            conn.close()
            print("All genai API Call's DONE")
