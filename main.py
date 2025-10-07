import json
import logging
import socket
import struct
import threading
import multiprocessing
import time
from pathlib import Path
from datetime import timezone, datetime
import platform
import smtplib
from email.message import EmailMessage

RECV_DIR = Path("received_files")
LOG_FILE = "network_app.log"
TCP_HEADER_FMT = "!I"
TCP_HEADER_LEN = struct.calcsize(TCP_HEADER_FMT)
MULTIPROC_THRESHOLD = 1 * 1024 * 1024
UDP_FILE_THRESHOLD = 512 * 1024

logger = logging.getLogger("net_app")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

def ensure_recv_dir():
    RECV_DIR.mkdir(parents=True, exist_ok=True)

def timestamped_filename(orig_name: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    safe = Path(orig_name).name
    return f"{ts}_{safe}"

def choose_processing_strategy(payload_size: int) -> str:
    if platform.system() == "Windows":
        return "thread"
    return "process" if payload_size >= MULTIPROC_THRESHOLD else "thread"

def send_tcp_message(host: str, port: int, header: dict, payload_reader, retries=3):
    total_size = header.get("size", 0)
    attempt = 0
    while attempt < retries:
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")
                sock.sendall(struct.pack(TCP_HEADER_FMT, len(header_bytes)))
                sock.sendall(header_bytes)
                sent_bytes = 0
                last_update = time.time()
                while True:
                    chunk = payload_reader.read(64 * 1024)
                    if not chunk:
                        break
                    sock.sendall(chunk)
                    sent_bytes += len(chunk)
                    now = time.time()
                    if now - last_update >= 0.5 or sent_bytes == total_size:
                        percent = (sent_bytes / total_size * 100) if total_size else 0
                        print(f"\rОтправлено: {sent_bytes}/{total_size} байт ({percent:.2f}%)", end="", flush=True)
                        last_update = now
                print("\nПередача завершена")
            logger.info("Файл успешно отправлен по TCP")
            break
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
            attempt += 1
            logger.error("Ошибка соединения при отправке файла: %s (попытка %d/%d)", e, attempt, retries)
            if attempt < retries:
                time.sleep(2)
            else:
                raise
        except Exception as e:
            logger.exception("Неожиданная ошибка при отправке файла: %s", e)
            raise

def recv_tcp_data(conn: socket.socket, header: dict, addr, tag: str):
    try:
        filename = header.get("filename", "unknown.bin")
        expected_size = int(header.get("size", -1))
        save_name = timestamped_filename(filename)
        ensure_recv_dir()
        target_path = RECV_DIR / save_name
        bytes_received = 0
        last_update = time.time()
        with open(target_path, "wb") as f:
            if expected_size >= 0:
                while bytes_received < expected_size:
                    chunk = conn.recv(min(64 * 1024, expected_size - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    now = time.time()
                    if now - last_update >= 0.5 or bytes_received == expected_size:
                        percent = (bytes_received / expected_size * 100) if expected_size else 0
                        print(f"\rПринято: {bytes_received}/{expected_size} байт ({percent:.2f}%)", end="", flush=True)
                        last_update = now
            else:
                while True:
                    chunk = conn.recv(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
        print("\nПриём завершён")
        logger.info(f"Файл сохранён ({tag}) от {addr} -> {target_path} ({bytes_received} байт)")
    finally:
        conn.close()

def udp_handler_loop(host: str, port: int, stop_event: threading.Event):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        s.settimeout(1.0)
        logger.info("UDP сервер слушает %s:%d", host, port)
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(65536)
            except socket.timeout:
                continue
            header_end = data.find(b"\n")
            if header_end == -1:
                continue
            header = json.loads(data[:header_end].decode("utf-8"))
            payload = data[header_end + 1:]
            filename = header.get("filename", "udp_file.bin")
            ensure_recv_dir()
            target_path = RECV_DIR / timestamped_filename(filename)
            with open(target_path, "wb") as f:
                f.write(payload)
            logger.info(f"Файл получен по UDP от {addr} -> {target_path}")

class NetworkServer:
    def __init__(self, host="127.0.0.1", tcp_port=9000, udp_port=9001):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.stop_event = threading.Event()

    def start(self):
        ensure_recv_dir()
        threading.Thread(target=udp_handler_loop, args=(self.host, self.udp_port, self.stop_event), daemon=True).start()
        threading.Thread(target=self.tcp_accept_loop, daemon=True).start()
        logger.info("Сервер запущен (TCP %d / UDP %d)", self.tcp_port, self.udp_port)

    def tcp_accept_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.tcp_port))
            s.listen(5)
            s.settimeout(1.0)
            while not self.stop_event.is_set():
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._tcp_initial_handler, args=(conn, addr), daemon=True).start()

    def _tcp_initial_handler(self, conn, addr):
        try:
            data = conn.recv(TCP_HEADER_LEN)
            if len(data) < TCP_HEADER_LEN:
                conn.close()
                return
            (header_len,) = struct.unpack(TCP_HEADER_FMT, data)
            header_data = b""
            while len(header_data) < header_len:
                chunk = conn.recv(header_len - len(header_data))
                if not chunk:
                    break
                header_data += chunk
            header = json.loads(header_data.decode("utf-8"))
            expected_size = int(header.get("size", 0))
            strat = choose_processing_strategy(expected_size)
            if strat == "process":
                p = multiprocessing.Process(target=recv_tcp_data, args=(conn, header, addr, "процесс"))
                p.daemon = True
                p.start()
            else:
                threading.Thread(target=recv_tcp_data, args=(conn, header, addr, "поток"), daemon=True).start()
        except Exception as e:
            logger.exception("Ошибка TCP: %s", e)
            try:
                conn.close()
            except:
                pass

    def stop(self):
        self.stop_event.set()
        logger.info("Сервер остановлен")

class NetworkClient:
    def __init__(self, host="127.0.0.1"):
        self.host = host

    def send_file(self, file_path: str):
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(file_path)
        size = p.stat().st_size
        protocol = "UDP" if size <= UDP_FILE_THRESHOLD else "TCP"
        if protocol == "UDP":
            header = {"type": "file", "filename": p.name, "size": size}
            with open(p, "rb") as f:
                data = f.read()
            packet = json.dumps(header, ensure_ascii=False).encode("utf-8") + b"\n" + data
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(packet, (self.host, 9001))
            logger.info("Файл отправлен по UDP")
        else:
            header = {"type": "file", "filename": p.name, "size": size}
            with open(p, "rb") as f:
                send_tcp_message(self.host, 9000, header, f)
            logger.info("Файл отправлен по TCP")

    def send_email_gmail(self, sender_email, app_password, recipients, subject, body, attachments=None):
        msg = EmailMessage()
        msg["From"] = sender_email
        msg["To"] = ", ".join(recipients) if isinstance(recipients, list) else recipients
        msg["Subject"] = subject
        msg.set_content(body)
        if attachments:
            for path in attachments:
                p = Path(path)
                if not p.exists():
                    continue
                with open(p, "rb") as f:
                    data = f.read()
                msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=p.name)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        logger.info("Письмо отправлено")

def main():
    choice = input("Выберите режим (1 - сервер, 2 - клиент): ").strip()
    if choice == "1":
        srv = NetworkServer()
        srv.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            srv.stop()
    elif choice == "2":
        host = input("Введите IP сервера (по умолчанию 127.0.0.1): ").strip() or "127.0.0.1"
        client = NetworkClient(host)
        while True:
            print("\nВыберите действие:")
            print("f - Отправить файл")
            print("e - Отправить email через Gmail")
            print("0 - Выйти")
            action = input("Ваш выбор: ").strip().lower()
            if action == "f":
                path = input("Путь к файлу: ").strip()
                client.send_file(path)
            elif action == "e":
                sender = input("Ваш Gmail: ").strip()
                app_pass = input("Пароль приложения Gmail: ").strip()
                to_addrs = [a.strip() for a in input("Кому (через запятую): ").strip().split(",") if a.strip()]
                subject = input("Тема письма: ").strip()
                body = input("Текст письма: ").strip()
                attach_str = input("Пути к файлам через запятую (или пусто): ").strip()
                attachments = [a.strip() for a in attach_str.split(",") if a.strip()] if attach_str else None
                client.send_email_gmail(sender, app_pass, to_addrs, subject, body, attachments)
            elif action == "0":
                break

if __name__ == "__main__":
    main()
