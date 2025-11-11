import sys
import socket
import threading
import queue
import time
import argparse
import os
import logging
from typing import Set, Dict, List, Tuple

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP
except ImportError:
    print("Ошибка: библиотека Scapy не найдена.")
    print("Пожалуйста, установите ее: pip install scapy")
    sys.exit(1)

results_lock = threading.Lock()
results_list: List[Tuple[str, int, str]] = []


def parse_port_specs(port_specs: List[str]) -> Dict[str, Set[int]]:
    ports_to_scan: Dict[str, Set[int]] = {'tcp': set(), 'udp': set()}
    all_ports = set(range(1, 65536))

    if not port_specs:
        return ports_to_scan

    remaining_specs = []
    full_tcp = 'tcp' in port_specs
    full_udp = 'udp' in port_specs

    if full_tcp:
        ports_to_scan['tcp'].update(all_ports)
    if full_udp:
        ports_to_scan['udp'].update(all_ports)

    remaining_specs = [s for s in port_specs if s not in ['tcp', 'udp']]

    for spec in remaining_specs:
        try:
            if '/' not in spec:
                print(f"Ошибка: неверный формат '{spec}'. Ожидается 'tcp/...' или 'udp/...'.", file=sys.stderr)
                continue

            proto_str, port_str = spec.split('/', 1)
            if proto_str not in ['tcp', 'udp']:
                print(f"Ошибка: неизвестный протокол '{proto_str}' в '{spec}'.", file=sys.stderr)
                continue

            port_parts = port_str.split(',')
            for part in port_parts:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if 1 <= start <= end <= 65535:
                        ports_to_scan[proto_str].update(range(start, end + 1))
                    else:
                        print(f"Ошибка: неверный диапазон портов '{part}'.", file=sys.stderr)
                else:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports_to_scan[proto_str].add(port)
                    else:
                        print(f"Ошибка: неверный порт '{port}'.", file=sys.stderr)
        except ValueError:
            print(f"Ошибка: не удалось распознать порты в '{spec}'.", file=sys.stderr)
        except Exception as e:
            print(f"Неожиданная ошибка при парсинге '{spec}': {e}", file=sys.stderr)

    return ports_to_scan


def guess_protocol(ip: str, port: int, proto: str, timeout: int) -> str:
    result = ""
    try:
        if proto == 'tcp':
            if port == 7:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    payload = b'hello\r\n'
                    s.sendall(payload)
                    data = s.recv(1024)
                    if data == payload:
                        return "ECHO"

            if port == 80:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((ip, port))
                    s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                    data = s.recv(1024)
                    if b'HTTP/' in data:
                        return "HTTP"

        elif proto == 'udp':
            if port == 7:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    payload = b'hello_udp'
                    s.sendto(payload, (ip, port))
                    data, _ = s.recvfrom(1024)
                    if data == payload:
                        return "ECHO"

            if port == 53:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    payload = b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
                    s.sendto(payload, (ip, port))
                    data, _ = s.recvfrom(1024)
                    if data[:2] == b'\xAA\xAA':
                        return "DNS"

    except (socket.timeout, ConnectionRefusedError, socket.error):
        pass
    except Exception:
        pass

    return result


def scan_tcp(ip: str, port: int, timeout: int) -> Tuple[bool, float]:
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    start_time = time.perf_counter()

    resp = sr1(packet, timeout=timeout, verbose=0)

    end_time = time.perf_counter()
    response_time_ms = (end_time - start_time) * 1000

    is_open = False
    if resp and resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            is_open = True

    return is_open, response_time_ms


def scan_udp(ip: str, port: int, timeout: int) -> bool:
    packet = IP(dst=ip) / UDP(dport=port)
    resp = sr1(packet, timeout=timeout, verbose=0)

    if resp is None:
        return True
    elif resp.haslayer(ICMP):
        if resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code == 3:
            return False
        else:
            return True
    elif resp.haslayer(UDP):
        return True

    return False


def worker(task_queue: queue.Queue, ip: str, timeout: int, verbose: bool, guess: bool):
    while True:
        try:
            proto, port = task_queue.get_nowait()
        except queue.Empty:
            break

        is_open = False
        response_time = 0.0

        try:
            if proto == 'tcp':
                is_open, response_time = scan_tcp(ip, port, timeout)
            elif proto == 'udp':
                is_open = scan_udp(ip, port, timeout)
        except Exception as e:
            pass

        if is_open:
            app_protocol = ""
            if guess:
                app_protocol = guess_protocol(ip, port, proto, timeout)

            output = f"{proto.upper()} {port} "
            if verbose and proto == 'tcp':
                output += f"[{response_time:.2f}ms] "
            if guess and app_protocol:
                output += f"[{app_protocol}] "
            output += "-"

            with results_lock:
                results_list.append((proto, port, output))

        task_queue.task_done()


def main():
    if os.getuid() != 0:
        print("ВНИМАНИЕ: Для SYN/UDP сканирования через Scapy требуются права root.", file=sys.stderr)
        print("Пожалуйста, запустите скрипт с 'sudo'.", file=sys.stderr)

    parser = argparse.ArgumentParser(description="Сканер портов TCP/UDP на Python")
    parser.add_argument('ip_address', help="IP-адрес или доменное имя цели")
    parser.add_argument('port_specs', nargs='*',
                        help="Спецификации портов. "
                             "Примеры: 'tcp/80', 'udp/53,100-200', 'tcp' (все порты)")

    parser.add_argument('--timeout', type=float, default=2.0,
                        help="Таймаут ожидания ответа в секундах (по умолч. 2с)")
    parser.add_argument('-j', '--num-threads', type=int, default=10,
                        help="Число потоков (по умолч. 10)")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Подробный режим (показывает время ответа для TCP)")
    parser.add_argument('-g', '--guess', action='store_true',
                        help="Определение протокола прикладного уровня (HTTP, DNS, ECHO)")

    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.ip_address)
        print(f"Сканирование {args.ip_address} ({target_ip})...")
    except socket.gaierror:
        print(f"Ошибка: не удалось разрешить имя хоста '{args.ip_address}'", file=sys.stderr)
        sys.exit(1)

    ports_to_scan = parse_port_specs(args.port_specs)
    if not ports_to_scan['tcp'] and not ports_to_scan['udp']:
        print("Порты для сканирования не указаны. Завершение.")
        sys.exit(0)

    task_queue = queue.Queue()
    for port in sorted(list(ports_to_scan['tcp'])):
        task_queue.put(('tcp', port))
    for port in sorted(list(ports_to_scan['udp'])):
        task_queue.put(('udp', port))

    if task_queue.empty():
        print("Нет задач для сканирования.")
        return

    threads = []
    for _ in range(args.num_threads):
        t = threading.Thread(target=worker,
                             args=(task_queue, target_ip, args.timeout, args.verbose, args.guess),
                             daemon=True)
        threads.append(t)

    task_queue.join()

    print("\n--- Результаты сканирования ---")

    # Сортируем результаты по протоколу, затем по номеру порта
    results_list.sort(key=lambda x: (x[0], x[1]))

    if not results_list:
        print("Открытых портов не найдено.")
    else:
        for _, _, output_line in results_list:
            print(output_line)


if __name__ == "__main__":
    main()