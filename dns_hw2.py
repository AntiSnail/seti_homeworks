import socket
import struct
import time
import pickle
import threading
import os
import sys

HOST = "127.0.0.1"
PORT = 53
CACHE_FILE = "cache.pkl"
MAX_ITERATIVE_DEPTH = 10

ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.7.91.13",    # b.root-servers.net
    "192.228.79.201", # c.root-servers.net
    "192.33.4.12",    # d.root-servers.net
]

cache = {}
cache_lock = threading.Lock()


def load_cache():
    global cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "rb") as f:
                loaded = pickle.load(f)
                now = time.time()
                with cache_lock:
                    # Загружаем только неистекшие записи
                    cache = {k: v for k, v in loaded.items() if v[0] > now}
            print(f"[КЭШ] Успешно загружено активных записей с диска: {len(cache)}")
        except Exception as e:
            print(f"[КЭШ] Ошибка при загрузке файла кэша: {e}")
            cache = {}

def save_cache():
    with cache_lock:
        now = time.time()
        active_cache = {k: v for k, v in cache.items() if v[0] > now}
        try:
            with open(CACHE_FILE, "wb") as f:
                pickle.dump(active_cache, f)
            print(f"[КЭШ] Сохранено записей на диск: {len(active_cache)}")
        except Exception as e:
            print(f"[КЭШ] Ошибка при сохранении кэша: {e}")


def parse_qname(data, offset):

    labels = []
    curr = offset
    visited_offsets = set()
    jumped = False
    next_offset = offset

    while True:
        if curr >= len(data):
            if not jumped:
                next_offset = curr
            break
            
        length = data[curr]

        if length == 0:
            if not jumped:
                next_offset = curr + 1
            break

        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                if not jumped:
                    next_offset = curr + 2
                break
            if not jumped:
                next_offset = curr + 2
                jumped = True
            
            pointer = struct.unpack("!H", data[curr:curr+2])[0] & 0x3FFF
            if pointer in visited_offsets or pointer >= len(data):
                break
            visited_offsets.add(pointer)
            curr = pointer
            continue

        curr += 1
        if curr + length > len(data):
            if not jumped:
                next_offset = curr + length
            break
        label = data[curr:curr+length].decode("latin-1", errors="replace")
        labels.append(label)
        curr += length

    qname = ".".join(labels)
    return qname, next_offset


def parse_question(data, offset=12):
    qname, end_qname_offset = parse_qname(data, offset)
    if end_qname_offset + 4 > len(data):
        raise ValueError("Некорректный размер секции вопросов")
    qtype, qclass = struct.unpack("!HH", data[end_qname_offset:end_qname_offset+4])
    return qname, qtype, qclass, end_qname_offset + 4


def parse_resource_record(data, offset):
    name, curr = parse_qname(data, offset)
    if curr + 10 > len(data):
        raise ValueError("Запись RR слишком короткая")
    
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[curr:curr+10])
    curr += 10
    
    if curr + rdlength > len(data):
        raise ValueError("RDATA выходит за пределы пакета")
        
    rdata = data[curr:curr+rdlength]
    curr += rdlength
    return name, rtype, rclass, ttl, rdlength, rdata, curr


def parse_dns_packet(data):
    if len(data) < 12:
        return None

    req_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    
    offset = 12
    questions = []
    for _ in range(qdcount):
        qname, qtype, qclass, offset = parse_question(data, offset)
        questions.append((qname, qtype, qclass))

    answers = []
    for _ in range(ancount):
        rr = parse_resource_record(data, offset)
        answers.append(rr)
        offset = rr[6]

    authorities = []
    for _ in range(nscount):
        rr = parse_resource_record(data, offset)
        authorities.append(rr)
        offset = rr[6]

    additionals = []
    for _ in range(arcount):
        rr = parse_resource_record(data, offset)
        additionals.append(rr)
        offset = rr[6]

    return {
        "id": req_id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
        "question_end_offset": offset
    }


def extract_min_ttl(packet_info):
    ttls = [rr[3] for rr in packet_info["answers"] if rr[3] > 0]
    return min(ttls) if ttls else 300


def build_error_response(req_id, req_data, rcode=2):
    if len(req_data) >= 12:
        q_end = 12
        try:
            _, _, _, q_end = parse_question(req_data, 12)
        except Exception:
            q_end = len(req_data)
        question_bytes = req_data[12:q_end]
        qdcount = 1
    else:
        question_bytes = b""
        qdcount = 0

    flags = 0x8180 | (rcode & 0x0F)  # QR=1, RD=1, RA=1, RCODE
    header = struct.pack("!HHHHHH", req_id, flags, qdcount, 0, 0, 0)
    return header + question_bytes


def handle_multiply(req_id, req_data, qname, question_end):
    parts = qname.split(".")
    numbers = []
    for part in parts:
        if part.lower() == "multiply":
            break
        if part.isdigit():
            numbers.append(int(part))

    prod = 1
    for num in numbers:
        prod *= num
    result_x = prod % 256
    ip_str = f"127.0.0.{result_x}"

    header = struct.pack("!HHHHHH", req_id, 0x8180, 1, 1, 0, 0)
    question = req_data[12:question_end]
    
    rr_header = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4)
    rdata = socket.inet_aton(ip_str)

    print(f"[MULTIPLY] {qname} -> Вычислено: {numbers} -> IP: {ip_str}")
    return header + question + rr_header + rdata


def send_udp_query(query_data, server_ip, timeout=2.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query_data, (server_ip, 53))
        resp, _ = sock.recvfrom(4096)
        return resp
    except Exception:
        return None
    finally:
        sock.close()


def resolve_iteratively(qname, qtype, req_data, depth=0):
    if depth > MAX_ITERATIVE_DEPTH:
        return None

    current_ns_list = list(ROOT_SERVERS)

    while current_ns_list:
        ns_ip = current_ns_list.pop(0)
        resp_data = send_udp_query(req_data, ns_ip)
        if not resp_data:
            continue

        try:
            parsed = parse_dns_packet(resp_data)
        except Exception:
            continue

        if not parsed:
            continue

        rcode = parsed["flags"] & 0x0F
        if parsed["answers"] or rcode == 3: 
            return resp_data

        next_ns_ips = []
        ns_names = []

        for name, rtype, rclass, ttl, rdlength, rdata, _ in parsed["authorities"]:
            if rtype == 2:  # NS record
                ns_domain, _ = parse_qname(resp_data, _ - rdlength)
                ns_names.append(ns_domain)

        for name, rtype, rclass, ttl, rdlength, rdata, _ in parsed["additionals"]:
            if rtype == 1 and rdlength == 4:  # A record
                next_ns_ips.append(socket.inet_ntoa(rdata))

        if next_ns_ips:
            current_ns_list = next_ns_ips
            continue

        for ns_name in ns_names:
            sub_header = struct.pack("!HHHHHH", 0x5555, 0x0100, 1, 0, 0, 0)
            labels = ns_name.split(".")
            q_bytes = b""
            for l in labels:
                if l:
                    q_bytes += struct.pack("!B", len(l)) + l.encode("latin-1")
            q_bytes += b"\x00" + struct.pack("!HH", 1, 1)
            
            ns_resp = resolve_iteratively(ns_name, 1, sub_header + q_bytes, depth + 1)
            if ns_resp:
                ns_parsed = parse_dns_packet(ns_resp)
                if ns_parsed and ns_parsed["answers"]:
                    for _, rtype, _, _, rdlength, rdata, _ in ns_parsed["answers"]:
                        if rtype == 1 and rdlength == 4:
                            next_ns_ips.append(socket.inet_ntoa(rdata))

        if next_ns_ips:
            current_ns_list = next_ns_ips
        else:
            break

    return None


def process_dns_request(req_data):
    if len(req_data) < 12:
        return None

    req_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", req_data[:12])

    try:
        qname, qtype, qclass, question_end = parse_question(req_data, 12)
    except Exception:
        return build_error_response(req_id, req_data, rcode=1)

    key = (qname.lower(), qtype)
    now = time.time()

    with cache_lock:
        if key in cache:
            expire_time, cached_resp = cache[key]
            if now < expire_time:
                print(f"[КЭШ] ХИТ: {qname} (тип {qtype}) подгружен из кэша")
                return struct.pack("!H", req_id) + cached_resp[2:]  # Подменяем ID
            else:
                del cache[key]

    if ".multiply." in qname.lower():
        return handle_multiply(req_id, req_data, qname, question_end)

    print(f"[СЕТЬ] Итеративный опрос для {qname} (тип {qtype})...")
    resp_data = resolve_iteratively(qname, qtype, req_data)

    if resp_data:
        try:
            parsed_resp = parse_dns_packet(resp_data)
            if parsed_resp:
                ttl = extract_min_ttl(parsed_resp)
                with cache_lock:
                    cache[key] = (now + ttl, resp_data)
                print(f"[КЭШ] Запись сохранена: {qname} (TTL={ttl}s)")
                return struct.pack("!H", req_id) + resp_data[2:]
        except Exception as e:
            print(f"[ОШИБКА] Ошибка при кэшировании: {e}")

    return build_error_response(req_id, req_data, rcode=2)

def handle_udp_client(sock, data, addr):
    resp = process_dns_request(data)
    if resp:
        try:
            sock.sendto(resp, addr)
        except Exception:
            pass

def run_udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, PORT))
        print(f"[UDP] Сервер запущен на {HOST}:{PORT}")
    except Exception as e:
        print(f"[UDP] Не удалось привязать порт: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            threading.Thread(target=handle_udp_client, args=(sock, data, addr), daemon=True).start()
        except Exception:
            pass


def handle_tcp_client(conn, addr):
    with conn:
        try:
            conn.settimeout(5.0)
            while True:
                length_bytes = conn.recv(2)
                if not length_bytes or len(length_bytes) < 2:
                    break
                length = struct.unpack("!H", length_bytes)[0]
                
                req_data = b""
                while len(req_data) < length:
                    chunk = conn.recv(length - len(req_data))
                    if not chunk:
                        break
                    req_data += chunk

                resp = process_dns_request(req_data)
                if resp:
                    prefix = struct.pack("!H", len(resp))
                    conn.sendall(prefix + resp)
        except Exception:
            pass


def run_tcp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, PORT))
        sock.listen(10)
        print(f"[TCP] Сервер запущен на {HOST}:{PORT}")
    except Exception as e:
        print(f"[TCP] Не удалось привязать порт: {e}")
        return

    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
        except Exception:
            pass


if __name__ == "__main__":
    load_cache()

    udp_thread = threading.Thread(target=run_udp_server, daemon=True)
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)

    udp_thread.start()
    tcp_thread.start()

    print("\n=== DNS СЕРВЕР УСПЕШНО ЗАПУЩЕН НА 127.0.0.1:53 ===")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nСохранение кэша и остановка сервера...")
        save_cache()
        sys.exit(0)