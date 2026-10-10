import re
import socket
import uuid
from urllib.parse import urlsplit, urlencode

url = "http://hw1.alexbers.com/"
cookies = {
    'user': '3df3f22bf92d21bca14d564ebb60685c'
}

jar = dict(cookies)

templateHref = r"""<a\s+href=['"]([^'"]+)['"]"""
templateCode = r"<code>(/[^<]+)</code>"
templateGetP = r"Перейдите по"
templatePostO = r"Отправьте POST-запрос"
templateGetO = r"Отправьте GET-запрос"
templatePostZ = r"Загрузите файлы"
templateParts = r"(<table[^>]*>.*?</table>)"
templateCodeTable = r"<code>([^<]*)</code>"
templateTable = r"<tr>(.*?)</tr>"

GET_LINK   = 0
GET_CODE   = 1
POST_DATA  = 2
POST_FILES = 3
UNKNOWN    = 4

_conn = None

# === НАЧАЛО СОКЕТ ВЕРСИИ ===

def _close_conn():
    global _conn
    if _conn:
        try:
            _conn[3].close()
            _conn[2].close()
        except OSError:
            pass
    _conn = None


def _get_conn(host, port):
    global _conn
    if _conn and _conn[0] == host and _conn[1] == port:
        return _conn[2], _conn[3]
    _close_conn()
    s = socket.create_connection((host, port), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    _conn = (host, port, s, s.makefile('rb'))
    return _conn[2], _conn[3]


def _read_response(f):
    status_line = f.readline()
    if not status_line:
        raise ConnectionError("соединение закрыто сервером")
    status = int(status_line.split()[1])

    resp_headers = []
    while True:
        line = f.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode('iso-8859-1').partition(":")
        resp_headers.append((k.strip().lower(), v.strip()))
    hdr = dict(resp_headers)

    if "chunked" in hdr.get("transfer-encoding", "").lower():
        body = b""
        while True:
            size = int(f.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while f.readline() not in (b"\r\n", b"\n", b""):
                    pass
                break
            body += f.read(size)
            f.readline()
    elif "content-length" in hdr:
        body = f.read(int(hdr["content-length"]))
    else:
        body = f.read()
        hdr["connection"] = "close"

    if hdr.get("connection", "").lower() == "close":
        _close_conn()
    return status, resp_headers, body


def _build_multipart(files: dict):
    boundary = "----boundary" + uuid.uuid4().hex
    body = b""
    for field, (filename, content, ctype) in files.items():
        body += f"--{boundary}\r\n".encode()
        body += (f'Content-Disposition: form-data; name="{field}"; '
                 f'filename="{filename}"\r\n').encode('utf-8')
        body += f"Content-Type: {ctype}\r\n\r\n".encode()
        body += content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def _raw_request(method, full_url, headers, req_cookies, params, data, files):
    parts = urlsplit(full_url)
    host = parts.hostname
    port = parts.port or 80
    path = parts.path or "/"

    query = parts.query
    if params:
        extra = urlencode(params)
        query = query + "&" + extra if query else extra
    if query:
        path += "?" + query

    body = b""
    content_type = None
    if files:
        body, content_type = _build_multipart(files)
    elif data:
        body = urlencode(data).encode('utf-8')
        content_type = "application/x-www-form-urlencoded"

    final = {
        "Host": parts.netloc,
        "User-Agent": "python-socket-client",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
    }
    if method == "POST":
        final["Content-Length"] = str(len(body))
        if content_type:
            final["Content-Type"] = content_type
    if req_cookies:
        final["Cookie"] = "; ".join(f"{k}={v}" for k, v in req_cookies.items())

    lower_map = {k.lower(): k for k in final}
    for k, v in headers.items():
        if k.lower() in lower_map:
            del final[lower_map[k.lower()]]
        final[k] = v
        lower_map[k.lower()] = k

    head = f"{method} {path} HTTP/1.1\r\n"
    for k, v in final.items():
        head += f"{k}: {v}\r\n"
    head += "\r\n"

    payload = head.encode('utf-8') + body
    for attempt in (1, 2):
        sock, f = _get_conn(host, port)
        try:
            sock.sendall(payload)
            return _read_response(f)
        except (OSError, ValueError):
            _close_conn()
            if attempt == 2:
                raise


def send(method, full_url, headers=None, req_cookies=None,
         params=None, data=None, files=None) -> str:
    headers = headers or {}
    params = params or {}
    data = data or {}
    files = files or {}

    for _ in range(10):
        sent_cookies = {**jar, **(req_cookies or {})}
        status, resp_headers, body = _raw_request(
            method, full_url, headers, sent_cookies, params, data, files)

        for k, v in resp_headers:
            if k == "set-cookie":
                name, _, value = v.split(";")[0].partition("=")
                jar[name.strip()] = value.strip()

        location = next((v for k, v in resp_headers if k == "location"), None)
        if status in (301, 302, 303, 307, 308) and location:
            if location.startswith("http"):
                full_url = location
            else:
                p = urlsplit(full_url)
                if not location.startswith("/"):
                    location = p.path.rsplit("/", 1)[0] + "/" + location
                full_url = f"{p.scheme}://{p.netloc}{location}"
            if status in (301, 302, 303):
                method, data, files = "GET", {}, {}
            params = {}
            continue
        return body.decode('utf-8', errors='replace')
    raise ValueError("Слишком много редиректов")

# === КОНЕЦ СОКЕТ ВЕРСИИ ===

def firstRequests() -> str:
    return send("GET", url)


def findLink(page: str) -> str:
    href_match = re.search(templateHref, page)
    if href_match:
        return href_match.group(1)
    code_match = re.search(templateCode, page)
    if code_match:
        return code_match.group(1)
    raise ValueError("Не удалось найти ссылку на странице")


def VarChoser(page: str) -> int:
    if re.search(templatePostZ, page):
        return POST_FILES
    if re.search(templatePostO, page):
        return POST_DATA
    if re.search(templateGetO, page):
        return GET_CODE
    if re.search(templateGetP, page):
        return GET_LINK
    return UNKNOWN


def _parse_step(page: str) -> dict:
    path = findLink(page)
    full_url = url.rstrip('/') + path
    typeOfPost = VarChoser(page)

    req_headers = {}
    req_cookies = dict(cookies)
    req_params = {}
    req_data = {}
    req_files = {}

    parts = re.split(templateParts, page, flags=re.S)

    for i, part in enumerate(parts):
        if not part.startswith("<table"):
            continue
        before = parts[i - 1] if i > 0 else ""
        before = before[-300:]

        rows = []
        for tr in re.findall(templateTable, part, re.S):
            codes = re.findall(templateCodeTable, tr)
            if len(codes) >= 2:
                rows.append((codes[0], codes[1]))

        if not rows:
            continue

        if "cookie" in before.lower():
            req_cookies.update(dict(rows))
        elif "заголовки" in before.lower():
            req_headers.update(dict(rows))
        elif "параметр" in before.lower():
            req_params.update(dict(rows))
        elif "данные формы" in before.lower():
            req_data.update(dict(rows))
        elif "Имя файла" in part:
            for name, content in rows:
                req_files[name] = (name, content.encode('utf-8'),
                                   'application/octet-stream')
        else:
            if typeOfPost == GET_LINK:
                req_headers.update(dict(rows))

    return {
        'kind': typeOfPost,
        'url': full_url,
        'headers': req_headers,
        'cookies': req_cookies,
        'params': req_params,
        'data': req_data,
        'files': req_files,
    }


def MakeMove(page: str) -> str:
    step = _parse_step(page)
    kind = step['kind']
    n = page.find("Шаг #")
    if n != -1:
        print(page[n:n+10])
    else:
        print(page)

    if kind in (GET_LINK, GET_CODE):
        return send(
            "GET",
            step['url'],
            headers=step['headers'],
            req_cookies=step['cookies'],
            params=step['params']
        )
    elif kind == POST_DATA:
        return send(
            "POST",
            step['url'],
            headers=step['headers'],
            req_cookies=step['cookies'],
            params=step['params'],
            data=step['data']
        )
    elif kind == POST_FILES:
        return send(
            "POST",
            step['url'],
            req_cookies=step['cookies'],
            files=step['files']
        )
    else:
        raise ValueError("Неизвестный тип шага")


def main():
    page = firstRequests()
    step = 0
    while step < 500:
        step += 1

        try:
            page = MakeMove(page)
        except Exception as e:
            print(f"Ошибка: {e}")
            print(page)
            break
    _close_conn()


if __name__ == '__main__':
    main()