import re
import requests

url = "http://hw1.alexbers.com/"
cookies = {
    'user': '3df3f22bf92d21bca14d564ebb60685c'
}

session = requests.Session()
session.cookies.update(cookies)

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


def firstRequests() -> str:
    r = session.get(url, timeout=15)
    return r.text


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
        r = session.get(
            step['url'],
            timeout=15,
            headers=step['headers'],
            cookies=step['cookies'],
            params=step['params']
        )
    elif kind == POST_DATA:
        r = session.post(
            step['url'],
            timeout=15,
            headers=step['headers'],
            cookies=step['cookies'],
            params=step['params'],
            data=step['data']
        )
    elif kind == POST_FILES:
        r = session.post(
            step['url'],
            timeout=15,
            cookies=step['cookies'],
            files=step['files']
        )
    else:
        raise ValueError("Неизвестный тип шага")

    r.encoding = 'utf-8'
    return r.text


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


if __name__ == '__main__':
    main()
    