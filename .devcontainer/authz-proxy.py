#!/usr/bin/env python3
# authz-proxy.py
# Body-inspecting Docker gate. Sits in FRONT of tecnativa/docker-socket-proxy:
#
#   app  (DOCKER_HOST=tcp://docker-authz:2375)
#     -> this shim            (polices POST /containers/create and /exec by content)
#       -> docker-endpoint-proxy  (tecnativa: coarse endpoint ACL, holds the real socket)
#         -> /var/run/docker.sock
#
# Policy: a container created through this shim may not have MORE access than the
# dev container -- no privileged, no added capabilities, no devices, no host or
# cross-container namespaces, no host bind mounts outside the workspace, and it
# cannot attach to the proxy network. Every container the shim creates is stamped
# with a label; `docker exec` is permitted ONLY into containers carrying that label,
# so you can exec your own containers but not the privileged proxy (or anything
# else on the host). Anything it cannot parse is denied (fail closed).
import json, os, re, select, socket, threading

UP_HOST = os.environ.get("UPSTREAM_HOST", "docker-endpoint-proxy")
UP_PORT = int(os.environ.get("UPSTREAM_PORT", "2375"))
LISTEN  = ("0.0.0.0", 2375)
ALLOWED = [p for p in os.environ.get("ALLOWED_BIND_PREFIXES", "").split(":") if p]
PROTECTED_NET = os.environ.get("PROTECTED_NETWORK", "")
OWN_LABEL = "authz.owned"

CREATE_RE = re.compile(r"^/(v[\d.]+/)?containers/create(\?|$)")
EXEC_RE   = re.compile(r"^/(v[\d.]+/)?containers/([^/]+)/exec(\?|$)")


def bind_ok(src):
    return any(src == p or src.startswith(p.rstrip("/") + "/") for p in ALLOWED)


def check_create(body):                        # None = allow, str = deny reason
    try:
        cfg = json.loads(body)
    except Exception:
        return "unparseable create body"
    hc = cfg.get("HostConfig") or {}
    if hc.get("Privileged"):       return "privileged"
    if hc.get("CapAdd"):           return "adds capabilities"
    if hc.get("Devices") or hc.get("DeviceRequests") or hc.get("DeviceCgroupRules"):
        return "device passthrough"
    if hc.get("VolumesFrom"):      return "VolumesFrom (could inherit the proxy socket)"
    for k in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"):
        if hc.get(k):              return "shares namespace: " + k
    nm = hc.get("NetworkMode") or ""
    if nm == "host" or nm.startswith("container:"):    return "NetworkMode " + nm
    if PROTECTED_NET and nm == PROTECTED_NET:          return "joins protected network"
    nc = (cfg.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}
    if PROTECTED_NET and PROTECTED_NET in nc:          return "attaches to protected network"
    for opt in hc.get("SecurityOpt") or []:
        if "unconfined" in opt or "no-new-privileges:false" in opt.replace(" ", ""):
            return "weakens confinement: " + opt
    for b in hc.get("Binds") or []:
        if not bind_ok(b.split(":")[0]):   return "bind outside workspace: " + b
    for m in hc.get("Mounts") or []:
        if m.get("Type") == "bind" and not bind_ok(m.get("Source", "")):
            return "bind outside workspace: " + m.get("Source", "")
    return None


def read_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def content_length(head):
    for l in head.split(b"\r\n"):
        if l.lower().startswith(b"content-length:"):
            try:
                return int(l.split(b":", 1)[1])
            except Exception:
                return None
    return None


def set_content_length(head, n):
    lines = [l for l in head.split(b"\r\n") if not l.lower().startswith(b"content-length:")]
    return b"\r\n".join(lines + [b"Content-Length: %d" % n])


def rewrite(head):                             # force one request per connection
    lines = head.split(b"\r\n")
    kept = [l for l in lines[1:] if not l.lower().startswith((b"connection:", b"keep-alive:"))]
    return b"\r\n".join([lines[0]] + kept + [b"Connection: close"]) + b"\r\n\r\n"


def deny(sock, msg):
    body = json.dumps({"message": "denied by authz shim: " + msg}).encode()
    sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                 b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    print("DENY:", msg, flush=True)


def upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((UP_HOST, UP_PORT))
    return s


def target_is_ours(cid):                       # is the exec target labelled by us?
    try:
        u = upstream()
        u.sendall(("GET /containers/%s/json HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n" % cid).encode())
        resp = b""
        while True:
            c = u.recv(65536)
            if not c:
                break
            resp += c
        u.close()
        body = resp.split(b"\r\n\r\n", 1)[1]
        data = json.loads(body[body.find(b"{"): body.rfind(b"}") + 1])
        return ((data.get("Config") or {}).get("Labels") or {}).get(OWN_LABEL) == "1"
    except Exception:
        return False                           # fail closed


def relay(a, b):
    socks = [a, b]
    while socks:
        for s in select.select(socks, [], [])[0]:
            data = s.recv(65536)
            other = b if s is a else a
            if not data:
                socks.remove(s)
                try:
                    other.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                other.sendall(data)


def handle(client):
    try:
        head, rest = read_headers(client)
        if not head:
            return
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1].decode("latin1")
        body = rest

        m = EXEC_RE.match(path)
        if method == b"POST" and m:
            if not target_is_ours(m.group(2)):
                return deny(client, "exec into a container we don't own")
            # owned -> fall through and forward unchanged
        elif method == b"POST" and CREATE_RE.match(path):
            clen = content_length(head)
            if clen is None:
                return deny(client, "create without Content-Length")
            while len(body) < clen:
                chunk = client.recv(65536)
                if not chunk:
                    break
                body += chunk
            reason = check_create(body[:clen])
            if reason:
                return deny(client, reason)
            cfg = json.loads(body[:clen])
            cfg.setdefault("Labels", {})[OWN_LABEL] = "1"     # stamp ownership
            body = json.dumps(cfg).encode()
            head = set_content_length(head, len(body))
            print("ALLOW: create (owned)", flush=True)

        u = upstream()
        u.sendall(rewrite(head) + body)
        relay(client, u)
        u.close()
    except Exception:
        pass
    finally:
        client.close()


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print("authz shim up -> %s:%d | allowed binds: %s | protected net: %s"
          % (UP_HOST, UP_PORT, ALLOWED, PROTECTED_NET), flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
