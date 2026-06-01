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
# cross-container namespaces, no host bind mounts outside the workspace, and it may
# not attach to the proxy ("gate") network. Every container the shim creates is
# stamped with a label; `docker exec` is permitted ONLY into containers carrying that
# label. Anything it cannot parse is denied (fail closed).
#
# Networks are per-devcontainer (Compose scopes them to the project), so the gate
# network's name is dynamic. The shim recognises it two ways: by Compose suffix
# (".._gate"), and by discovering the gate network's real name AND id at runtime
# (it resolves the proxy's address and finds which network it sits on) -- so joining
# the gate by network id can't slip past a name-only check.
import json, os, re, socket, select, threading, time

UP_HOST = os.environ.get("UPSTREAM_HOST", "docker-endpoint-proxy")
UP_PORT = int(os.environ.get("UPSTREAM_PORT", "2375"))
LISTEN  = ("0.0.0.0", 2375)
ALLOWED = [p for p in os.environ.get("ALLOWED_BIND_PREFIXES", "").split(":") if p]
OWN_LABEL = "authz.owned"
GATE_RE = re.compile(os.environ.get("GATE_NET_PATTERN", r"(^|[-_])gate$"))

CREATE_RE  = re.compile(r"^/(v[\d.]+/)?containers/create(\?|$)")
EXEC_RE    = re.compile(r"^/(v[\d.]+/)?containers/([^/]+)/exec(\?|$)")
CONNECT_RE = re.compile(r"^/(v[\d.]+/)?networks/([^/]+)/connect(\?|$)")


# ---- upstream helpers -------------------------------------------------------
def upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((UP_HOST, UP_PORT))
    return s


def _extract_json(body):
    starts = [i for i in (body.find(b"{"), body.find(b"[")) if i != -1]
    ends   = [i for i in (body.rfind(b"}"), body.rfind(b"]")) if i != -1]
    if not starts or not ends:
        raise ValueError("no json in response")
    return json.loads(body[min(starts):max(ends) + 1])


def http_get_json(path):
    u = upstream()
    try:
        u.sendall(("GET %s HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n" % path).encode())
        resp = b""
        while True:
            c = u.recv(65536)
            if not c:
                break
            resp += c
    finally:
        u.close()
    return _extract_json(resp.split(b"\r\n\r\n", 1)[1])


# ---- gate-network discovery (cached) ---------------------------------------
_gate_cache = set()
_gate_lock = threading.Lock()


def discover_gate():
    """Return {name, id} of the network the upstream proxy lives on, or empty."""
    try:
        proxy_ip = socket.gethostbyname(UP_HOST)
    except Exception:
        return set()
    out = set()
    try:
        nets = http_get_json("/networks")
    except Exception:
        return out
    for n in nets:
        nid = n.get("Id")
        if not nid:
            continue
        try:
            detail = http_get_json("/networks/%s" % nid)
        except Exception:
            continue
        for c in (detail.get("Containers") or {}).values():
            if (c.get("IPv4Address") or "").split("/")[0] == proxy_ip:
                if n.get("Name"):
                    out.add(n["Name"])
                out.add(nid)
                return out
    return out


def gate_ids():
    global _gate_cache
    if _gate_cache:
        return _gate_cache
    with _gate_lock:
        if not _gate_cache:
            found = discover_gate()
            if found:
                _gate_cache = found
                print("discovered gate network:", found, flush=True)
            return found
        return _gate_cache


def is_gate_net(name):
    if not name:
        return False
    if GATE_RE.search(name):     # Compose suffix, e.g. <project>_gate (any project)
        return True
    if name in gate_ids():       # discovered name OR id (defeats join-by-id)
        return True
    return False


def network_is_gate(net):
    """True if network `net` currently hosts the upstream proxy. Backstop for the
    `network connect` path: catches the gate by membership even if the suffix
    pattern and the discovery cache both miss (e.g. join-by-raw-id pre-discovery)."""
    try:
        proxy_ip = socket.gethostbyname(UP_HOST)
        detail = http_get_json("/networks/%s" % net)
    except Exception:
        return False
    for c in (detail.get("Containers") or {}).values():
        if (c.get("IPv4Address") or "").split("/")[0] == proxy_ip:
            return True
    return False


# ---- create policy ----------------------------------------------------------
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
    if is_gate_net(nm):                                return "joins the gate network: " + nm
    for net in (cfg.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}:
        if is_gate_net(net):                           return "attaches to the gate network: " + net
    for opt in hc.get("SecurityOpt") or []:
        if "unconfined" in opt or "no-new-privileges:false" in opt.replace(" ", ""):
            return "weakens confinement: " + opt
    for b in hc.get("Binds") or []:
        if not bind_ok(b.split(":")[0]):   return "bind outside workspace: " + b
    for m in hc.get("Mounts") or []:
        if m.get("Type") == "bind" and not bind_ok(m.get("Source", "")):
            return "bind outside workspace: " + m.get("Source", "")
    return None


def target_is_ours(cid):
    try:
        data = http_get_json("/containers/%s/json" % cid)
        return ((data.get("Config") or {}).get("Labels") or {}).get(OWN_LABEL) == "1"
    except Exception:
        return False                           # fail closed


# ---- HTTP plumbing ----------------------------------------------------------
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

        mc = CONNECT_RE.match(path)
        m = EXEC_RE.match(path)
        if method == b"POST" and mc:
            net = mc.group(2)
            if is_gate_net(net) or network_is_gate(net):
                return deny(client, "connect a container to the gate network: " + net)
        elif method == b"POST" and m:
            if not target_is_ours(m.group(2)):
                return deny(client, "exec into a container we don't own")
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
    print("authz shim up -> %s:%d | allowed binds: %s | gate pattern: %s"
          % (UP_HOST, UP_PORT, ALLOWED, GATE_RE.pattern), flush=True)
    # Discover the gate network up front so a join-by-raw-id is caught from the
    # very first request (the suffix pattern alone wouldn't catch a raw id). The
    # upstream proxy may not be reachable the instant we start, so retry briefly.
    for _ in range(20):
        if gate_ids():
            break
        time.sleep(0.5)
    else:
        print("WARNING: gate network not discovered yet; until it is, only the "
              "suffix pattern guards join-by-id (raw-id joins/connects to a gate "
              "network created with a non-matching name could slip through)",
              flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
