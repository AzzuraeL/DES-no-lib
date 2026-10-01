"""
(receiver/listener):  python chat.py listen --port 5000 --key KUNCI123
(sender/connector):   python chat.py connect --host <IP_A> --port 5000 --key KUNCI123
"""
import argparse, socket, struct, sys, threading
import des

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup")
        buf += chunk
    return buf

def send_msg(sock, text, key):
    blob = des.encrypt(text.encode("utf-8"), key)
    print(f"   [SEND] plaintext : {text}")
    print(f"   [SEND] ciphertext: {blob[8:].hex().upper()} (IV={blob[:8].hex().upper()})")
    sock.sendall(struct.pack(">I", len(blob)) + blob)

def receiver_loop(sock, key, peer):
    try:
        while True:
            (n,) = struct.unpack(">I", recv_exact(sock, 4))
            blob = recv_exact(sock, n)
            print(f"\n   [RECV] ciphertext: {blob[8:].hex().upper()} (IV={blob[:8].hex().upper()})")
            try:
                print(f"   [RECV] plaintext : {des.decrypt(blob, key).decode('utf-8')}   (dari {peer})")
            except Exception as e:
                print(f"   [RECV] gagal dekripsi: {e}")
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        print("\n[!] Lawan bicara terputus.")
        try: sock.close()
        except OSError: pass
        import os; os._exit(0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["listen", "connect"])
    ap.add_argument("--host", default="0.0.0.0", help="IP tujuan (connect) / bind (listen)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", required=True, help="Key DES: 8 karakter ASCII, atau 16 digit hex")
    a = ap.parse_args()

    key = bytes.fromhex(a.key) if len(a.key) == 16 and all(c in "0123456789abcdefABCDEF" for c in a.key) else a.key.encode()
    if len(key) != 8:
        sys.exit("Key harus 8 byte (8 karakter ASCII atau 16 hex).")

    if a.mode == "listen":
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((a.host, a.port)); srv.listen(1)
        print(f"[*] Menunggu koneksi di {a.host}:{a.port} ...")
        sock, addr = srv.accept()
    else:
        sock = socket.create_connection((a.host, a.port)); addr = (a.host, a.port)
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] Tersambung dengan {peer}. Ketik pesan lalu Enter.")

    threading.Thread(target=receiver_loop, args=(sock, key, peer), daemon=True).start()
    try:
        while True:
            line = input("> ")
            if line.strip().lower() == "exit": break
            if line: send_msg(sock, line, key)
    except (EOFError, KeyboardInterrupt):
        pass
    sock.close()

if __name__ == "__main__":
    main()
