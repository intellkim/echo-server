import socket  # TCP 클라이언트 소켓
import json  # 헤더/args JSON 처리
import struct  # 길이 prefix pack/unpack
import hashlib  # sha256 계산
import os  # 파일 경로/이름 처리
import uuid  # request_id 생성(고유 ID)
from typing import Dict, Any, Tuple  # 타입 힌트

HOST = "127.0.0.1"  # 서버 IP
PORT = 9999         # 서버 포트

MAX_FRAME_SIZE = 64 * 1024 * 1024  # 프레임 최대 크기


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # bytes -> sha256 hex


def pack_frame(header: Dict[str, Any], payload: bytes = b"") -> bytes:
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")  # dict -> JSON bytes
    body = header_bytes + b"\n" + payload  # BODY = header + '\n' + payload
    if len(body) > MAX_FRAME_SIZE:  # 과대 프레임 방지
        raise ValueError("Frame too large")
    return struct.pack("!I", len(body)) + body  # 4바이트 길이 + BODY


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []  # 받은 조각들을 담을 리스트
    remaining = n  # 아직 받아야 할 바이트 수
    while remaining > 0:  # n바이트를 전부 받을 때까지 반복
        chunk = sock.recv(remaining)  # 남은 만큼 recv 시도
        if not chunk:  # 중간에 연결이 끊기면
            raise ConnectionError("Server closed connection")
        chunks.append(chunk)  # 조각 저장
        remaining -= len(chunk)  # 남은 길이 갱신
    return b"".join(chunks)  # 조각들을 합쳐서 반환


def recv_frame(sock: socket.socket) -> Tuple[Dict[str, Any], bytes]:
    hdr = recv_exact(sock, 4)  # 길이(prefix) 4바이트 먼저 받기
    (length,) = struct.unpack("!I", hdr)  # big-endian unsigned int로 해석
    if length > MAX_FRAME_SIZE:  # 비정상적으로 큰 메시지 방지
        raise ValueError(f"Frame length too large: {length}")

    body = recv_exact(sock, length)  # BODY를 length만큼 정확히 받기
    sep = body.find(b"\n")  # header/payload 구분자 찾기
    if sep == -1:  # 없으면 프로토콜 위반
        raise ValueError("Invalid body: missing header separator")

    header = json.loads(body[:sep].decode("utf-8"))  # header JSON 파싱
    payload = body[sep + 1:]  # 나머지 payload bytes
    return header, payload  # (dict, bytes)


def send_echo(sock: socket.socket, text: str):
    req_id = str(uuid.uuid4())  # 요청 ID 생성
    payload = text.encode("utf-8")  # 보낼 문자열을 bytes로
    header = {"type": "echo", "request_id": req_id}  # echo 요청 헤더
    sock.sendall(pack_frame(header, payload))  # 프레임으로 포장해 전송

    resp_h, resp_p = recv_frame(sock)  # 서버 응답 한 프레임 수신
    print("[client] resp header:", resp_h)  # 응답 헤더 출력
    print("[client] resp payload:", resp_p.decode("utf-8", errors="replace"))  # payload 출력


def upload_file(sock: socket.socket, path: str):
    req_id = str(uuid.uuid4())  # 요청 ID
    data = open(path, "rb").read()  # 파일 전체 읽기(대용량이면 chunk 방식 추천)
    filename = os.path.basename(path)  # 경로에서 파일명만 추출

    header = {  # 업로드 요청 헤더
        "type": "file_upload",
        "request_id": req_id,
        "filename": filename,
        "sha256": sha256_hex(data),  # 무결성 비교용: 클라가 계산한 sha256
    }
    sock.sendall(pack_frame(header, data))  # payload에 파일 바이트를 담아 전송
    resp_h, resp_p = recv_frame(sock)  # 응답 수신
    print("[client] resp header:", resp_h)  # 결과 출력
    if resp_p:  # (보통 upload 응답 payload는 비어있음)
        print("[client] resp payload bytes:", len(resp_p))


def download_file(sock: socket.socket, filename: str, out_path: str):
    req_id = str(uuid.uuid4())  # 요청 ID
    header = {"type": "file_download", "request_id": req_id, "filename": filename}  # 다운로드 요청 헤더
    sock.sendall(pack_frame(header, b""))  # payload는 없음(빈 bytes)

    resp_h, resp_p = recv_frame(sock)  # 응답 수신
    print("[client] resp header:", resp_h)  # 헤더 출력

    if not resp_h.get("ok"):  # 실패 응답이면(파일 없음 등)
        return  # 여기서 종료

    expected = resp_h.get("sha256")  # 서버가 준 sha256
    actual = sha256_hex(resp_p)  # 받은 payload의 sha256
    if expected and expected != actual:  # 불일치하면 경고
        print("[client] WARNING: sha256 mismatch!")
        print(" expected:", expected)
        print(" actual  :", actual)
    else:
        print("[client] sha256 OK")  # 일치하면 OK

    with open(out_path, "wb") as f:  # 저장 경로에 쓰기
        f.write(resp_p)  # 파일 바이트 저장
    print(f"[client] saved to {out_path} ({len(resp_p)} bytes)")  # 저장 완료 로그


def rpc_call(sock: socket.socket, method: str, args: Dict[str, Any]):
    req_id = str(uuid.uuid4())  # 요청 ID
    payload = json.dumps(args, ensure_ascii=False).encode("utf-8")  # args를 JSON payload로
    header = {  # RPC 요청 헤더
        "type": "rpc_request",
        "request_id": req_id,
        "method": method,
        "args_encoding": "json",
    }
    sock.sendall(pack_frame(header, payload))  # 프레임 전송

    resp_h, resp_p = recv_frame(sock)  # 응답 수신
    print("[client] resp header:", resp_h)  # 헤더 출력
    if resp_p:  # payload가 있으면
        try:
            print("[client] resp payload:", json.loads(resp_p.decode("utf-8")))  # JSON으로 출력 시도
        except Exception:
            print("[client] resp payload raw:", resp_p)  # 실패하면 raw로 출력


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:  # TCP 소켓 생성 + 자동 close
        print("[client] connecting to server...")
        client.connect((HOST, PORT))  # 서버에 TCP 연결(3-way handshake)
        print("[client] connected")

        while True:  # 메뉴 루프
            print("\nChoose:")
            print(" 1) Echo")
            print(" 2) Upload file")
            print(" 3) Download file")
            print(" 4) RPC ping")
            print(" 5) RPC add")
            print(" 0) Exit")
            choice = input("> ").strip()  # 사용자 입력

            if choice == "0":  # 종료
                break
            elif choice == "1":  # echo
                msg = input("send message: ")
                send_echo(client, msg)
            elif choice == "2":  # upload
                path = input("file path to upload: ").strip()
                upload_file(client, path)
            elif choice == "3":  # download
                name = input("filename on server: ").strip()
                out = input("save as (path): ").strip()
                download_file(client, name, out)
            elif choice == "4":  # rpc ping
                rpc_call(client, "ping", {"msg": "hello"})
            elif choice == "5":  # rpc add
                a = float(input("a: "))
                b = float(input("b: "))
                rpc_call(client, "add", {"a": a, "b": b})
            else:
                print("unknown option")  # 잘못된 입력 처리

    print("[client] connection closed")  # with 블록 끝나면서 소켓 close됨


if __name__ == "__main__":
    main()  # 직접 실행이면 main 호출