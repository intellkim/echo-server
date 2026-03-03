import socket  # 소켓 API (TCP/UDP)
import selectors  # select/poll을 OS에 맞게 추상화한 고수준 이벤트 루프
import json  # 헤더를 JSON으로 인코딩/디코딩
import struct  # 4바이트 길이(prefix) pack/unpack
import hashlib  # SHA-256 무결성 체크
import os  # 파일 저장 경로/디렉토리 처리
from dataclasses import dataclass, field  # 클라이언트 상태를 깔끔하게 관리
from typing import Dict, Any  # 타입 힌트

HOST = "127.0.0.1"  # 서버 바인딩 IP (localhost)
PORT = 9999         # 서버 포트

STORAGE_DIR = "./storage"  # 업로드된 파일을 저장할 폴더
os.makedirs(STORAGE_DIR, exist_ok=True)  # 폴더 없으면 생성 (있으면 무시)

MAX_FRAME_SIZE = 64 * 1024 * 1024  # 한 메시지(프레임) 최대 크기 제한(DoS 방어용): 64MB


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()  # 바이트를 SHA-256 해시(hex 문자열)로 반환


def pack_frame(header: Dict[str, Any], payload: bytes = b"") -> bytes:
    header_bytes = json.dumps(header, ensure_ascii=False).encode("utf-8")  # dict -> JSON 문자열 -> utf-8 bytes
    body = header_bytes + b"\n" + payload  # BODY = header_json + '\n' + payload
    if len(body) > MAX_FRAME_SIZE:  # 프레임이 너무 크면 거부
        raise ValueError("Frame too large")
    return struct.pack("!I", len(body)) + body  # FRAME = 4바이트 길이(네트워크 바이트 오더) + BODY


def try_unpack_frames(buf: bytearray):
    while True:  # 버퍼에서 가능한 만큼 프레임을 계속 꺼내기
        if len(buf) < 4:  # 길이(prefix) 4바이트가 아직 안 들어왔으면 대기
            return
        (length,) = struct.unpack("!I", buf[:4])  # 4바이트를 big-endian unsigned int로 해석
        if length > MAX_FRAME_SIZE:  # 비정상적으로 큰 프레임이면 프로토콜 위반
            raise ValueError(f"Frame length too large: {length}")
        if len(buf) < 4 + length:  # BODY 전체가 아직 안 들어왔으면 더 recv 필요
            return
        body = bytes(buf[4:4 + length])  # BODY만 잘라서 bytes로 복사
        del buf[:4 + length]  # 사용한 만큼 버퍼에서 제거 (앞부분 pop)
        yield body  # BODY를 호출자에게 넘김 (generator)


def split_header_payload(body: bytes):
    sep = body.find(b"\n")  # 헤더/페이로드 구분자('\n') 위치 찾기
    if sep == -1:  # 구분자가 없으면 프로토콜 위반
        raise ValueError("Invalid body: missing header separator")
    header = json.loads(body[:sep].decode("utf-8"))  # header 부분 bytes -> str -> dict
    payload = body[sep + 1:]  # 나머지는 payload bytes
    return header, payload  # (dict, bytes) 반환


@dataclass
class ClientState:
    addr: tuple  # (ip, port)
    inbuf: bytearray = field(default_factory=bytearray)  # 수신 누적 버퍼 (TCP는 스트림이라 조립 필요)
    outbuf: bytearray = field(default_factory=bytearray)  # 송신 대기 버퍼 (non-blocking이라 쌓아두고 나눠 보냄)
    closed: bool = False  # 이미 닫혔는지 플래그 (중복 close 방지)


class ToyServer:
    def __init__(self, host: str, port: int):
        self.sel = selectors.DefaultSelector()  # OS에 맞는 selector 생성(epoll/kqueue/select 등)
        self.host = host  # 저장
        self.port = port  # 저장

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4 + TCP 소켓 생성
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 재시작 시 포트 재사용 용이
        self.server_sock.setblocking(False)  # 이벤트 기반 처리를 위해 non-blocking
        self.server_sock.bind((self.host, self.port))  # (IP, PORT)에 바인딩
        self.server_sock.listen(socket.SOMAXCONN)  # 접속 대기 큐 최대치(가능한 크게)

        self.sel.register(self.server_sock, selectors.EVENT_READ, data=None)  # 서버 소켓은 "읽기=새 연결" 이벤트만 감시

        self.rpc_handlers = {  # toy RPC 메소드 테이블(디스패치)
            "ping": self.rpc_ping,
            "add": self.rpc_add,
            "echo": self.rpc_echo,
        }

    def run(self):
        print(f"[server] listening on {self.host}:{self.port}")  # 서버 시작 로그
        try:
            while True:  # 서버 메인 이벤트 루프
                for key, mask in self.sel.select(timeout=1.0):  # 준비된 이벤트들 가져오기(최대 1초 블록)
                    if key.data is None:  # data=None이면 서버 리스닝 소켓 이벤트
                        self.accept_client(key.fileobj)  # 새 클라 accept
                    else:  # data가 있으면 클라이언트 소켓 이벤트
                        self.service_client(key, mask)  # 읽기/쓰기 처리
        except KeyboardInterrupt:  # Ctrl+C
            print("\n[server] shutdown")
        finally:
            self.close_all()  # 종료 정리

    def close_all(self):
        try:
            self.sel.unregister(self.server_sock)  # selector에서 서버 소켓 해제
        except Exception:
            pass
        try:
            self.server_sock.close()  # 서버 소켓 닫기
        except Exception:
            pass

        for key in list(self.sel.get_map().values()):  # selector에 등록된 나머지 소켓들 순회
            if key.data is not None:  # 클라이언트 소켓만
                sock = key.fileobj  # 실제 소켓 객체
                try:
                    self.sel.unregister(sock)  # selector 해제
                except Exception:
                    pass
                try:
                    sock.close()  # 소켓 닫기
                except Exception:
                    pass
        try:
            self.sel.close()  # selector 자체 닫기
        except Exception:
            pass

    def accept_client(self, server_sock: socket.socket):
        conn, addr = server_sock.accept()  # 새 TCP 연결 수락 -> 연결용 소켓(conn) 생성
        conn.setblocking(False)  # 클라 소켓도 non-blocking
        state = ClientState(addr=addr)  # 클라 상태 객체 생성
        self.sel.register(conn, selectors.EVENT_READ, data=state)  # 처음엔 READ만 감시(보낼 게 생기면 WRITE도 추가)
        print(f"[server] connected by {addr}")  # 접속 로그

    def service_client(self, key, mask):
        sock: socket.socket = key.fileobj  # 이벤트 발생한 클라이언트 소켓
        state: ClientState = key.data  # 그 클라이언트의 상태(버퍼 등)
        try:
            if mask & selectors.EVENT_READ:  # 읽기 가능 이벤트
                self.read_from_client(sock, state)  # recv 및 프레임 파싱/처리
            if mask & selectors.EVENT_WRITE:  # 쓰기 가능 이벤트
                self.write_to_client(sock, state)  # outbuf에 있는 데이터를 send
        except (ConnectionResetError, BrokenPipeError):  # 상대가 강제 종료/파이프 깨짐
            self.disconnect(sock, state, "reset/broken")
        except ValueError as e:  # 프레임 크기/형식 오류 등 프로토콜 위반
            self.disconnect(sock, state, f"protocol error: {e}")
        except Exception as e:  # 그 외 예외
            self.disconnect(sock, state, f"error: {e}")

    def disconnect(self, sock: socket.socket, state: ClientState, reason: str):
        if state.closed:  # 이미 닫혔으면 중복 처리 방지
            return
        state.closed = True  # 닫힘 표시
        print(f"[server] disconnected {state.addr} ({reason})")  # 로그
        try:
            self.sel.unregister(sock)  # selector에서 해제
        except Exception:
            pass
        try:
            sock.close()  # 소켓 닫기
        except Exception:
            pass

    def update_interest(self, sock: socket.socket, state: ClientState):
        if state.closed:  # 닫힌 소켓이면 수정하지 않음
            return
        events = selectors.EVENT_READ  # 기본적으로 READ는 항상 감시(새 데이터 수신)
        if state.outbuf:  # 보내야 할 데이터가 있으면
            events |= selectors.EVENT_WRITE  # WRITE 이벤트도 감시(보낼 수 있을 때 전송)
        self.sel.modify(sock, events, data=state)  # 감시 이벤트 갱신

    def enqueue(self, sock: socket.socket, state: ClientState, header: Dict[str, Any], payload: bytes = b""):
        state.outbuf.extend(pack_frame(header, payload))  # 응답을 프레임으로 만들어 송신버퍼에 누적
        self.update_interest(sock, state)  # outbuf가 생겼으니 WRITE 감시 활성화

    def read_from_client(self, sock: socket.socket, state: ClientState):
        data = sock.recv(4096)  # non-blocking이지만 READ 이벤트가 왔으므로 보통 즉시 읽힘(최대 4096B)
        if not data:  # 빈 바이트면 정상 종료(FIN)로 연결 끊김
            self.disconnect(sock, state, "client closed")
            return
        state.inbuf.extend(data)  # 수신 데이터를 누적 버퍼에 추가(TCP는 조각나서 올 수 있음)

        for body in try_unpack_frames(state.inbuf):  # 누적 버퍼에서 완성된 프레임들을 하나씩 꺼내기
            header, payload = split_header_payload(body)  # BODY를 (header dict, payload bytes)로 분리
            self.handle_message(sock, state, header, payload)  # 메시지 타입에 따라 처리

        self.update_interest(sock, state)  # 처리 결과 outbuf가 생겼을 수 있으니 이벤트 갱신

    def write_to_client(self, sock: socket.socket, state: ClientState):
        if not state.outbuf:  # 보낼 게 없으면
            self.update_interest(sock, state)  # WRITE 감시 끄기
            return
        sent = sock.send(state.outbuf)  # outbuf에서 가능한 만큼만 전송(부분 전송 가능)
        del state.outbuf[:sent]  # 전송된 만큼 버퍼에서 제거
        self.update_interest(sock, state)  # 남은 outbuf 여부에 따라 WRITE 유지/해제

    # ---------------- handlers ----------------
    def handle_message(self, sock, state, header: Dict[str, Any], payload: bytes):
        mtype = header.get("type")  # 메시지 종류
        req_id = header.get("request_id")  # request/response 매칭용 ID

        if mtype == "echo":  # 에코 요청이면
            self.enqueue(sock, state, {  # 응답 헤더 구성
                "type": "echo_response",
                "request_id": req_id,
                "ok": True,
                "payload_len": len(payload),
            }, payload)  # payload 그대로 되돌려줌
            return

        if mtype == "file_upload":  # 파일 업로드
            return self.handle_file_upload(sock, state, header, payload)

        if mtype == "file_download":  # 파일 다운로드
            return self.handle_file_download(sock, state, header)

        if mtype == "rpc_request":  # RPC 호출
            return self.handle_rpc(sock, state, header, payload)

        # 여기까지 왔으면 모르는 타입 -> 에러 응답
        self.enqueue(sock, state, {
            "type": "error",
            "request_id": req_id,
            "ok": False,
            "error": f"unknown type: {mtype}",
        })

    def handle_file_upload(self, sock, state, header: Dict[str, Any], payload: bytes):
        req_id = header.get("request_id")  # 요청 ID
        filename = header.get("filename")  # 저장 파일명
        claimed = header.get("sha256")  # 클라가 주장하는 sha256(옵션)

        # 경로 조작 방지(../ 같은 걸 막기 위해 단순 검증)
        if not filename or "/" in filename or "\\" in filename:
            self.enqueue(sock, state, {
                "type": "file_upload_response",
                "request_id": req_id,
                "ok": False,
                "error": "invalid filename",
            })
            return

        path = os.path.join(STORAGE_DIR, filename)  # 저장 경로 구성
        with open(path, "wb") as f:  # 바이너리 쓰기 모드로 열고
            f.write(payload)  # payload를 파일로 저장

        actual = sha256_hex(payload)  # 실제 저장된 데이터의 sha256 계산
        ok = (claimed is None) or (claimed == actual)  # claimed가 없으면 ok, 있으면 일치 여부로 ok

        self.enqueue(sock, state, {  # 업로드 결과 응답
            "type": "file_upload_response",
            "request_id": req_id,
            "ok": ok,
            "filename": filename,
            "size": len(payload),
            "sha256": actual,
            "integrity": "match" if ok else "mismatch",
        })

    def handle_file_download(self, sock, state, header: Dict[str, Any]):
        req_id = header.get("request_id")  # 요청 ID
        filename = header.get("filename")  # 요청 파일명

        # 경로 조작 방지
        if not filename or "/" in filename or "\\" in filename:
            self.enqueue(sock, state, {
                "type": "file_download_response",
                "request_id": req_id,
                "ok": False,
                "error": "invalid filename",
            })
            return

        path = os.path.join(STORAGE_DIR, filename)  # 파일 경로 구성
        if not os.path.exists(path):  # 파일이 없으면
            self.enqueue(sock, state, {
                "type": "file_download_response",
                "request_id": req_id,
                "ok": False,
                "error": "file not found",
                "filename": filename,
            })
            return

        data = open(path, "rb").read()  # 파일 전체를 메모리로 읽음(대용량이면 chunk 방식으로 개선 필요)
        self.enqueue(sock, state, {  # 응답 헤더
            "type": "file_download_response",
            "request_id": req_id,
            "ok": True,
            "filename": filename,
            "size": len(data),
            "sha256": sha256_hex(data),
        }, data)  # payload에 파일 바이트를 담아 전송

    def handle_rpc(self, sock, state, header: Dict[str, Any], payload: bytes):
        req_id = header.get("request_id")  # 요청 ID
        method = header.get("method")  # 호출할 메소드 이름

        if method not in self.rpc_handlers:  # 등록되지 않은 메소드면
            self.enqueue(sock, state, {
                "type": "rpc_response",
                "request_id": req_id,
                "ok": False,
                "error": f"unknown method: {method}",
            })
            return

        try:
            args = json.loads(payload.decode("utf-8")) if payload else {}  # payload가 있으면 JSON args로 파싱
            result = self.rpc_handlers[method](args)  # 메소드 핸들러 호출
            resp_payload = json.dumps({"result": result}, ensure_ascii=False).encode("utf-8")  # 결과를 JSON으로
            self.enqueue(sock, state, {
                "type": "rpc_response",
                "request_id": req_id,
                "ok": True,
                "method": method,
                "result_encoding": "json",
            }, resp_payload)  # 성공 응답 + payload
        except Exception as e:  # 호출 중 에러
            self.enqueue(sock, state, {
                "type": "rpc_response",
                "request_id": req_id,
                "ok": False,
                "method": method,
                "error": str(e),
            })

    # ---------------- RPC methods ----------------
    def rpc_ping(self, args: Dict[str, Any]):
        return {"pong": True, "args": args}  # 단순 응답

    def rpc_add(self, args: Dict[str, Any]):
        a, b = args.get("a"), args.get("b")  # 인자 꺼내기
        if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):  # 타입 검증
            raise ValueError("a and b must be numbers")
        return a + b  # 합 반환

    def rpc_echo(self, args: Dict[str, Any]):
        return args  # 받은 args 그대로 반환


def main():
    ToyServer(HOST, PORT).run()  # 서버 객체 생성 후 run


if __name__ == "__main__":
    main()  # 스크립트 직접 실행 시 main 호출