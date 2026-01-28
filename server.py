import socket

HOST = "127.0.0.1"  # localhost
PORT = 9999         # 사용할 포트

def main():
    # TCP 소켓 생성 (IPv4, TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # 서버 재시작할 때 "Address already in use" 덜 나게 해줌
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # (IP, Port)에 바인딩 후, 연결 대기 시작
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[server] listening on {HOST}:{PORT}")

        # 클라이언트 1명 접속 대기 → 접속되면 연결 소켓(conn) 생성됨
        conn, addr = server.accept()
        with conn:
            print(f"[server] connected by {addr}")

            # 클라이언트가 보내는 데이터를 받아서 그대로 다시 보냄
            while True:
                data = conn.recv(1024)
                if not data:
                    print("[server] client disconnected")
                    break

                print(f"[server] recv: {data!r}")
                conn.sendall(data)
                print(f"[server] sent: {data!r}")

if __name__ == "__main__":
    main()