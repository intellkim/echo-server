import socket

HOST = "127.0.0.1"  # 서버 IP
PORT = 9999         # 서버 포트

def main():
    # TCP 소켓 생성
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        print("[client] connecting to server...")
        client.connect((HOST, PORT))
        print("[client] connected")

        # 서버로 보낼 메시지
        message = input("send message: ")
        client.sendall(message.encode())

        # 서버로부터 echo 수신
        data = client.recv(1024)
        print(f"[client] received: {data.decode()}")

    print("[client] connection closed")

if __name__ == "__main__":
    main()
