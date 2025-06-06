import time
import socket
import os

SECRET_PASSWORD = "secret23"
PER_CHAR_DELAY = 0.05 

def vulnerable_password_check(supplied_password):
    if len(supplied_password) > len(SECRET_PASSWORD):
        time.sleep(len(SECRET_PASSWORD) * PER_CHAR_DELAY)
        return False

    for i in range(len(supplied_password)):
        if supplied_password[i] == SECRET_PASSWORD[i]:
            time.sleep(PER_CHAR_DELAY)  
        else:
            return False
    if len(supplied_password) == len(SECRET_PASSWORD):
        return True
    return False 

def main():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
    except socket.error as e:
        print(f"Lỗi bind socket: {e}")
        os._exit(1)

    server_socket.listen(5)
    print(f"[*] Server đang lắng nghe trên {host}:{port}")
    print(f"[*] Mật khẩu bí mật là: {SECRET_PASSWORD} (chỉ để tham khảo demo)")
    print(f"[*] PER_CHAR_DELAY được đặt là: {PER_CHAR_DELAY} giây")

    try:
        while True:
            print(f"\n[*] Đang chờ kết nối mới...")
            conn, addr = server_socket.accept()
            print(f"[*] Kết nối mới từ: {addr}")

            try:
                while True:
                    data = conn.recv(1024).decode().strip()
                    if not data:
                        print(f"[-] Client {addr} đã ngắt kết nối.")
                        break

                    print(f"[+] {addr} thử: {data}")

                    if vulnerable_password_check(data):
                        response = "ACCESS_GRANTED"
                        print(f"[*] {addr} - Mật khẩu đúng! ({data})")
                    else:
                        response = "ACCESS_DENIED"
                        print(f"[*] {addr} - Mật khẩu sai. ({data})")
                    conn.sendall(response.encode())
            except ConnectionResetError:
                print(f"[-] Client {addr} đã reset kết nối đột ngột.")
            except Exception as e:
                print(f"[!] Lỗi khi xử lý client {addr}: {e}")
            finally:
                print(f"[-] Đóng kết nối với {addr}.")
                conn.close()
    except KeyboardInterrupt:
        print("\n[*] Server đang tắt do KeyboardInterrupt...")
    finally:
        server_socket.close()
        print("[-] Server đã đóng hoàn toàn.")

if __name__ == "__main__":
    main()