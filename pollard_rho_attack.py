import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def pollards_rho(n):
    if n % 2 == 0:
        return 2
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
        if d == n:
            return None
    return d

if __name__ == "__main__":
    # Ví dụ: n = p * q với p và q bất kỳ
    p = 1000003
    q = 1000033
    n = p * q

    print(f"🧪 Pollard Rho attack on n = {n}")
    d = pollards_rho(n)
    if d:
        print(f"✅ Found factor: d = {d}, n/d = {n // d}")
    else:
        print("❌ Attack failed.")
