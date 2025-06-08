import math

def is_square(n):
    root = int(math.isqrt(n))
    return root * root == n

def fermat_factor(n):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    while not is_square(b2):
        a += 1
        b2 = a * a - n
    b = math.isqrt(b2)
    return a - b, a + b

if __name__ == "__main__":
    # Ví dụ: n = p * q với p và q gần nhau
    p = 1000003
    q = 1000033
    n = p * q

    print(f"🧪 Fermat attack on n = {n}")
    p, q = fermat_factor(n)
    print(f"✅ Found: p = {p}, q = {q}")
