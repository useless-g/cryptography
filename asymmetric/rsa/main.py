m, e = map(int, input('введите m и e\n').split(' '))
for i in range(2, m + 1):
    if m % i == 0:
        break
cipher = list(map(int, input('введите через пробел числа\n').split(' ')))
p = i
q = (m // p)
print(f"dividers of m is {p} & {q}")
fi = (p - 1) * (q - 1)
print(f"fi(m) = {fi}")
s = 1
while s % e:
    s += fi
pr_key = s // e
print(f"private key = {pr_key}")
answer = []
for char in cipher:
    d = char % m
    for i in range(2, pr_key + 1):
        d = char * d % m
        print(i, d)  # остатки при возведении в степень
    print(f"text = {d}")
    answer.append(d)
alphabet = 'абвгдежзийклмнопрстуфхцчшщъыьэюя'
answer = list(map(lambda x: alphabet[x - 2], answer))
print(''.join(answer))
