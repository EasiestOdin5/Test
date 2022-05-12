def encryptChar(ochar, kchar):
    i = ord(ochar) - ord('A')
    j = ord(kchar) - ord('A')
    k = (i + j) % 26
    return chr(k + ord('A'))

def decryptChar(echar, kchar):
    i = ord(echar) - ord('A')
    j = ord(kchar) - ord('A')
    k = i - j
    if k < 0:
        k = k + 26
    return chr(k + ord('A'))


def encryptText(original, key):
    encrypted = ""
    for i in range(len(original)):
        e = encryptChar(original[i], key[i%len(key)])
        encrypted = encrypted + e
    return encrypted

def decryptText(encrypted, key):
    original = ""
    for i in range(len(encrypted)):
        o = decryptChar(encrypted[i], key[i%len(key)])
        original = original + o
    return original


out = encryptText("VERSAILLES", "CHEESE")
print(out)

out = decryptText(out, "CHEESE")
print(out)


out = encryptText("VERSAILLES", "PIZZA")
print(out)

out = decryptText("NVYZJI", "CHEESE")
print(out)

out = decryptText("NVSO", "CHEESE")
print(out)

message = "If an intercepter had"
message = message.upper().replace(" ", "")
print("Message:", message)
out = encryptText(message, "CHEESE")
print(out)

out = decryptText(out, "CHEESE")
print(out)
