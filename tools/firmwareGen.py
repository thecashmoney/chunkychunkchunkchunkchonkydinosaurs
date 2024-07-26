# with open("firmware.bin", "w") as f:
#     letter = 97
#     for i in range(26):
#         for j in range(500):
#             f.write(chr(letter))
#         letter += 1

# with open("firmware.bin", "w") as f:
#     f.write("CHUUNDFKSNKDNKNKCHUNK")

with open("firmware.bin", "wb") as f:
    f.write(("a"*477).encode('ascii'))