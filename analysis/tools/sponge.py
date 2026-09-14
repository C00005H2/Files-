#!/usr/bin/env python3
# Sponge (keystretcher/MAC) model for crackme.exe.
#
# VERIFIED byte-exact vs emulator capture (test123, all 6 rounds of iter 1):
#   RD-1..RD-6 (0x5E20 entry states) + F1/B60/PW intermediate states.
#
# Structure:
#   0x60B0(state, r11, off):
#     - operates on the fixed 8-byte window at state[r11..r11+7] (r11 = 5th arg,
#       0 for the low window, 8 for the high window).
#     - swap s[win..win+3] <-> s[win+4..win+7]
#     - a'=rotl8(a+b,b&7)^T1[off%8]
#     - b'=rotl8(b+D,c&7)
#     - c'=rotl8(c-d,d&7)^T2[off%8]
#     - d'=rotl8(c'+d,A&7)^T1[(off+3)%8]
#     (a,b,c,d = s[win..win+3] post-swap; A=s[win+4], D=s[win+7])
#   0x5E20(state, counter):
#     - 0x60B0(state, r11=0, off=counter)   (low window)
#     - 0x60B0(state, r11=8, off=counter)   (high window)
#     - pairwise rots: for i in 0..7:
#         s[8+i]=rotl8(s[8+i], s[i]&7); s[i]=rotl8(s[i], s[8+i]&7)  (NEW s[8+i])
#   0x5C10(state, key16, loopbound):  (key = buf[16..31])
#     - state ^= key16
#     - for lv in 0..loopbound-1: 0x5E20(state, lv)
#   0x65A0 driver (VERIFIED byte-exact, r14=0x3e8=1000 iters):
#     buf40 = pw + 0x80 + zeros(40-n-1)          (built by 0x9b80 into [rsp+0x60])
#     prev = 0 (16B; xmm1 cleared pre-loop)
#     for i in 0..999:
#       state = buf40[0..15] ^ prev              (0x6611: xmm0=xmm6; 0x6617: xmm0^=xmm1; xmm6=buf40[0..15] const)
#       6x 0x5E20(state, ctr=0..5)               (0x6620 loop, ret 0x663b)
#       0x5C10(state, key=buf40[16..31], lb=6)   (0x6662; state^=key then 6x 0x5E20)
#       state[0..7] ^= buf40[32..39]             (0x6667-0x66bc; upper 8B ^= 0, see 0x660c)
#       6x 0x5E20(state, ctr=0..5)               (0x66c2 loop, ret 0x66dd)
#       prev = state                             (0x66ea: xmm1=[rsp+0x40])
#     MAC = prev -> [rdi+0x140]                  (0x6703 xmm6=state; 0x6937 movups [rdi+0x140],xmm6)
#     Also stored: [rdi+0x150]=buf40[16..31], [rdi+0x160]=buf40[32..39], [rdi+0x168]=0x80
#   => MAC(pw) byte-exact: test123 -> cc32b406bbfcacc658bcf662cca61c23, aaaaaaaa -> 8929fc1347a4b5db644e5ba5f47067cf

# Tables (CONFIRMED, dumped at runtime 0x2B628 / 0x2B630)
T1 = bytes.fromhex('6c9f1ab735e3487d51132bc78eb24f63')
T2 = bytes.fromhex('51132bc78eb24f63c93bbd119443ebdf')

def rotl8(v, k):
    k &= 7
    return v if k == 0 else ((v << k) | (v >> (8 - k))) & 0xFF

def f60b0_win(s, win, off, t1=T1, t2=T2):
    """0x60B0 on the fixed 8-byte window at s[win..win+7]; table index = off."""
    s = bytearray(s); b = win
    for k in range(4):
        s[b+k], s[b+4+k] = s[b+4+k], s[b+k]
    a, bv, c, d = s[b], s[b+1], s[b+2], s[b+3]
    A, D = s[b+4], s[b+7]
    an = rotl8((a+bv)&0xff, bv&7) ^ t1[off % 8]
    bn = rotl8((bv+D)&0xff, c&7)
    cn = rotl8((c-d)&0xff, d&7) ^ t2[off % 8]
    dn = rotl8((cn+d)&0xff, A&7) ^ t1[(off+3) % 8]
    s[b], s[b+1], s[b+2], s[b+3] = an, bn, cn, dn
    return bytes(s)

def pairwise_rots(s):
    """for i in 0..7: s[8+i]=rotl8(s[8+i], s[i]&7); s[i]=rotl8(s[i], s[8+i]&7) (NEW)."""
    s = list(s)
    for i in range(8):
        s[8+i] = rotl8(s[8+i], s[i] & 7)
        s[i]   = rotl8(s[i], s[8+i] & 7)
    return bytes(s)

def f5e20(s, counter):
    """0x5E20(state, counter) = low 0x60B0 + high 0x60B0 + pairwise rots."""
    s = f60b0_win(s, 0, counter)
    s = f60b0_win(s, 8, counter)
    return pairwise_rots(s)

def f5c10(s, key, loopbound):
    """0x5C10(state, key16, loopbound): state ^= key; loop(0x5E20(lv)). [to verify]"""
    s = bytes(a ^ b for a, b in zip(s, key))
    for lv in range(loopbound):
        s = f5e20(s, lv)
    return s

def mac(password: bytes, iters=1000):
    """Compute the MAC for a password. Returns (mac16, prev).

    Driver (VERIFIED byte-exact vs emulator: test123, aaaaaaaa):
      buf40 = pw + 0x80 + zeros;  prev = 0
      for i in 0..iters-1:
        state = buf40[0..15] ^ prev        (Feistel feedback, 0x6611-0x661a)
        6x 0x5E20(ctr=0..5)
        0x5C10(key=buf40[16..31], lb=6)
        state[0..7] ^= buf40[32..39]
        6x 0x5E20(ctr=0..5)
        prev = state
      MAC = prev
    Total work per password: iters x (12 x 0x5E20 + 6 x 0x5E20) = iters x 18 rounds.
    """
    buf = bytearray(40)
    n = len(password)
    if n > 39:
        raise ValueError("password too long")
    buf[:n] = password
    buf[n] = 0x80
    head = bytes(buf[0:16])
    key = bytes(buf[16:32])
    tail = buf[32:40]
    prev = bytes(16)
    for _ in range(iters):
        state = bytes(a ^ b for a, b in zip(head, prev))
        for ctr in range(6):
            state = f5e20(state, ctr)
        state = f5c10(state, key, 6)
        if any(tail):
            tb = bytearray(state)
            for k in range(8):
                tb[k] ^= tail[k]
            state = bytes(tb)
        for ctr in range(6):
            state = f5e20(state, ctr)
        prev = state
    return prev[:16], prev

if __name__ == '__main__':
    # Self-test against the captured trace (test123, iter 1).
    trace = [bytes.fromhex(h) for h in [
        '74657374313233800000000000000000',  # RD-1 (init)
        'e1355c3274657374d80045cd00000000',  # RD-2
        '49cbd95fc335c519f9dc31c4b1005437',  # RD-3
        'a0259c9e4af2677d753196a5f3e66262',  # RD-4
        '47124dd71449393de02e1fb675266969',  # RD-5
        '1f80226947126abee9b91d2a70b8e35b',  # RD-6
        '1ab733e3f1012296f2e2ed67f4b97454',  # after 6th round (PW-6)
    ]]
    s = trace[0]; ok = True
    for i in range(6):
        s = f5e20(s, i)
        m = s == trace[i+1]
        ok = ok and m
        print(f"round {i}: {'OK' if m else 'MISMATCH'} got={s.hex()}")
    print("ALL 6 ROUNDS MATCH:", ok)
    # Full MAC (byte-exact vs emulator captures)
    for pw, want in [(b'test123', 'cc32b406bbfcacc658bcf662cca61c23'),
                     (b'aaaaaaaa', '8929fc1347a4b5db644e5ba5f47067cf')]:
        m, _ = mac(pw)
        print(f"MAC({pw.decode()}) = {m.hex()} ({'OK' if m.hex()==want else 'MISMATCH, want '+want})")
