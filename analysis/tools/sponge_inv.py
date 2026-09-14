import sys, json
sys.path.insert(0,'analysis/tools')
from sponge import T1, T2, rotl8, f5e20, f60b0_win, pairwise_rots, f5c10

def rotr8(v,k):
    k&=7; v&=0xff
    return v if k==0 else ((v>>k)|(v<<(8-k)))&0xff

def inv60b0(s, win, off):
    s=bytearray(s); b=win
    # output window: s[b..b+3]=(a',b',c',d'), s[b+4..b+7]=(p,q,r,t) = original first half
    ap,bp,cp,dp = s[b],s[b+1],s[b+2],s[b+3]
    p,q,r,t = s[b+4],s[b+5],s[b+6],s[b+7]
    # recover original second half (a,b,c,d)
    x = rotr8(dp ^ T1[(off+3)%8], p&7)      # = c'+d
    d = (x - cp) & 0xff
    y = rotr8(cp ^ T2[off%8], d&7)          # = c-d
    c = (y + d) & 0xff
    z = rotr8(bp, c&7)                      # = b+t
    bb = (z - t) & 0xff
    w = rotr8(ap ^ T1[off%8], bb&7)         # = a+b
    a = (w - bb) & 0xff
    out=bytearray(s)
    out[b],out[b+1],out[b+2],out[b+3] = p,q,r,t
    out[b+4],out[b+5],out[b+6],out[b+7] = a,bb,c,d
    return bytes(out)

def inv_pairwise(s):
    s=list(s)
    for i in range(7,-1,-1):
        s[i]   = rotr8(s[i], s[8+i]&7)
        s[8+i] = rotr8(s[8+i], s[i]&7)
    return bytes(s)

def inv5e20(s, counter):
    s=inv_pairwise(s)
    s=inv60b0(s,8,counter)
    s=inv60b0(s,0,counter)
    return s

def invA(s):
    """inverse of one sponge iteration body: 6x5e20 + xor tail + 5c10(key) + 6x5e20"""
    for c in range(5,-1,-1): s=inv5e20(s,c)
    return s

# self-test: inv(f5e20(x,c)) == x
import os
x=os.urandom(16)
for c in range(6):
    assert inv5e20(f5e20(x,c),c)==x, ("5e20 inv fail",c)
print("inv5e20 self-test OK")
# test inv60b0 alone
for w in (0,8):
    for c in range(9):
        assert inv60b0(f60b0_win(x,w,c),w,c)==x
print("inv60b0 self-test OK")
