from Crypto.Util.number import inverse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA 

n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = '7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476'
p = '151441473357136152985216980397525591305875094288738820699069271674022167902643'
q = '15624342005774166525024608067426557093567392652723175301615422384508274269305'

pp = ''
for i in range(len(p)):
    pp += p[i]
    pp += '0'
pp = pp[:-1]

qq = '1'
for i in range(len(q)):
    qq += q[i]
    qq += '0'
qq = qq[:-1] + '1'
print('p_start: ', pp)
print('q_start: ', qq)

assert(len(pp) == len(qq))

for i in range(len(pp)-2,0,-1):
    mod = 10**(len(pp)-i)
    if (len(pp)-i) % 2 == 0:
        j = 0
        while (int(qq[i:])*int(pp[i:])) % mod != n % mod:
            j += 1
            pp = pp[:i] + str(j) + pp[i+1:]
    else:
        j = 0
        while (int(qq[i:])*int(pp[i:])) % mod != n % mod:
            j += 1
            qq = qq[:i] + str(j) + qq[i+1:]

p = int(pp)
q = int(qq)
assert(p*q == n)
print('p = ', p)
print('q = ', qq)

e = 0x10001
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
rsa = RSA.construct((n,e,d))
cipher = PKCS1_OAEP.new(rsa)
message = cipher.decrypt(bytes.fromhex(ct))
print(message)