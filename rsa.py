import secrets
import hashlib
import base64

size = 1024
rnds = 100


def MRprim(n,k):    # Confere se é provavelmente primo, retorna 0 se prova que é composto, 1 se não conseguiu provar. n é o número, k a quantidade de iterações 
    n1 = n -1
    s = 0
    while (n1 % 2 == 0):    # Dividindo por 2 até encontrar resto 0 para conhecer o expoente
        s += 1
        n1 = n1 // 2
    d = n1
    for i in range(k):
        a = secrets.randbelow(n-4) + 2  # Pegando número aleatório entre 2 e n-2
        
        x = pow(a,d,n)
        y = 0
        for j in range(s):
            y = pow(x,2,n)
            if (y == 1) and (x != 1) and (x != n-1):
                return 0    # Composto
            x = y
        if y != 1:
            return 0    # Composto
    return 1    # Provavelmente primo

def genprime():     # Gera um número aleatório de 1024 bits e checa se é primo, continuando a gerar até confirmar que é
    check = 0
    p = secrets.randbits(size)
    while (p < 2) or (p % 2 == 0):
        p = secrets.randbits(size)
    count = 0
    while check == 0:
        count += 1
        check = MRprim(p,rnds)
        if check == 1:
            break
        p = secrets.randbits(size)
        while (p < 2) or (p % 2 == 0):
            p = secrets.randbits(size)
    return p

def gcdeuclid(p,q): # Pega o GCD pelo algoritmo de Eulid
    rem = 1
    while rem > 0:
        g = max(p,q)
        l = min(p,q)
        rem = g % l
        p = rem
        q = l
    return l

def euclidexp(a,b): # Algoritmo de Euclid Expandido
    rs = sorted([a,b],reverse=True)
    ss = [1,0]
    ts = [0,1]
    r = 1
    t = 0
    s = 0
    q = 0
    pos = 1
    while r > 0:
        q = (rs[(pos-1)%2]//rs[pos])
        r = rs[(pos-1)%2] - q * rs[pos]
        s = ss[(pos-1)%2] - q * ss[pos]
        t = ts[(pos-1)%2] - q * ts[pos]
        pos = (pos + 1) % 2
        rs[pos] = r
        ss[pos] = s
        ts[pos] = t
    r = rs[(pos-1)%2]
    s = ss[(pos-1)%2]
    t = ts[(pos-1)%2]
    if a > b:
        return [r,s,t]
    else:
        return [r,t,s]

        
def genrsakeys(p,q):    # Gera as chaves usando p,q e o algoritmo de euclid
    n = p * q
    lcm = ((p-1)*(q-1))//gcdeuclid((p-1),(q-1))
    if lcm < 0:
        lcm = - lcm
    e = 65537
    euc =  euclidexp(e,lcm)
    if (((euc[1] * e) + (euc[2] * lcm)) != 1):
        print("Error in finding d")
    d = euc[1]
    return n,e,d

def HASH(M):    # Converte um valor inteiro em bytes e faz o HASH com sha3_256
    return hashlib.sha3_256(bytes(M,'utf-8')).digest()

def MGF(Z,length):  # Função geradora de máscara, que atua como um hash com output de tamanho desejado
    if length > pow(2,32) * 32:     # Caso o tamanho fosse maior do que esse número, dá erro, mas não deve acontecer
        print("Erro: máscara grande demais")
        return -1
    T = b''
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4,'big')
        T = T + hashlib.sha3_256(Z+C).digest()
    return T[:length]

def OAEP(MGF,HASH,hlen,k,M,L): # Toma como argumento a função MGF, a função de HASH, o comprimento do retorno de hash (32), o comprimento de n no RSA (1024), a mensagem M e uma label L que nesse caso é ''
    lhash = HASH(L)
    
    mlen = len(M)  
    PS = bytes(k - mlen - 2*hlen - 2)
    DB = lhash + PS + bytes([1]) + M
    seed = secrets.randbits(8*hlen).to_bytes(hlen,'big')
    dbMask = MGF(seed,k-hlen-1)
    maskDB = bytes(a ^ b for a, b in zip(dbMask, DB)) 
    seedMask = MGF(maskDB,hlen)
    maskseed = bytes(a ^ b for a, b in zip(seedMask, seed ))
    return bytes(1) + maskseed + maskDB # Tem tamanho K

def deOAEP(MGF,HASH,hlen,k,EM,L):
    lhash = HASH(L)
    mlen = k -2*hlen -2
    maskseed = EM[1:hlen+1]
    maskDB = EM[hlen+1:]
    seedMask = MGF(maskDB,hlen)
    seed = bytes(a ^ b for a, b in zip(seedMask, maskseed ))
    DBmask = MGF(seed,k-hlen-1)
    DB = bytes(a ^ b for a, b in zip(maskDB, DBmask)) 
    pslen = -1
    i = hlen
    crntbyte = b'0'
    while crntbyte != 1:    # Encontrando PSlen
        crntbyte = DB[i]
        i += 1
        pslen += 1
    lhash2,PS2,pad,M = DB[:hlen],DB[hlen:hlen+pslen], DB[hlen+pslen], DB[hlen+pslen+1:]
    PS = bytes(pslen)
    if lhash != lhash2 or PS != PS2 or pad != 1:    # Checando se os hashes são diferentes, se o segmento PS2 é igual a uma sequencia de bytes 0 de tamanho pslen e se o padding é diferente de 1
        print(lhash != lhash2,PS != PS2, pad != 1)
        print("Erro: Hash não confere")
        return -1
    else:
        return M

def RSA(pm,n,e):
    c = pow(int.from_bytes(pm),e,n) # Funciona para a  criptografia e decriptografia
    return c.to_bytes(256,'big')

def signMsg(msg, private_key):
    hash_bytes = hashlib.sha3_256(msg.encode('utf-8')).digest() 
    n, d = private_key
    padmsg = OAEP(MGF,HASH,32,256,hash_bytes,'')
    sign_byte = RSA(padmsg,n,d)
    assinatura_b64 = base64.b64encode(sign_byte).decode('utf-8') #Converte para base64

    return assinatura_b64

def verifySign(msg, b64, public_key): #Verifica se a assinatura está correta
    sign_bytes = base64.b64decode(b64) #Transforma a string em base64 para byte
    n, e = public_key

    decbytes = RSA(sign_bytes,n,e)
    hash_bytes  = deOAEP(MGF,HASH,32,256,decbytes,'')
    
    hash_msg = hashlib.sha3_256(msg.encode('utf-8')).digest() #Calcula o hash da mensagem em claro

    return hash_bytes[-len(hash_msg):] == hash_msg #Compara o hash decifrado com o hash da mensagem olhando os últimos bytes.

# START
def RSAexec():
    p = genprime()
    q = genprime()  # Gera p e q primos
    n,e,d = genrsakeys(p,q) # Obtém as chaves usando p e q
    public_key = (n,e)
    private_key = (n,d)
    print("Public Key:\nn:",n,'\ne:',e)
    print()
    print("Private Key:\nd:",d)
    print()
    print('Enter Message:',end='')
    tempM = input()     # Pega a mensagem
    hlen = 32 
    k = 2048    # Comprimento doo produto de 2 números de 1024 bits
    mlen = k//8 -2*hlen -2 # mlen é o comprimento máximo de M para um OAEP de um RSA com n de tamanho k e usando hash de output tamanho hlen
    Mlist = []
    Msize = len(tempM)

    if  Msize  > mlen:      # Se a mensagem é grande demais,separa em partes menores
        i = 1
        while i * mlen < Msize:
            newM = []
            for j in range(mlen):
                newM.append(tempM[j + (i-1)*mlen])
            Mlist.append(''.join(newM)) # Convertendo a lista e string e colocando na lista
            i+= 1
        base = (i-1)*mlen
        if base != Msize:   # Pegando o resto dos caractéres que não estão em um bloco completo
            limit = Msize - base
            newM = []
            for j in range(limit):
                newM.append(tempM[j + base])
            Mlist.append(''.join(newM))
    else:
        Mlist.append(tempM)
    Clist = []
    for M in Mlist:
        PM = OAEP(MGF,HASH,hlen,k//8,bytes(M,'utf-8'),'')      # Obtendo a mensagem com padding
        C = RSA(PM,private_key[0],private_key[1]) # Obtendo mensagem assinada
        Clist.append(PM)        # Colocando na lista de Mensagens criptografadas
        dM = RSA(C,public_key[0],public_key[1])   # Decriptografando a mensagem
        deM = deOAEP(MGF,HASH,hlen,k//8,dM,'')  # Removendo o padding
        print(bytes(M,'utf-8'))
        print()
        print(deM)  # Imprimindo ambas as mensagens para conferir que são iguais (a segunda é retornada com b'', mas o conteúdo é identico)
    
    sign64 = signMsg(tempM, private_key)
    print("Assinatura base64 = " + sign64)
    print("Assinatura válida? ", verifySign(tempM, sign64, public_key))
    return Mlist,Clist


Mlist, Clist = RSAexec()
