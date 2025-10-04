from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
cache = {}
def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  # creating a query
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  # sends the query via UDP
  # print("\nDNS query", repr(q))
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  # waiting for a response up to 8192 bytes
  pkt, _ = udp_socket.recvfrom(8192)
  # the response that can be parsed easily
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """
  
  header = DNSHeader.parse(buff)
  # print("DNS header", repr(header))
  # ensures the the transaction ID in the response is the same that we sent
  if q.header.id != header.id:
    print("Unmatched transaction.")
    return
  # Checks to see if there was an error
  if header.rcode != RCODE.NOERROR:
    print("Query failed.")
    return
  if header.rcode == RCODE.NXDOMAIN:
    print(f'{domain} is not a valid domain.')
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    print(f"Question-{k} {repr(q)}")
    
  # Parse the answer section #3
  answers = []
  for k in range(header.a):
    a = RR.parse(buff)
    # for authoritative response
    if a.rtype == QTYPE.A:
      answers.append((QTYPE[a.rtype], str(a.rname), str(a.rdata)))
    if a.rtype == QTYPE.NS:
      answers.append((QTYPE[a.rtype], str(a.rname), str(a.rdata)))
      # print(f"\n{a}\n")
    if a.rtype == QTYPE.CNAME:
      targ = str(a.rdata)
      print(f"\ncname", targ)
      answers.append((QTYPE[a.rtype], str(a.rdata), str(a.rname)))
      
      
  # Parse the authority section #4
  authority = []
  for k in range(header.auth):
    auth = RR.parse(buff)
    if auth.rtype == QTYPE.A:
      authority.append((QTYPE[auth.rtype], str(auth.rname), str(auth.rdata)))
    if auth.rtype == QTYPE.NS:
      authority.append((QTYPE[auth.rtype], str(auth.rname), str(auth.rdata)))
    else:
      authority.append((QTYPE[auth.rtype], str(auth.rname), str(auth.rdata)))
      
  # Parse the additional section #5
  additional = []
  for k in range(header.ar):
    adr = RR.parse(buff)
    # just IP
    additional.append((QTYPE[adr.rtype], str(adr.rname), str(adr.rdata)))
  return {"answers": answers, "authority": authority, "additional": additional}

ips = []
def resolve(udp_sock, domain:str, record_type):
  dom = domain.split('.')
  # first time through NS?
  if dom[-1] == '':
    dom.remove('')
  name = '.' + dom[-1]
  print(name)
  # first NS Root server query
  result = get_dns_record(udp_sock, dom[-1], ROOT_SERVER, record_type)
  cache[(dom[-1], record_type)] = result
  
  # solve from cache
  if (domain, "A") in cache:
    print("solved")
    return cache[(domain, record_type)] #needs to return an IP
  print(f"\nresult: {result}")
  # restart if there is an alias
  if result["answers"]:
    if result["answers"][0][0] == "CNAME":
      return resolve(udp_sock, result["answers"][0][2], "A")
    if result["answers"][0][0] == "A" or result["answers"][0][0] == "AA":
      print("resolved")
  # if 
  cur_server = result["additional"][0][2]
  print(f"\ncurent server:{cur_server}\n")
  while True:
    # not resolved second time NS
    second = dom[-2] + "." + dom[-1]
    print(second)
    response = get_dns_record(udp_sock, second, cur_server, "NS")
    cache[(second, record_type)] = response

    if response is None:
      return None
    # print(response["answers"])
    print(f"New cache: {cache}")
    print(f"\nresponse: {response}\n")
    # with third
    # cur_server = response["authority"][0][1]
    if response["answers"]:
      cur_server = response["answers"][0][2]
    elif response["authority"] and response["additional"] == []:
      # cur_server = response["authority"][0][1]
      name =  response["authority"][0][2]
      print(cur_server)
      recurs = resolve(udp_sock, name, "A")
      ips.append(recurs)
      # response = get_dns_record(udp_sock, name, ROOT_SERVER, "A")
      # cache[(domain, "A")] = response


      # print(f"new response third: {response}")
    # final resolve
    # print(f"answers: {response["answers"]}")
    if response["answers"]:
      if response["answers"][0][2] == response["additional"][0][1]:
          cur_server = response["additional"][0][2]
          if response["answers"][0][0] == 'A':
            response = get_dns_record(udp_sock, second, cur_server, "A")
            ips.append(response["answers"][0][2])
      # for i in range(len(response["answers"])):
      #   if response["answers"][0][2] == response["additional"][0][1]:
      #     cur_server = response["additional"][0][2]
      #     if response["answers"][i][0] == 'A':
      #       response = get_dns_record(udp_sock, second, cur_server, "A")
      #       ips.append(response["answers"][0][2])
      #     elif response["answers"][i][0] == 'AAAA':
      #       server = response["additional"][i][2]
      #       print(f"server: {server}")
            # response = get_dns_record(udp_sock, second, cur_server, "AAAA")
            # ips.append(response["answers"][0][2])

        # print(response)
    elif response["answers"] == [] and response["authority"] and response["additional"]:
      if response["authority"][0][2] == response["additional"][0][1]:
        cur_server = response["authority"][0][2]
        response = get_dns_record(udp_sock, second, cur_server, "A")
        print(response["answers"][0][2])
        ips.append(response["answers"][0][2])
      # elif response["authority"][0][0] == 'AAAA' and response["additional"][0][0] == 'AAAA':
      #   print(f"authority: {response["authority"]}")
      #   print("stuff")
        # cur_server = 
        # response = get_dns_record(udp_sock, second, cur_server, "AAAA")
        # print(response)
    print("ended here")
    print(ips)
    return ips

    # print(f"\nthird response: {response}\n")
    # cache[(domain, "A")] = response
    # print(f"Authoritative cache: {cache}")
    # type = A 
    # print(f"This response: {response}")
    # if response["answers"] != []:
    # ips = []
  # I don't remember why 
    # for ans in response["answers"]:
    #   for i in range(len(response["answers"])-1):
    #     if ans[2] == response["additional"][i][1]:
    #       ips.append(str(response["additional"][i][2]))
    #   print(f"IP list: {ips}")
    #   return ips
    # if response["authority"] and response["additional"]:
    #   if response["authority"][0][2] == response["additional"][0][1]:
    #     if response["additional"][0][0] == 'A' or response["additional"][0][0] == 'AAAA':
    #       cur_server = response["additional"][0][2] # ip address
    #       dname = response["additional"][0][1]
    #       response = get_dns_record(udp_sock, dname, cur_server, "A")
    #       print(f"\nFinal: {response}")
          

      
def lists():
  # for i in range(len(cache)):
  for i, (k, v) in enumerate(cache.items()):
    print(f"{i}: {k}: {v}\n")

def clear():
  cache.clear
  print("Your cache has been clear.")

def remove():
  pass

if __name__ == '__main__':
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)
  while True:
    domain_name = input("Enter a domain name or .exit > ")

    if domain_name == '.exit':
      break
    if domain_name == '.list':
      lists()
      break
    if domain_name == '.clear':
      clear()
      break
    if domain_name == '.remove':
      remove()
      break

    while True:
      # Use the function get_dns_record(____) (from the starter code
      # below) to resolve the IP address of the domain name in question
      # ip4 = resolve(sock, domain_name, record_type="A")
      # ip6 = resolve(sock, domain_name, record_type="AAAA")
      ips = resolve(sock, domain_name, record_type="A")
      if ips:
        ip4 = ips[-1]
        # ip6 = ips[-1]
        print(f'{domain_name} resolved to IPv4 {ip4} and IPv6')
        break
      else:
        print(f'Could not resolve {domain_name}')
        break
  sock.close()
  