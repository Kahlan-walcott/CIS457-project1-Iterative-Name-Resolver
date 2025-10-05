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
    return {"answers": answers, "authority": authority, "additional": additional, "rcode": "NXDOMAIN"}

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    print(f"Question-{k} {repr(q)}")
    
  # Parse the answer section #3
  answers = []
  for k in range(header.a):
    a = RR.parse(buff)
    # for authoritative response
    if a.rtype == QTYPE.CNAME:
      targ = str(a.rdata)
      print(f"\ncname", targ)
      answers.append((QTYPE[a.rtype], str(a.rdata), str(a.rname)))
    else:
      answers.append((QTYPE[a.rtype], str(a.rname), str(a.rdata)))
    
      
      
  # Parse the authority section #4
  authority = []
  for k in range(header.auth):
    auth = RR.parse(buff)
    authority.append((QTYPE[auth.rtype], str(auth.rname), str(auth.rdata)))
      
  # Parse the additional section #5
  additional = []
  for k in range(header.ar):
    adr = RR.parse(buff)
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
  if result is None or result.get("rcode") == "NXDOMAIN":
    print(f'{domain} is not a valid domain.')
    return None
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
    if result["answers"][0][0] == "A" or result["answers"][0][0] == "AAAA":
      print("resolved")

  cur_server = result["additional"][0][2]
  print(f"\ncurent server:{cur_server}\n")
  while True:
    # not resolved second time NS
    second = dom[-2] + "." + dom[-1]
    print(second)
    response = get_dns_record(udp_sock, second, cur_server, "NS")
    if response is None or response.get("rcode") == "NXDOMAIN":
      print(f'{domain} is not a valid domain.')
      return None
    cache[(second, record_type)] = response

    print(f"New cache: {cache}")
    print(f"\nresponse: {response}\n")
    # third resolve
    if response["answers"]:
      cur_server = response["answers"][0][2]
    elif response["authority"] and response["additional"] == []:
      name =  response["authority"][0][2]
      # print(cur_server)
      recurs = resolve(udp_sock, name, "A")
      return recurs

    if response["answers"]:
      if response["answers"][0][2] == response["additional"][0][1]:
          cur_server = response["additional"][0][2]
          if response["answers"][0][0] == 'A':
            response = get_dns_record(udp_sock, second, cur_server, "A")
            if response is None or response.get("rcode") == "NXDOMAIN":
              print(f'{domain} is not a valid domain.')
              return None
            return response["answers"][0][2]
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
        if response is None or response.get("rcode") == "NXDOMAIN":
          print(f'{domain} is not a valid domain.')
          return None
        # print(response["answers"][0][2])
        # ips.append(response["answers"][0][2])
        return response["answers"][0][2]
      # elif response["authority"][0][0] == 'AAAA' and response["additional"][0][0] == 'AAAA':
      #   print(f"authority: {response["authority"]}")
      #   print("stuff")
        # cur_server = 
        # response = get_dns_record(udp_sock, second, cur_server, "AAAA")
        # print(response)
    print("ended here")
    print(ips)
    return ips

      
def lists():
  i = 1
  for k, v in cache.items():
    print(f"{i}: {k}: {v}\n")
    i += 1

def clear():
  cache.clear()
  print("Your cache has been cleared.")

def remove(num):
  # error checking
  if num < 0:
    print("Error: Please enter a positive number.")
  if num > len(cache):
    print(f"Error: You entered {num} which is bigger than the size of cache which is {len(cache)}.")
  # removing the entry
  key_at = 0
  cp = cache.copy()
  if 0 < num < len(cache):
    for k in cp.keys():
      if key_at == num-1:
        del cache[k]
        print(f"deleted the {num} entry in cache which was {k}.")
        break
      else:
        key_at += 1

if __name__ == '__main__':
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)
  while True:
    domain_name = input("Enter a domain name, .exit, .list, .clear, or .remove integer > ")
    inputs = domain_name.split()
    print(inputs)
    if len(inputs) == 2:
      if inputs[0] == '.remove':
        remove(int(inputs[1]))
        domain_name = input("Enter a domain name, .exit, .list, .clear, or .remove integer > ")
        inputs = domain_name.split()
    if domain_name == '.exit':
      break
    if domain_name == '.list':
      lists()
      domain_name = input("Enter a domain name, .exit, .list, .clear, or .remove integer > ")
      inputs = domain_name.split()
    if domain_name == '.clear':
      cache.clear()
      domain_name = input("Enter a domain name, .exit, .list, .clear, or .remove integer > ")
      inputs = domain_name.split()
    while True:
      # resolving IPv4 IPs
      ips = resolve(sock, domain_name, record_type="A")
      if ips is None:
        break
      if ips:
        print(f'{domain_name} resolved to IPv4 {ips} and IPv6')
        break
      else:
        print(f'Could not resolve {domain_name}')
        break
  sock.close()
  