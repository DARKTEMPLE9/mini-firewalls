#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct
import socket
# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class ICMPRule:
    def __init__(self, verdict, ip_lower_bound, ip_upper_bound,icmp_type, country_code = None):
        self.verdict = verdict
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.icmp_type = icmp_type
        self.country_code = country_code

class UDPRule:
    def __init__(self, verdict, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, country_code = None):
        self.verdict = verdict
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

class TCPRule:
    def __init__(self, verdict, ip_lower_bound, ip_upper_bound, port_lower_bound, port_upper_bound, country_code = None):
        self.verdict = verdict
        self.ip_range = (ip_lower_bound, ip_upper_bound)
        self.port_range = (port_lower_bound, port_upper_bound)
        self.country_code = country_code

class DNSRule:
    def __init__(self, verdict, domain, regax_match):
        self.verdict = verdict
        self.domain = domain
        self.regax_match = regax_match

class HTTPRule:
    def __init__(self, hostname, hostname_type):
        self.hostname = hostname
        self.hostname_type = hostname_type

class HTTPConnection:
    def __init__(self, request='', response='', is_request_finish=False, is_response_finish=False, expected_request_seq_num=None, expected_response_seq_num=None, is_written_connection=False):
        self.request = request
        self.response = response
        self.is_request_finish = is_request_finish
        self.is_response_finish = is_response_finish
        self.expected_request_seq_num = expected_request_seq_num
        self.expected_response_seq_num = expected_response_seq_num
        self.is_written_connection = is_written_connection

    def append_to_request(self, add_request):
        self.request += add_request

    def append_to_response(self, add_response):
        self.response += add_response

        
class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        f = open(config['rule'], 'r')
        self.rules = f.readlines()
        f.close()
        
        self.icmp_rules = []
        self.udp_rules = []
        self.tcp_rules = []
        self.dns_rules = []
        self.http_rules = []
        #store connected http to table
        self.http_connection_map = {} 

        self.geo_map = self.initialize_all_geo('geoipdb.txt')
        
        self.initialize_all_rules(self.rules)  

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    def initialize_all_rules(self, rules):
        #scan all line in rules list
        for i in range(0,len(rules)):
            str_rule = rules[i].strip('\n')
            #skip whitespace
            if len(str_rule) == 0:
                continue
            #skip comcmment
            if str_rule.startswith('%'):
                continue
            #remove '/n' and split based on ' '
            #<verdict> <protocol> <ip> <port>
            rule = str_rule.split(' ')
            verdict = rule[0].upper()
            protocol = rule[1].upper()
            if protocol == 'ICMP':
                tmp_ip_lower_bound = ''
                tmp_ip_upper_bound = ''
                tmp_country_code = None
                ip = rule[2]
                icmp_type = rule[3]
                if icmp_type == 'any':
                    icmp_type = '-1'
                if ip == 'any':
                    tmp_ip_lower_bound = '0.0.0.0'
                    tmp_ip_upper_bound = '255.255.255.255'
                elif ip.upper() in self.geo_map:
                    tmp_country_code = ip.upper()
                    tmp_ip_lower_bound = 'country'
                    tmp_ip_upper_bound = 'country'
                elif '/' in ip:
                    ip_range = self.cidr_to_ip_range(ip)
                    tmp_ip_lower_bound = ip_range[0]
                    tmp_ip_upper_bound = ip_range[1]
                else:
                    tmp_ip_lower_bound = ip
                    tmp_ip_upper_bound = ip
                new_icmp_rule = ICMPRule(verdict, tmp_ip_lower_bound, tmp_ip_upper_bound, icmp_type, tmp_country_code)
                self.icmp_rules.append(new_icmp_rule)
            elif protocol == 'UDP':
                tmp_ip_lower_bound = ''
                tmp_ip_upper_bound = ''
                tmp_port_lower_bound = -100000
                tmp_port_upper_bound = 100000
                tmp_country_code = None
                ip = rule[2]
                port = rule[3]
                if ip == 'any':
                    tmp_ip_lower_bound = '0.0.0.0'
                    tmp_ip_upper_bound = '255.255.255.255'
                elif ip.upper() in self.geo_map:
                    tmp_country_code = ip.upper()
                    tmp_ip_lower_bound = 'country'
                    tmp_ip_upper_bound = 'country'
                elif '/' in ip:
                    ip_range = self.cidr_to_ip_range(ip)
                    tmp_ip_lower_bound = ip_range[0]
                    tmp_ip_upper_bound = ip_range[1]
                else:
                    tmp_ip_lower_bound = ip
                    tmp_ip_upper_bound = ip
                
                if port == 'any':
                    pass
                elif '-' in port:
                    tmp_port_range = port.split('-')
                    tmp_port_lower_bound = tmp_port_range[0]
                    tmp_port_upper_bound = tmp_port_range[1]
                else:
                    tmp_port_lower_bound = port
                    tmp_port_upper_bound = port
                new_udp_rule = UDPRule(verdict, tmp_ip_lower_bound, tmp_ip_upper_bound, tmp_port_lower_bound, tmp_port_upper_bound,tmp_country_code)
                self.udp_rules.append(new_udp_rule)
                
            elif protocol == 'TCP':
                tmp_port_lower_bound = -100000
                tmp_port_upper_bound = 1000000
                tmp_ip_lower_bound = ''
                tmp_ip_upper_bound = ''
                tmp_country_code = None
                ip = rule[2]
                port = rule[3]
                if ip == 'any':
                    tmp_ip_lower_bound = '0.0.0.0'
                    tmp_ip_upper_bound = '255.255.255.255'
                elif ip.upper() in self.geo_map:
                    tmp_country_code = ip.upper()
                    tmp_ip_lower_bound = 'country'
                    tmp_ip_upper_bound = 'country'
                elif '/' in ip:
                    ip_range = self.cidr_to_ip_range(ip)
                    tmp_ip_lower_bound = ip_range[0]
                    tmp_ip_upper_bound = ip_range[1]
                else:
                    tmp_ip_lower_bound = ip
                    tmp_ip_upper_bound = ip
                if port == 'any':
                    pass
                elif '-' in port:
                    tmp_port_range = port.split('-')
                    tmp_port_lower_bound = tmp_port_range[0]
                    tmp_port_upper_bound = tmp_port_range[1]
                else:
                    tmp_port_lower_bound = port
                    tmp_port_upper_bound = port
                new_tcp_rule = TCPRule(verdict, tmp_ip_lower_bound, tmp_ip_upper_bound, tmp_port_lower_bound, tmp_port_upper_bound, tmp_country_code)
                self.tcp_rules.append(new_tcp_rule)

            elif protocol == 'DNS':
                tmp_domain = rule[2]
                #check wildcard case
                if tmp_domain.startswith('*'):
                    new_dns_rule = DNSRule(verdict, tmp_domain[1:], 'WILDCARD')
                    #It is an outgoing UDP packet with destination port 53.
                    self.udp_rules.append(new_dns_rule)
                else:
                    new_dns_rule = DNSRule(verdict, tmp_domain, 'EXACT')
                    self.udp_rules.append(new_dns_rule)

            elif protocol == 'HTTP':
                hostname = rule[2]
                if hostname.startswith('*'):
                    new_http_rule = HTTPRule(hostname[1:], 'WILDCARD')
                    self.http_rules.append(new_http_rule)
                #1.1.1.1 -> 1111 
                #judge ip address
                elif hostname.translate(None, '.').isdigit():
                    new_http_rule = HTTPRule(hostname, 'IP')
                    self.http_rules.append(new_http_rule)
                elif hostname == '*':
                    new_http_rule = HTTPRule(hostname, 'ANY')
                    self.http_rules.append(new_http_rule)
                else:
                    new_http_rule = HTTPRule(hostname, 'EXACT')
                    self.http_rules.append(new_http_rule)

            else:
                pass
                
    # geo data structure:    
    #{'CN':[(1.1.1.0,1.1.1.1),(1.1.1.2,1.1.1.4)]}
    def initialize_all_geo(self, filename):
        geo = {}
        f = open(filename, 'r')
        line = f.readline()
        while line:
            lst = line.strip().split(' ')
            # print lst
            country = lst[2]
            ip_range = (lst[0],lst[1])
            if country not in geo:
                geo[country] = []
            geo[country].append(ip_range)
            line = f.readline()
        f.close()
        return geo


    '''
    Given '1.1.1.0/22'
    Get [1.1.0.0, 1.1.3.255]
    '''
    def cidr_to_ip_range(cidr):
        lst = cidr.split('/')
        addr_str = lst[0]
        cidr_str = lst[1]
        #http://stackoverflow.com/questions/1038002/how-to-convert-cidr-to-network-and-ip-address-range-in-c
        ip_addr_array = self.ip_address_to_array(addr_str)
        mask_addr_array = self.cidr_to_mask_array(cidr_str)[0]
        reversed_mask_addr_array = self.cidr_to_mask_array(cidr_str)[1]

        ip_lower_bound = []
        ip_upper_bound = []
        #startIP = ip_address & mask
        for i in range(0,32):
            bit = ip_addr_array[i] & mask_addr_array[i]
            ip_lower_bound.append(bit)
        #endIP = (ip_address & mask) | ~mask
        for i in range(0,32):
            bit = (ip_addr_array[i] & mask_addr_array[i]) | reversed_mask_addr_array[i]
            ip_upper_bound.append(bit)
    
        ip_range = []
        ip_range.append(self.ip_addr_array_to_ip_addr(ip_lower_bound))
        ip_range.append(self.ip_addr_array_to_ip_addr(ip_upper_bound))
        return ip_range

    '''
    Given '1.1.1.0' 
    Get [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0]
    '''
    def ip_address_to_array(self, ip_addr):
        #1.1.1.0 -> ['1','1','1','0']
        ip_addr_array = []
        addr = ip_addr.split('.')
        # print addr
        for i in addr:
            #'0b1' -> '1'
            #print i, type(i)
            tmp = bin(int(i))[2:]
            #add extra 0 to convert 1 -> 00000001
            add_bit_num = 8 - len(tmp)
            for i in range(0,add_bit_num):
                ip_addr_array.append(0)
            for s in tmp:
                ip_addr_array.append(int(s))
        return ip_addr_array

    #get mask and ~mask
    # Given 24, get ~mask 0x000000FF, mask 0xFFFFFF00
    def cidr_to_mask_array(cidr_str):
        cidr = int(cidr_str)
        reversed_mask = (1 << (32-cidr)) - 1
        mask_addr_array = []
        reversed_mask_addr_array = []
        #'255' -> '11111111'
        tmp = bin(int(reversed_mask))[2:]
        add_bit_num = 32 - len(tmp)
        #add extra 0 to make it 32 bit
        #convert 0xFF -> 0X000000FF
        for i in range(0,add_bit_num):
            reversed_mask_addr_array.append(0)
        for s in tmp:
            reversed_mask_addr_array.append(int(s))

        #convert 0xFF -> 0xFFFFFF00
        #~ operation
        for i in reversed_mask_addr_array:
            if i == 0:
                mask_addr_array.append(1)
            else:
                mask_addr_array.append(0)
        return (mask_addr_array, reversed_mask_addr_array)

    def ip_addr_array_to_ip_addr(ip_addr_array):
        res = []
        for i in range(0,32,8):
            #[1,1,1,1] -> ['1','1','1','1']
            string_list = map(str, ip_addr_array[i:i+8])
            string = ''.join(string_list)
            #int(str, base): ('11111111', 2) = 255
            res.append(str(int(string, 2)))
        return '.'.join(res)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        # when we capture a packet, we will call this method
        try:
            #read ip header format to understand following code
            #Convert a 32-bit packed IPv4 address (a string four characters in length) to 
            #its standard dotted-quad string representation 
            #(for example,'123.121.2.0').
            src_ip_addr = socket.inet_ntoa(pkt[12:16])
            dst_ip_addr = socket.inet_ntoa(pkt[16:20])
            src_ip_addr_array = src_ip_addr.split('.')
            dst_ip_addr_array = dst_ip_addr.split('.')
            #ord('a') -> 97
            protocol = ord(pkt[9:10])
            #with byte_offset, we can calculate the next layer header begin location
            ip_header_length = ord(pkt[0:1]) & 0xf
            #print ip_header_length
            byte_offset = ip_header_length * 4
            
        except:
            print "parse ip packet failed"
            return 
        
        #deal with tcp 
        if protocol == 6:
            #based on tcp header, we can find src port and dst port based on byte_offset
            #struct.unpack(fmt, string):The result is a tuple even if it contains exactly one item. 
            src_port = struct.unpack('!H', pkt[byte_offset:byte_offset + 2])[0]
            dst_port = struct.unpack('!H', pkt[byte_offset + 2:byte_offset + 4])[0]
            exteral_ip = ''
            exteral_port = 0
            
            internal_ip = ''
            internal_port = 0
            
            if pkt_dir == PKT_DIR_INCOMING:
                exteral_ip = src_ip_addr
                exteral_port = src_port
                internal_ip = dst_ip_addr
                internal_port = dst_port
            elif pkt_dir == PKT_DIR_OUTGOING:
                exteral_ip = dst_ip_addr
                exteral_port = dst_port
                internal_ip = src_ip_addr
                internal_ip = src_port
            else:
                pass
            is_send = self.is_send_tcp_packet(pkt_dir, exteral_ip, exteral_port, internal_ip, internal_port, pkt)
            if is_send:
                if pkt_dir == PKT_DIR_INCOMING:
                    if exteral_port == 80:
                        tcp_record = (src_ip_addr, dst_ip_addr, src_port, dst_port, 'TCP')
                        http_connection = None
                        #judge this http connection is in the map
                        for map_tcp_record in self.http_connection_map:
                            if self.is_same_http_connection(tcp_record, map_tcp_record):
                                http_connection = self.http_connection_map[map_tcp_record]
                                tcp_record = map_tcp_record
                        #if not, we create new http connection
                        if http_connection == None:
                            http_connection = HTTPConnection()
                            self.http_connection_map[tcp_record] = http_connection
                        is_send_http = self.is_send_http_message(pkt, 'RESPONSE', http_connection, tcp_record)
                        if is_send_http:
                            self.iface_int.send_ip_packet(pkt)
                        
                        if http_connection.is_response_finish and http_connection.is_response_finish:
                            self.write_to_log(http_connection, exteral_ip)
                    #port != 80, just send
                    else:
                        self.iface_int.send_ip_packet(pkt)

                elif pkt_dir == PKT_DIR_OUTGOING:
                    if exteral_port == 80:
                        tcp_record = (src_ip_addr, dst_ip_addr, src_port, dst_port, 'TCP')
                        http_connection = None
                        for map_tcp_record in self.http_connection_map:
                            if self.is_same_http_connection(tcp_record, map_tcp_record):
                                http_conection = self.http_connection_map[map_tcp_record]
                                tcp_record = map_tcp_record
                        if http_connection == None:
                            http_connection = HTTPConnection()
                            self.http_connection_map[tcp_record] = http_connection
                        is_send_http = self.is_send_http_message(pkt, 'REQUEST', http_connection, tcp_record)
                        if is_send_http:
                            self.iface_ext.send_ip_packet(pkt)
                        
                        if http_connection.is_request_finish and http_connection.is_response_finish:
                            self.write_to_log(http_connection, exteral_ip)
                            del self.http_connection_map[tcp_record]
                    else:
                        self.iface_ext.send_ip_packet(pkt)
                print 'send tcp packet'
            else:
                print 'drop tcp packet'
                return
        #deal with icmp
        elif protocol == 1:
            #look at icmp header format
            icmp_type = ord(pkt[byte_offset:byte_offset + 1])
            print icmp_type
            exteral_ip = ''
            if pkt_dir == PKT_DIR_INCOMING:
                exteral_ip = src_ip_addr
            elif pkt_dir == PKT_DIR_OUTGOING:
                exteral_ip = dst_ip_addr
            else:
                pass
            is_send = self.is_send_icmp_packet(exteral_ip, icmp_type)
            if is_send:
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
                print 'send icmp packet'
            else:
                print 'drop icmp packet'
                return 
        #deal with udp
        #we need to discuss udp without dns and udp with dns two case
        elif protocol == 17:
            src_port = struct.unpack('!H', pkt[byte_offset:byte_offset + 2])[0]
            dst_port = struct.unpack('!H', pkt[byte_offset + 2:byte_offset + 4])[0]
            exteral_ip = ''
            exteral_port = 0
            if pkt_dir == PKT_DIR_INCOMING:
                exteral_ip = src_ip_addr
                exteral_port = src_port
            elif pkt_dir == PKT_DIR_OUTGOING:
                exteral_ip = dst_ip_addr
                exteral_port = dst_port
            else:
                pass
            #udp header has 8 byte
            dns_byte_offset = byte_offset + 8
            #dns question count
            dns_question_count_byte_offset = dns_byte_offset + 4
            dns_question_count = struct.unpack('!H',pkt[dns_question_count_byte_offset:dns_question_count_byte_offset+2])[0]
            #dns header has 12 byte
            dns_question_byte_offset = dns_byte_offset + 12

            dns_name = ''
            #
            while ord(pkt[dns_question_byte_offset:(dns_question_byte_offset+1)]) is not 0:
                i = 0
                cur_length = ord(pkt[dns_question_byte_offset:(dns_question_byte_offset+1)])
                dns_question_byte_offset += 1
                while i < cur_length:
                    cur_character = pkt[dns_question_byte_offset:dns_question_byte_offset+1]
                    dns_name += cur_character
                    dns_question_byte_offset += 1
                    i += 1
                dns_name += '.'
            #move to query type 
            dns_question_byte_offset += 1
            dns_name = dns_name[0:(len(dns_name)-1)]
            #print dns_name
            #get query type and query class to judge whether it is dns
            query_type = struct.unpack('!H', pkt[dns_question_byte_offset:dns_question_byte_offset+2])[0]
            query_class = struct.unpack('!H', pkt[dns_question_byte_offset+2:dns_question_byte_offset+4])[0]
            
            #It is an outgoing UDP packet with destination port 53.
            #It has exactly one DNS question entry.
            #There may be other nonempty sections (Answer, Authority, and Additional)
            #The query type of the entry is either A or AAAA (QTYPE == 1 or QTYPE == 28), and
            #The class of the entry is Internet (QCLASS == 1).
            if (exteral_port == 53) and (dns_question_count == 1) and (query_type == 1 or query_type == 28) and (query_class == 1):
                is_send = self.is_send_udp_packet(pkt,exteral_ip, exteral_port, True, dns_name, query_type, dns_question_byte_offset)
                if is_send:
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_int.send_ip_packet(pkt)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_ext.send_ip_packet(pkt)
                    print 'send udp packet'
                else:
                    print 'drop udp packet'
                    return 
            else:
                is_send = self.is_send_udp_packet(pkt, exteral_ip, exteral_port, False, None)
                if is_send:
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_int.send_ip_packet(pkt)
                    elif pkt_dir == PKT_DIR_OUTGOING:
                        self.iface_ext.send_ip_packet(pkt)
                    print 'send udp packet'
                else:
                    print 'drop udp packet'
                    return

            
        #should always pass nonTCP/UDP/ICMP packets based on the project document
        else:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

    
    def binary_search_ip_ranges(self, country_ip_ranges,ip_addr):
        lo = 0
        hi = len(country_ip_ranges) - 1
        while lo <= hi:
            mid = lo + (hi - lo) / 2
            mid_ip_range = country_ip_ranges[mid]
            if self.is_ip_in_ranges(mid_ip_range[0], mid_ip_range[1], ip_addr):
                return True
            elif self.ip_addr_to_integer(ip_addr) < self.ip_addr_to_integer(mid_ip_range[0]):
                hi = mid - 1
            elif self.ip_addr_to_integer(ip_addr) > self.ip_addr_to_integer(mid_ip_range[1]):
                lo = mid + 1
            else:
                pass
        return False

    def is_ip_in_ranges(self, ip_lower_bound, ip_upper_bound, ip_addr):
        is_contained = False
        if (self.ip_addr_to_integer(ip_lower_bound) <= self.ip_addr_to_integer(ip_addr)) and (self.ip_addr_to_integer(ip_upper_bound) >= self.ip_addr_to_integer(ip_addr)):
            is_contained = True
        return is_contained

    def ip_addr_to_integer(self, ip_addr):
        ip_addr_array = self.ip_address_to_array(ip_addr)
        strlist_ip_addr_array = map(str, ip_addr_array)
        string = ''.join(strlist_ip_addr_array)
        return int(string, 2)

    # TODO: You can add more methods as you want.
    def is_send_tcp_packet(self, pkt_dir, exteral_ip, exteral_port, internal_ip, internal_port, packet):
        is_send = True
        #iterator all rules in tcp_rules_list
        for tcp_rule in self.tcp_rules:
            is_ip_corrected = False
            is_port_corrected = False
            #check satisfiy ip requirement
            #have country code
            if tcp_rule.country_code is not None:
                #country_ip_ranges is a list with mutiple items
                country_ip_ranges = self.geo_map[tcp_rule.country_code]
                if self.binary_search_ip_ranges(country_ip_ranges, exteral_ip):
                    is_ip_corrected = True
            else:
                ip_range = tcp_rule.ip_range
                if self.is_ip_in_ranges(ip_range[0],ip_range[1], exteral_ip):
                    is_ip_corrected = True
            
            #check satisify port requirement
            port_range = tcp_rule.port_range
            if (int(port_range[0]) <= exteral_port) and (exteral_port <= int(port_range[1])):
                is_port_corrected = True

            if is_ip_corrected and is_port_corrected:
                if tcp_rule.verdict == 'PASS':
                    is_send = True
                elif tcp_rule.verdict == 'DROP':
                    is_send = False
                # inject reset packet: deny tcp
                elif tcp_rule.verdict == 'DENY':
                    is_send = False
                    reset_packet = self.generate_reset_packet(packet)
                    if pkt_dir == PKT_DIR_INCOMING:
                        self.iface_ext.send_ip_packet(reset_packet)
                    else:
                        self.iface_int.send_ip_packet(reset_packet)

        return is_send

    def is_send_icmp_packet(self, exteral_ip, icmp_type):
        is_send = False
        for icmp_rule in self.icmp_rules:
            is_ip_corrected = False
            is_icmp_type_matched = False
            #check ip is satisfied requirements
            if icmp_rule.country_code is not None:
                country_ip_ranges = self.geo_map[exteral_ip]
                if self.binary_search_ip_ranges(country_ip_ranges, exteral_ip):
                    is_ip_corrected = True
            else:
                ip_range = icmp_rule.ip_range
                if self.is_ip_in_ranges(ip_range[0],ip_range[1],exteral_ip):
                    is_ip_corrected = True
            #check icmp_tpye is equal
            if int(icmp_rule.icmp_type) == icmp_type:
                is_icmp_type_matched = True
            if is_ip_corrected and is_icmp_type_matched:
                if icmp_rule.verdict == 'PASS':
                    is_send = True
                elif icmp_rule.verdict == 'DROP':
                    is_send = False
        return is_send

    def is_send_udp_packet(self,pkt, exteral_ip, exteral_port, is_dns, dns_name=None, q_type=None,q_type_offset=None):
        #we will deal with dns packet
        is_send = True
        if is_dns:
            for udp_rule in self.udp_rules:
                #udp_rule is DNS rule
                if isinstance(udp_rule, DNSRule):
                    if udp_rule.regax_match == 'EXACT':
                        if udp_rule.domain == dns_name:
                            if udp_rule.verdict == 'PASS':
                                is_send = True
                            elif udp_rule.verdict == 'DROP':
                                is_send = False
                            elif udp_rule.verdict == 'DENY':
                                is_send = False
                                #send dns deny packet when query type == 1
                                if q_type == 1:
                                    dns_deny_packet = self.generate_dns_deny_packet(pkt, q_type_offset)
                                    self.iface_int.send_ip_packet(dns_deny_packet)

                    else:
                        if dns_name.endswith(udp_rule.domain):
                            if udp_rule.verdict == 'PASS':
                                is_send = True
                            elif udp_rule.verdict == 'DROP':
                                is_send = False 
                            elif udp_rule.verdict == 'DENY':
                                is_send = False
                                #send dns deny packet when query type == 1
                                if q_type == 1:
                                    dns_deny_packet = self.generate_dns_deny_packet(pkt, q_type_offset)
                                    self.iface_int.send_ip_packet(dns_deny_packet)


        else:
            for udp_rule in self.udp_rules:
                if isinstance(udp_rule, DNSRule):
                    continue
                is_ip_corrected = False
                is_port_corrected = False
                if udp_rule.country_code is not None:
                    country_ip_ranges = self.geo_map[udp_rule.country_code]
                    if self.binary_search_ip_ranges(country_ip_ranges, exteral_ip):
                        is_ip_corrected = True
                else:
                    ip_range = udp_rule.ip_range
                    if self.is_ip_in_ranges(ip_range[0], ip_range[1], exteral_ip):
                        is_ip_corrected = True

                port_range = udp_rule.port_range
                if (int(port_range[0]) <= exteral_port and exteral_port <= int(port_range[1])):
                    is_port_corrected = True

                if is_ip_corrected and is_port_corrected:
                    if tcp_rule.verdict == 'PASS':
                        is_send = True
                    elif tcp_rule.verdict == 'DROP':
                        is_send = False
        return is_send    

    def generate_reset_packet(self,packet):
        reset_packet = ''
        ip_header_length = ord(packet[0:1]) & 0xf
        ip_header_length = ip_header_length * 4
        packet_total_length = struct.unpack('!H', packet[2:4])[0]
        #add Ip header first two bytes
        reset_packet += packet[0:2]
        #add total length
        reset_packet += struct.pack('!H', 40)
        #add fragment information
        reset_packet += packet[4:8]
        #pack TTL is 64
        reset_packet += struct.pack('!B', 64)
        #add protocol
        reset_packet += packet[9:10]
        #set ip checksum = 0
        reset_packet += struct.pack('!H', 0)
        #add src ip and dst ip
        reset_packet += packet[12:16]
        reset_packet += packet[16:20]

        #add tcp src port and dst port
        reset_packet += packet[ip_header_length:ip_header_length+2]
        reset_packet += packet[ip_header_length+2:ip_header_length+4]

        #add new sequence number
        old_sequence_number = struct.unpack('!L', packet[ip_header_length+4:ip_header_length+8])[0]
        new_sequence_number = 0
        reset_packet += struct.pack('!L', new_sequence_number)

        #add new ack
        new_ack = old_sequence_number + 1
        reset_packet += struct.pack('!L', new_ack)

        reset_packet += struct.pack('!B', 0x50)
        #pack flags into 1 byte
        reset_packet += struct.pack('!B',0x14)

        #add window size
        reset_packet += struct.pack('!H',0)
        #set tcp checksum = 0
        reset_packet += struct.pack('!H',0)
        reset_packet += packet[38:40]

        #add ip checksum to reset packet
        reset_packet_checksum = struct.pack('!H', self.calculate_ipv4_checksum(ip_header_length,reset_packet))
        reset_packet = reset_packet[0:10] + reset_packet_checksum + reset_packet[12:]
        #add tcp checksum to reset packet
        reset_packet_tcp_checksum = struct.pack('!H', self.calculate_tcp_or_udp_checksum(ip_header_length, reset_packet))
        reset_packet = reset_packet[0:36] + reset_packet_tcp_checksum + reset_packet[36:]
        return reset_packet
    
    def generate_dns_deny_packet(self, pkt, q_type_offset):
        dns_deny_packet = ''
        ip_header_length = ord(pkt[0:1]) & 0x0f
        ip_header_length = ip_header_length * 4
        packet_length = struct.unpack('!H', pkt[2:4])[0]
        
        dns_deny_packet += pkt[0:2]
        dns_deny_packet += pkt[2:4]
        dns_deny_packet += pkt[4:6]
        dns_deny_packet += pkt[6:8]
        #pack TTL 64
        dns_deny_packet += struct.pack('!B', 64)
        dns_deny_packet += pkt[9:10]
        #set ip checksum = 0
        dns_deny_packet += struct.pack('!H',0)
        
        #we need to send reset packet, so the old src -> new dst, old dst -> new src
        dns_deny_packet += pkt[16:20]
        dns_deny_packet += pkt[12:16]
        dns_deny_packet += pkt[ip_header_length + 2:ip_header_length+4]
        dns_deny_packet += pkt[ip_header_length:ip_header_length+2]

        dns_deny_packet += pkt[24:28]
        dns_deny_packet += pkt[28:30]
        
        #set  qr = 1
        option_bits = struct.unpack['!H', pkt[30:32]][0]
        option_bits = 0x8000 | option_bits
        dns_deny_packet += struct.pack('!H',option_bits)

        dns_deny_packet += pkt[32:34]

        dns_deny_packet += struct.pack('!H', 1)

        dns_deny_packet += pkt[36:40]
        #copy qname
        dns_deny_packet += pkt[40:q_type_offset]

        length_of_q_name = q_type_offset - 40

        dns_deny_packet += struct.pack('!H', 1)

        dns_deny_packet += struct.pack('!H', 1)
        
        #copy qname, qtype, qclass
        dns_deny_packet += dns_deny_packet[40:40+length_of_q_name]
        dns_deny_packet += struct.pack('1H', 1)
        dns_deny_packet += struct.pack('!H', 1)

        dns_deny_packet += struct.pack('!L', 1)
        dns_deny_packet += struct.pack('!H', 4)

        dns_deny_packet += socket.inet_aton('54.173.224.150')

        udp_length = len(dns_deny_packet) - 20
        dns_deny_packet = dns_deny_packet[0:24] + struct.pack('!H',udp_length) + dns_deny_packet[26:]

        dns_deny_packet_length = len(dns_deny_packet)
        dns_deny_packet = dns_deny_packet[0:2] + struct.pack('!H', dns_deny_packet_length) + dns_deny_packet[4:]

        ip_checksum = struct.pack('!H', self.calculate_ipv4_checksum(20, dns_deny_packet))
        dns_deny_packet = dns_deny_packet[0:10] + ip_checksum + dns_deny_packet[12:]

        udp_checksum = struct.pack('!H', self.calculate_tcp_or_udp_checksum(20,dns_deny_packet))
        dns_deny_packet = dns_deny_packet[0:26] + udp_checksum + dns_deny_packet[28:]

        return dns_deny_packet



    def calculate_tcp_or_udp_checksum(self, header_len, packet):
        total_len = struct.unpack('!H', packet[2:4])[0]
        if total_len % 2 != 0:
            packet += struct.pack('!B',0)
            total_len += 1
        
        count = header_len
        check_sum = 0
        #An odd number of bytes just has a trailing zero byte added to make the total number even.
        protocol = struct.unpack('!B', packet[9:10])[0]
        if protocol == 6:
            while count < total_len:
                if count ==  header_len + 16:
                    count += 2
                    continue
                check_sum += struct.unpack('!H', packet[count:count+2])[0]
                count += 2
        elif protocol == 17:
            while count < total_len:
                if count == header_len + 6:
                    count += 2
                    continue
                check_sum += struct.unpack('!H', packet[count:count+2])[0]
                count += 2
        else:
            pass
        #tcp or udp need to add ip address to check sum
        #struct.unpack requires a string argument of length 2, so we split it two parts!
        src_ip = struct.unpack('!H', packet[12:14])[0]
        src_ip_2 = struct.unpack('!H', packet[14:16])[0]
        dst_ip = struct.unpack('!H', packet[16:18])[0]
        dst_ip_2 = struct.unpack('!H', packet[18:20])[0]
        check_sum = check_sum + src_ip + src_ip_2 + dst_ip + dst_ip_2

        check_sum += protocol

        check_sum += (total_len - header_len)

        high_16_bit = check_sum >> 16
        low_16_bit = check_sum & 0xffff
        check_sum = high_16_bit + low_16_bit
        check_sum = (~check_sum)
        check_sum = check_sum & 0xffff
        return check_sum

    def calculate_ipv4_checksum(self, ipv4_header_len, packet):
        check_sum = 0
        count = 0
        #set ip header's check sum = 0
        #add all ip header without check sum, so we skip 10-12
        while count < ipv4_header_len:
            if count == 10:
                count += 2
                continue
            check_sum += struct.unpack('!H', packet[count:count+2])[0]
            count += 2
        #EX: check_sum = 0x3c353, high_16_bit = 3, low_16_bit = c353
        high_16_bit = check_sum >> 16
        low_16_bit = check_sum & 0xffff
        check_sum = high_16_bit + low_16_bit
        #two complements c353 -> 3ca9
        check_sum = ~(check_sum)
        check_sum = check_sum & 0xffff
        return check_sum
    
    #Given two connections, check these two 5 tuples are equal
    def is_same_http_connection(self, http_record, map_http_record):
        #tuple is hard to compare, so we use set to judge!
        http_record_set = set(http_record)
        map_http_record_set = set(map_http_record)
        return (http_record_set.issubset(map_http_record_set)) and (map_http_record_set.issubset(http_record_set))

    def is_send_http_message(self, packet, http_message_type, http_connection, tcp_record):
        ip_header_length = ord(packet[0:1]) & 0x0f
        ip_header_length = ip_header_length * 4
        sequence_number = struct.unpack('!L',packet[ip_header_length+4:ip_header_length+8])[0]
        tcp_header_length = ord(packet[ip_header_length+12:ip_header_length+13]) >> 4
        tcp_header_length = tcp_header_length * 4
        packet_length = struct.unpack('!H', packet[2:4])[0]
        #http start location 
        http_start_offset = tcp_header_length + ip_header_length
        #packet skip ip header and tcp header
        payload_length = packet_length - tcp_header_length - ip_header_length
        if http_message_type == 'REQUEST':
            if not http_connection.is_request_finish and payload_length > 0:
                #first packet in the http request
                if http_connection.expected_request_seq_num is None:
                    #check whether it is valid http request header
                    if (packet[http_start_offset:http_start_offset+3] == 'GET') or (packet[http_start_offset:http_start_offset+3] == 'PUT') or (packet[http_start_offset:http_start_offset+4] == 'POST') or (packet[http_start_offset:http_start_offset+4] == 'DROP'):
                        http_connection.expected_request_seq_num = sequence_number + payload_length
                        count = http_start_offset
                        #append payload byte by byte.
                        while count < packet_length:
                            http_connection.append_to_request(packet[count:count+1])
                            if len(http_connection.request) >= 4:
                                #check whether we reach the end of http request header
                                if http_connection.request[-4:] == '\r\n\r\n':
                                    http_connection.is_request_finish = True
                                    break
                            count = count + 1
                    else:
                        #not valid http request
                        print 'not valid http request header'
                        return True
                else:
                    if sequence_number > http_connection.expected_request_seq_num:
                        print 'out of order packet!'
                        return False
                    elif sequence_number == http_connection.expected_request_seq_num:
                        http_connection.expected_request_seq_num = sequence_number + payload_length
                        count = http_start_offset
                        #append payload byte by byte.
                        while count < packet_length:
                            http_connection.append_to_request(packet[count:count+1])
                            if len(http_connection.request) >= 4:
                                #check whether we reach the end of http request header
                                if http_connection.request[-4:] == '\r\n\r\n':
                                    http_connection.is_request_finish = True
                                    break
                            count = count + 1
                    else:
                        return True
        elif http_message_type == 'RESPONSE':
            if not http_connection.is_response_finish and payload_length > 0:
                if http_connection.expected_response_seq_num is None:
                    print packet[http_start_offset:http_start_offset+4]
                    #if the packet is not a valid first http response, drop it!
                    if packet[http_start_offset:http_start_offset+4] == 'HTTP':
                        http_connection.expected_response_seq_num = sequence_number + payload_length
                        count = http_start_offset
                        while count < packet_length:
                            http_connection.append_to_response(packet[count:count+1])
                            if len(http_connection.response) >= 4:
                                if http_connection.response[-4:] == '\r\n\r\n':
                                    http_connection.is_response_finish = True
                                    break
                            count = count + 1
                    else:
                        return True
                else:
                    if sequence_number > http_connection.expected_response_seq_num:
                        print 'out of order packet!'
                        return False
                    elif sequence_number == http_connection.expected_response_seq_num:
                        http_connection.expected_response_seq_num = sequence_number + payload_length
                        count = http_start_offset
                        while count < packet_length:
                            http_connection.append_to_response(packet[count:count+1])
                            if len(http_connection.response) >= 4:
                                if http_connection.response[-4:] == '\r\n\r\n':
                                    http_connection.is_response_finish = True
                                    break
                            count = count + 1
                    else:
                        return True
        else:
            pass

        if http_connection.is_request_finish and http_connection.is_response_finish:
            print http_connection
        return True

    #parse the http_connection and write to log
    def write_to_log(self, http_connection, exteral_ip):
        line_to_write_to_log = ''
        host_name_is_ip_addr = False
        hostname = ''
        #request messsage can find host, mean hostname is domain name instead of ip address
        if http_connection.request.find('Host:') != -1:
            start = http_connection.request.index('Host:')
            start += 6
            while http_connection.request[start] != '\n':
                hostname += http_connection.request[start]
                start += 1
            hostname = hostname.strip()
            if hostname.translate(None,'.').isdigit():
                host_name_is_ip_addr = True
        else:
            host_name_is_ip_addr = True
            hostname = exteral_ip

        if self.is_record_http_log(hostname, host_name_is_ip_addr):
            line_to_write_to_log += hostname
            line_to_write_to_log += ' '
            request_line = http_connection.request.split('\n')
            response_line = http_connection.response.split('\n')

            method = request_line[0].split(' ')[0].strip()
            line_to_write_to_log += method
            line_to_write_to_log += ' '
            path = request_line[0].split(' ')[1].strip()
            line_to_write_to_log += path
            line_to_write_to_log += ' '

            version = request_line[0].split(' ')[2].strip()
            line_to_write_to_log += version
            line_to_write_to_log += ' '

            status_code = response_line[0].split(' ')[1].strip()
            line_to_write_to_log += status_code
            line_to_write_to_log += ' '

            content_length = ''
            if http_connection.response.find('Content-Length:') != -1:
                start = http_connection.response.index('Content-Length:')
                start = start + 15
                while http_connection.response[start] != '\n':
                    content_length += http_connection.response[start]
                    start += 1
                content_length = content_length.strip()
            else:
                content_length = '-1'

            if not http_connection.is_written_connection:
                log_file = open('http.log','a')
                log_file.write(line_to_write_to_log)
                log_file.flush()
                http_connection.is_written_connection = True
                


    #Given http log rules, judge whether we record this hostname!
    def is_record_http_log(self, hostname, is_ip_addr):
        print hostname
        print is_ip_addr
        print 'EEEEEEEEEEEEEEEEEEEEaaaaaaaaaaaaaaa'
        for http_rule in self.http_rules:
            if http_rule.hostname_type == 'IP':
                if not is_ip_addr:
                    continue
                elif hostname == http_rule.hostname:
                    return True
            elif http_rule.hostname_type == 'WILDCARD':
                if is_ip_addr:
                    continue
                elif hostname.endswith(http_rule.hostname):
                    return True

            elif http_rule.hostname_type == 'EXACT':
                if is_ip_addr:
                    continue
                elif hostname == http_rule.hostname:
                    return True

            elif http_rule.hostname_type == 'ANY':
                return True
        return False



# TODO: You may want to add more classes/functions as well.
