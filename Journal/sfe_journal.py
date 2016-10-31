#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys, getopt
import time
import struct
import re
import binascii

g_version = "2.4.x"

g_file_name = ""

g_msgtype_list = []
g_not_msgtype_list = []
g_contrnum_list = []
g_subid_exclude_list = [255] # by default we don't take heatbeat msg, g_subid_list can overwrite it.
g_subid_list = []
g_keywords = ""
g_num_of_msg = -1
g_show_packet = False
g_hit_msg_max = False
g_sequence_num = 0
g_delimiter = '|'
g_CR_LF = '\r\n'
g_rec_mode = False
g_tcp_data_buffer = ''
g_tcp_data_expected = 0

SUBID_RECOVERY = 3 # from tcp recovery mode, different protocal data format

CMD_Interpret = 1
CMD_Generate = 2
CMD_Version = 4
CMD_Help = 8

JNL_ONE_PAGE_SIZE = 1024*8
PCK_SIZE_MAX = 1400
REC_SIZE_MAX = 512
SINGLE_CONTR_NUM_IDX = [2]
NO_CONTR_NUM_IDX = []
PASS_CONTR_NUM_IDX = [-1]

PACKET_HEADER_FORMAT = '>10sQH'
PACKET_HEADER_SIZE = 20
MESSAGE_HEADER_FORMAT = '>Hc' #data message header, contains message type?
MESSAGE_HEADER_SIZE = 3
MESSAGE_HEADER_TYPE = 1
MESSAGE_FORMAT_T = '>I' # time
MESSAGE_FORMAT_S = '>IHc' # system event
MESSAGE_FORMAT_L = '>IHIQqq' # Tick Size Table

MESSAGE_FORMAT_R = '>IHI32s32s12s6s6sBIIq3sBQ10s' #Equity Symbol Directory
MESSAGE_FORMAT_f = '>IHI32s60s12s6s6s6sHBBIIIq3sQBHBII' # Future symbol directory
MESSAGE_FORMAT_h = '>IHI32s60s12s6s6s6sHBcqIBIIBIIIqQ3sQBHBII10s' # Option Symbol Directory
MESSAGE_FORMAT_M = '>IHI32s60s6sBBIIBIcIqIcIqIcIqIcIqIcIqIcIq' # Combination Symbol Directory
#MESSAGE_FORMAT_m = '>IHI32s60s6sBBIIB?(IcIq)' # Bundles Symbol Directory, variable array in '()', size followed by '?'
MESSAGE_FORMAT_m = '>IHI32s60s6sBBIIBIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIqIcIq'
MESSAGE_FORMAT_g = '>IHI6scIIBBBIH' #Spread Symbol Directory
MESSAGE_FORMAT_O = '>IHIc' # Order Book State

MESSAGE_FORMAT_A = '>IHIcQQIq' # Order Added
MESSAGE_FORMAT_F = '>IHIcQQIq3s' # Order Added with Participant Id
MESSAGE_FORMAT_U = '>IHIcQQIq' # Order Replaced
MESSAGE_FORMAT_X = '>IHIcQI' # Order Volume Cancelled
MESSAGE_FORMAT_D = '>IHIcQ' # Order Deleted
MESSAGE_FORMAT_j = '>IHIcQQIq' # Implied Order Added
MESSAGE_FORMAT_l = '>IHIcQQIq' # Implied Order Replaced
MESSAGE_FORMAT_k = '>IHIcQ' # Implied Order Deleted
#MESSAGE_FORMAT_n = '>IHQII' # Custom Market Order Replaced
MESSAGE_FORMAT_r = '>IHQ' # Custom Market Order Deleted

MESSAGE_FORMAT_E = '>IHIcQIcQIqQ3s' # Order Executed
MESSAGE_FORMAT_C = '>IHIcQIcQIqQ' # Auction Order Executed
MESSAGE_FORMAT_e = '>IHIcQIcQIqIcQQ' # Combination Order Executed
MESSAGE_FORMAT_P = '>IHIcQIqQ3s3s' # Trade Executed
#MESSAGE_FORMAT_u = '>IHQIcIIiIcc' # Custom Market Executed
MESSAGE_FORMAT_p = '>IHIcQIqIcQQ3sIcQQ3s' # Custom Market Trade
MESSAGE_FORMAT_B = '>IHIQ' # Trade Cancellation

MESSAGE_FORMAT_Z = '>IHIqQQQ' # Equilibrium Price
MESSAGE_FORMAT_t = '>IHIqqqqIQ' # Open, High, Low, Last Trade Adjustment
MESSAGE_FORMAT_Y = '>IHIQQic' # Market Settlement
MESSAGE_FORMAT_x = '>IH6s100s' # Text Message
MESSAGE_FORMAT_q = '>IHIcI' # Request for Quote
MESSAGE_FORMAT_Q = '>IHIcQIqc4sI' # Trade Report
MESSAGE_FORMAT_V = '>IHIQQH' # Volume and Open Interest
MESSAGE_FORMAT_W = '>IHIqqqqqq' # Anomalous Order Threshold Publish

MESSAGE_FORMAT_G = '>Q'

MESSAGE_FORMAT_MAP = {
    'T': (MESSAGE_FORMAT_T, PASS_CONTR_NUM_IDX, False),
    'S': (MESSAGE_FORMAT_S, NO_CONTR_NUM_IDX, False),
    'L': (MESSAGE_FORMAT_L, NO_CONTR_NUM_IDX,False),
    'R': (MESSAGE_FORMAT_R, SINGLE_CONTR_NUM_IDX,False),
    'f': (MESSAGE_FORMAT_f, SINGLE_CONTR_NUM_IDX,False),
    'h': (MESSAGE_FORMAT_h, SINGLE_CONTR_NUM_IDX,False),
    'M': (MESSAGE_FORMAT_M, SINGLE_CONTR_NUM_IDX,False),
    'm': (MESSAGE_FORMAT_m, SINGLE_CONTR_NUM_IDX,False),
    'g': (MESSAGE_FORMAT_g, SINGLE_CONTR_NUM_IDX,False),
    'O': (MESSAGE_FORMAT_O, SINGLE_CONTR_NUM_IDX,False),
    
    'A': (MESSAGE_FORMAT_A, SINGLE_CONTR_NUM_IDX,False),
    'U': (MESSAGE_FORMAT_U, SINGLE_CONTR_NUM_IDX,False),
    'X': (MESSAGE_FORMAT_X, SINGLE_CONTR_NUM_IDX,False),
    'D': (MESSAGE_FORMAT_D, SINGLE_CONTR_NUM_IDX,False),
    'F': (MESSAGE_FORMAT_F, SINGLE_CONTR_NUM_IDX,False),
    'j': (MESSAGE_FORMAT_j, SINGLE_CONTR_NUM_IDX,False),
    'l': (MESSAGE_FORMAT_l, SINGLE_CONTR_NUM_IDX,False),
    'k': (MESSAGE_FORMAT_k, SINGLE_CONTR_NUM_IDX,False),
    #'n': (MESSAGE_FORMAT_n, NO_CONTR_NUM_IDX),
    'r': (MESSAGE_FORMAT_r, NO_CONTR_NUM_IDX,False),
    
    'E': (MESSAGE_FORMAT_E, SINGLE_CONTR_NUM_IDX,False),
    'C': (MESSAGE_FORMAT_C, SINGLE_CONTR_NUM_IDX,False),
    'e': (MESSAGE_FORMAT_e, SINGLE_CONTR_NUM_IDX,False),#[2,10]),
    'P': (MESSAGE_FORMAT_P, SINGLE_CONTR_NUM_IDX,False),#[2,6]),
    #'u': (MESSAGE_FORMAT_u, [8]), deleted ?
    'p': (MESSAGE_FORMAT_p, SINGLE_CONTR_NUM_IDX,False),#[2,12]),
    'B': (MESSAGE_FORMAT_B, NO_CONTR_NUM_IDX,False),

    'Z': (MESSAGE_FORMAT_Z, SINGLE_CONTR_NUM_IDX,False),
    't': (MESSAGE_FORMAT_t, SINGLE_CONTR_NUM_IDX,False),
    'Y': (MESSAGE_FORMAT_Y, SINGLE_CONTR_NUM_IDX,False),
    'x': (MESSAGE_FORMAT_x, NO_CONTR_NUM_IDX,False),
    'q': (MESSAGE_FORMAT_q, SINGLE_CONTR_NUM_IDX,False),
    'Q': (MESSAGE_FORMAT_Q, SINGLE_CONTR_NUM_IDX,False),
    'V': (MESSAGE_FORMAT_V, SINGLE_CONTR_NUM_IDX,False),
    'W': (MESSAGE_FORMAT_W, SINGLE_CONTR_NUM_IDX,False),
    'G': (MESSAGE_FORMAT_G, NO_CONTR_NUM_IDX, False)
    }

DIGIT_FORMAT='QHBIiq'
STRING_FORMAT='sc'
PACKET_HEADER_LABEL='=> '
PACKET_HEADER_LABEL_LEN = len(PACKET_HEADER_LABEL)
PACKET_HEADER_LABEL_SEND='<= '
PACKET_HEADER_LABEL_SEND_LEN = len(PACKET_HEADER_LABEL_SEND)
PACKET_INFO_END='_> '
PACKET_INFO_SEND_END='_< '
PACKET_INFO_END_START = 30
PACKET_INFO_END_STOP = PACKET_INFO_END_START + len(PACKET_INFO_END)

PageHeadFormat = 'IIIIQQHHI'
PageHeadSize = struct.calcsize(PageHeadFormat)
PageHeadProperties = ['version', 'offset', 'jnl_page_size', 'systime',
                      'hp_counter', 'hp_frequency', 'milliseconds', 'spare_0',
                      'systime_high_lw']

PackageHeadFormat = 'IHHIIQ'
PackageHeadSize = struct.calcsize(PackageHeadFormat)
PackageHeadProperties = ['dep', 'bf0', 'compid', 'size', 'spare_0', 'hp_counter']


#A,J,S,H,Y,Z | L,R,O,W
GlanceResponse = '>Hc' # H,Z | R,O 
# response
GlanceLoginAccept = '>Hc10sQ' # A
GlanceLoginReject = '>Hcii' # J
GlancePasswordChangeResponse = '>Hc64s64si' # Y
GlanceSequencedData = '>Hcc' # S
# request
GlanceLoginRequest = '>Hc64s64s64sii12s' # L
GlancePasswordChangeRequest = '>Hc64s64s64s64s' # W

GLANCE_FORMAT_MAP = {
    # heartbeat, session end, logout
    'H': GlanceResponse,
    'R': GlanceResponse,
    'O': GlanceResponse,
    'Z': GlanceResponse,
    # login
    'L': GlanceLoginRequest,
    'A': GlanceLoginAccept,
    'J': GlanceLoginReject,
    # password
    'W': GlancePasswordChangeRequest,
    'Y': GlancePasswordChangeResponse,
    # sequenced data
    'S': GlanceSequencedData
    }

def ParsePageHead(read):
    """
    Parse the Journal head
    """
    page_head = {}
    result = struct.unpack_from(PageHeadFormat, read, 0)
    for i in xrange(len(PageHeadProperties)):
        page_head[PageHeadProperties[i]] = result[i]
    return page_head

def ProcessPageHead(journal):
    page_head = {}
    read = journal.read(PageHeadSize)
    if read != '':
        page_head = ParsePageHead(read)
    return page_head

def ParsePackageHead(read):
    package_head = {}
    result = struct.unpack_from(PackageHeadFormat, read, 0)
    for i in xrange(len(PackageHeadProperties)):
        package_head[PackageHeadProperties[i]] = result[i]
    return package_head

def get_output_raw_name(journal_file_name, output_type='txt'):
    """
    get output file's raw name, without .txt or .csv
    """
    dot_pos = journal_file_name.rfind('.')
    if dot_pos != -1:
        output_file_name = journal_file_name[0: dot_pos]
    else:
        output_file_name = journal_file_name
    num_of_output = 1
    if output_type == 'txt':
        while True:
            output_file = '%s_%d.txt'%(output_file_name,num_of_output)
            if not os.path.exists(output_file):
                break
            else:
                num_of_output += 1
    else:
        output_file = '%s.%s'%(output_file_name,output_type)
    return output_file

def checkContractNumber(message_body,match_map):
    if g_contrnum_list == []:
        return True
    if len(match_map[1]) == 0:
        return False
    if match_map[1][0] == -1: # msg should pass contract checking
        return True
    else:
        match = False
        for i in xrange(len(g_contrnum_list)):
            if match:
                break
            for j in match_map[1]:
                if str(message_body[j]).find(str(g_contrnum_list[i])) != -1:
                    match = True
                    break
        return match

def ParseJnlTime(PageHeader,PktHeader):
    l_time_delta = 0
    if PageHeader['hp_counter'] <= PktHeader['hp_counter']:
        l_time_delta = PktHeader['hp_counter'] - PageHeader['hp_counter']
    elif PageHeader['hp_counter'] <= PktHeader['hp_counter']+PageHeader['hp_frequency']:
        l_time_delta = 0;
    else:
        l_time_delta = PktHeader['hp_counter'] + 0x7FFFFFFFFFFFFFFF - PageHeader['hp_counter']

    jnl_time = 0
    jnl_time_micro = 0
    l_ms_deltra = 0
    l_micro_delta = 0
    if PageHeader['hp_frequency'] != 0:
        l_ms_delta = l_time_delta % PageHeader['hp_frequency'] * 1000.0 / PageHeader['hp_frequency']
        jnl_time = PageHeader['systime'] + (l_time_delta/PageHeader['hp_frequency']) + (l_ms_delta + PageHeader['milliseconds'])/1000
        l_micro_delta = (l_time_delta % PageHeader['hp_frequency']) * 1000000.0 / PageHeader['hp_frequency']
    else:
        jnl_time = PageHeader['systime']
    jnl_time_micro = (l_micro_delta + PageHeader['milliseconds']*1000)%1000000

    return jnl_time, jnl_time_micro
    
def formatMessage(message_format,text_line):
    message_line = []
    idx = 0
    for i in  xrange(len(message_format)):
        if DIGIT_FORMAT.find(message_format[i]) != -1: # digit
            message_line.append(int(text_line[idx]))
            idx += 1
        elif STRING_FORMAT.find(message_format[i]) != -1: # string
            message_line.append(text_line[idx])
            idx += 1
        else: # skip it 
            pass
    return message_line

def formatJnlTime(page_header,package_header):
    jnl_time,jnl_time_micro = ParseJnlTime(page_header,package_header)
    str_jnl_time_txt = ('%s.%06d ') % (time.strftime("%Y/%m/%d %H:%M:%S",time.gmtime(jnl_time)),int(jnl_time_micro))
    return str_jnl_time_txt

def findJnlVariableNum(match_str,msg_body_dat):
    # pattern: >XXXB?(XXX)
    var_index = match_str.find('?')
    offset = struct.calcsize(match_str[0:var_index]) # calculate offset for array count (->X?)
    ret = struct.unpack(match_str[0][0]+match_str[var_index-1],msg_body_dat[offset-1])
    return int(ret[0])

def findTxtVariableNum(match_str,msg_list):
    # pattern: >XXXB?(XXX)
    var_index = match_str.find('?')
    i = 0
    var_list_index = 0
    while(i < var_index):
        if DIGIT_FORMAT.find(match_str[i]) != -1: 
            var_list_index += 1
        elif STRING_FORMAT.find(match_str[i]) != -1: 
            var_list_index += 1
        else: # skip it 
            pass
        i += 1
    return int(msg_list[var_list_index-1])

def makeVariableMatch(match_str, var_num):
    start = match_str.rfind('(')
    end = match_str.rfind(')')
    repeat_str = match_str[start+1:end]
    array_str = ""
    i=0
    while(i<var_num):
        array_str += repeat_str
        i+=1
    return match_str.replace('?','')[0:start-1]+array_str+match_str[end+1:]

def parseRecoveryPacket(body_data, msgtype_list, sub_id, is_send_msg,str_jnl_time_txt):
    global g_tcp_data_expected
    global g_tcp_data_buffer
    
    txt_file_output = []
    num_of_messages = 0

    HeaderLengthPart = '>H'
    header_length_size = 2 #struct.calcsize(HeaderLengthPart)
    body_data_len = len(body_data)    
    data_start = 0
    processed_size = 0

    while (data_start < body_data_len):
        remaining_size = body_data_len - data_start
        one_msg_ready = False
        copy_size_offset = 0
        if(len(g_tcp_data_buffer) == 0):
            # no buffer, start from begining
            if (remaining_size >= header_length_size ): # remaining length no less than length in glance header
                glance_header_len = struct.unpack(HeaderLengthPart,body_data[data_start:data_start+header_length_size])
                one_msg_size = glance_header_len[0] + header_length_size # msg len =  length + sizeof(lengh part)
                if (one_msg_size <= remaining_size):
                    # complete message
                    copy_size_offset = one_msg_size
                    one_msg_ready = True
                else:
                    # incomplete msg, buffer remaining and wait for rest part
                    copy_size_offset = remaining_size               
                    g_tcp_data_expected = one_msg_size - remaining_size
            else:
                # smaller then minimal requirement, buffer and wait for rest part
                copy_size_offset = remaining_size
                # don't know the msg_size, so set it to zero
                g_tcp_data_expected = 0 
            
        else:
            # in the middle of a msg, try to copy the expected size
            if( g_tcp_data_expected == 0):
                # can't parse the message length in previous reading
                # read 1 more byte and figure out the msg length
                g_tcp_data_buffer += body_data[data_start : data_start+1]
                glance_header_len = struct.unpack(HeaderLengthPart,g_tcp_data_buffer[0:header_length_size])
                # no need to add len size, since buffer already includes length part
                g_tcp_data_expected = glance_header_len[0]
                data_start += 1
        
            if(g_tcp_data_expected <= remaining_size):
                # one complete msg
                copy_size_offset = g_tcp_data_expected
                one_msg_ready = True
            else:
                # still in complete msg, copy remaining
                copy_size_offset = remaining_size
                g_tcp_data_expected -= remaining_size

        # copy data into tcp buffer
        g_tcp_data_buffer += body_data[data_start: data_start+copy_size_offset]

        data_start += copy_size_offset

        if one_msg_ready:
            # one complete messaeg, parse it
            txt_output = parseRecoveryMessage(msgtype_list, sub_id, is_send_msg,str_jnl_time_txt)
            # buffer comsumed, clear it
            g_tcp_data_buffer = ''
            g_tcp_data_expected = 0

            if len(txt_output) > 0:
                txt_file_output.append(txt_output)
                num_of_messages += 1
    
    return txt_file_output, num_of_messages

def parseRecoveryMessage(msgtype_list, sub_id, is_send_msg,str_jnl_time_txt):
    # parse one complete message
    packet_info_delimitor = PACKET_INFO_END
    if is_send_msg:
        packet_info_delimitor = PACKET_INFO_SEND_END

    # process glance message header
    glance_header_data = struct.unpack(GlanceResponse,g_tcp_data_buffer[0:struct.calcsize(GlanceResponse)])  
    msg_header_format,msg_body_format,seq_msg_type = findGlanceFormatForI(glance_header_data,g_tcp_data_buffer)

    processed = False
    result = []
    data_start = 0
    if (msg_header_format != ''):
        message_header = struct.unpack(msg_header_format,g_tcp_data_buffer[0:struct.calcsize(msg_header_format)])
        for i in xrange(len(message_header)):
            result.append(str(message_header[i]));

        processed = True
        data_start += struct.calcsize(msg_header_format)

    if (msg_body_format != ''): 
        # msg SequenceData
        if (g_msgtype_list == []) or (seq_msg_type in msgtype_list):
            match_map_str = ""
            try:
                if(msg_body_format[2] == True): # variable message
                    match_map_str = makeVariableMatch(match_map[0],findJnlVariableNum(match_map[0],g_tcp_data_buffer[data_start:]))
                else:    
                    match_map_str = msg_body_format[0]

                # parse message boday part
                message_body = struct.unpack(match_map_str, g_tcp_data_buffer[data_start:data_start+struct.calcsize(match_map_str)])
                
                for i in xrange(len(message_body)):
                    result.append(str(message_body[i]));
                
            except Exception,ex:
                print Exception,":",ex

            processed = True

    str_output = ''
    if processed:
        # output message body
        output = ''
        output += g_delimiter.join(result)
        str_output = ('%s(%u)%s%s%s')%(str_jnl_time_txt,sub_id,packet_info_delimitor,output,g_CR_LF)
        
    return str_output
    
def parseMessagePacket(body_data, msgtype_list, sub_id, is_send_msg,str_jnl_time_txt):
    global g_hit_msg_max
    
    txt_file_output = []
    num_of_messages = 0

    data_start = 0
    # read packet header
    pck_header_dat = body_data[data_start:PACKET_HEADER_SIZE] 
    data_start = PACKET_HEADER_SIZE

    if (pck_header_dat == ''):
        print 'Error! fail to read packet_header'
        return [],0

    session_id,sequence,msg_count=struct.unpack(PACKET_HEADER_FORMAT, pck_header_dat)
    count_each_packet = 0

    pck_header_label_str = PACKET_HEADER_LABEL
    if is_send_msg == True:
        pck_header_label_str = PACKET_HEADER_LABEL_SEND

    if g_show_packet:
        packet_header_str = ('%s%s(%u)%s%s%s%u%s%u%s')%(pck_header_label_str,str_jnl_time_txt,sub_id,PACKET_INFO_END,
                                                        session_id,g_delimiter,sequence,g_delimiter,msg_count,g_CR_LF)
        txt_file_output.append(packet_header_str) # output packet header

    while(count_each_packet<msg_count): # parse message inside one packet                             
        result = []
        
        # read mesage header
        msg_header_dat = body_data[data_start : data_start+MESSAGE_HEADER_SIZE] 
        data_start += MESSAGE_HEADER_SIZE 
        if msg_header_dat == '':
            break
            
        # parse messgae header
        size,type=struct.unpack(MESSAGE_HEADER_FORMAT, msg_header_dat)
        # read message body
        msg_body_dat = body_data[data_start : data_start+size-MESSAGE_HEADER_TYPE]
        data_start += size-MESSAGE_HEADER_TYPE
        count_each_packet += 1

        # filter by message type
        if (g_msgtype_list == []) or (type in msgtype_list):
            result.append(str(size))
            result.append(type)
            # parse message body
            match_map = MESSAGE_FORMAT_MAP.get(type,())
            if(len(match_map)==0):
                str_output = ('%s(%u)%s Not Supported:%c%s')%(str_jnl_time_txt,sub_id,PACKET_INFO_END,type,g_CR_LF)
                txt_file_output.append(str_output) 
                num_of_messages += 1
                continue

            try:
                match_map_str = ""
                if(match_map[2] == True): # variable message
                    match_map_str = makeVariableMatch(match_map[0],findJnlVariableNum(match_map[0],msg_body_dat))
                else:    
                    match_map_str = match_map[0]
                message_body = struct.unpack(match_map_str, msg_body_dat)

                # filter by contract number
                if checkContractNumber(message_body,match_map):
                    for i in xrange(len(message_body)):
                        result.append(str(message_body[i]));

                    output = g_delimiter.join(result)

                    # filter by key words
                    if g_keywords == "" or output.find(g_keywords) != -1:
                        # output message body
                        str_output = ('%s(%u)%s%s%s')%(str_jnl_time_txt,sub_id,PACKET_INFO_END,output,g_CR_LF)
                        txt_file_output.append(str_output) 
                        num_of_messages += 1
                        if g_num_of_msg >0 and num_of_messages == g_num_of_msg:
                            g_hit_msg_max = True
                            break
            except Exception,ex:
                print ('Error for %c,%u')%(type,size)
                print Exception,":",ex
                num_of_messages += 1
    
    return txt_file_output,num_of_messages

def interpretJnl():
    global g_hit_msg_max
    '''
    Parse jnl file and convert it to readable text
    '''
    num_of_messages = 0
    size_processed = 0
    pre_percentage = 0
    file_size = os.path.getsize(g_file_name)

    output_file_name = get_output_raw_name(g_file_name)

    msgtype_list = []
    if g_msgtype_list == []:
        for item in MESSAGE_FORMAT_MAP.keys():
            if item not in g_not_msgtype_list:
                msgtype_list.append(item) 
    else:
        for raw_item in g_msgtype_list:
            item = raw_item.strip()
            if (item in MESSAGE_FORMAT_MAP) and (item not in g_not_msgtype_list):
                msgtype_list.append(item)
    
    jnl_file = open(g_file_name, 'rb')
    print 'Please stand by...'
    txt_file = open(output_file_name, 'w')

    g_hit_msg_max = False

    while True:
        page_header = ProcessPageHead(jnl_file) # read page header
        if page_header == {} or g_hit_msg_max:
            print '\rParsing...100%\n',
            sys.stdout.flush()
            break

        size_processed += PageHeadSize

        # load one page of data
        jnl_page_size = page_header['jnl_page_size']
        jnl_page_data = jnl_file.read(jnl_page_size - PageHeadSize)

        if jnl_page_data == '':
            break

        # process each package
        cursor_offset = 0
        end_of_page = page_header['offset']
        while (cursor_offset + PageHeadSize + PackageHeadSize < end_of_page):
            if g_hit_msg_max:
                break

            package_header = ParsePackageHead(jnl_page_data[cursor_offset : cursor_offset+PackageHeadSize])

            package_data_size = package_header['size']
            message_body = jnl_page_data[cursor_offset+PackageHeadSize : cursor_offset+package_data_size]

            sub_id = package_header['bf0'] >> 8 & 0x00FF
            
            if (g_subid_list==[] and sub_id not in g_subid_exclude_list) or (sub_id in g_subid_list):
                # parse one packet in each package
                str_jnl_time_txt = formatJnlTime(page_header,package_header)
                output_content = []
                num_of_msg = 0
                is_send_msg = False
                if (package_header['bf0'] & 0x0020) > 0 :
                    is_send_msg = True
                if g_rec_mode or sub_id == SUBID_RECOVERY:
                    output_content,num_of_msg = parseRecoveryPacket(message_body, msgtype_list, sub_id, is_send_msg,str_jnl_time_txt)
                else:
                    output_content,num_of_msg = parseMessagePacket(message_body, msgtype_list, sub_id, is_send_msg,str_jnl_time_txt)
                num_of_messages += num_of_msg

                # write to txt file
                if num_of_msg > 0:
                    txt_file.write(''.join(output_content))
                
            package_size = getSharpByte(package_data_size)# get the sharp bytes size
            cursor_offset += package_size

            # print progress
            size_processed += package_data_size #cursor_offset
            percentage = int(size_processed*100/file_size)

            if percentage - pre_percentage > 1:
                pre_percentage = percentage
                print '\rParsing...%d%%'%(percentage),
                sys.stdout.flush()
                
    jnl_file.close()
    txt_file.close()
    
    print 'Done: %d(msg)!'%num_of_messages
    print '->\n  %s'%output_file_name
    
def generateJnl():
    '''
    Convert readable text to jnl file
    '''

    output_file_name = get_output_raw_name(g_file_name,'sjl')
    journal_file = open(output_file_name, 'wb+')

    text_file = open(g_file_name, 'rb')
    file_line = ''

    session_id = 'ASX24TR123'
    if g_sequence_num == 0:
        # no sequence specified, calculate one to bypass arbitrator for injection purpose
        session_id = str(time.time())[0:10]

    sequence_num = g_sequence_num-1
    if sequence_num < 0 :
        sequence_num = 0
    msg_count = 0
    total_msg_size=0
    
    packet_header_msg = [session_id,sequence_num,msg_count]

    msg_content_out = []

    print 'Please stand by...'
    print '->\n %s'%output_file_name
    print 'Session:%s,Sequence:%d'%(session_id,sequence_num+1)

    while True:
        line_str = text_file.readline()
        
        if line_str == '':
            break
   
        # we don't take packet header, it will be calculated.
        elif line_str[0:PACKET_HEADER_LABEL_LEN] == PACKET_HEADER_LABEL: 
            continue
        elif line_str[0:PACKET_HEADER_LABEL_SEND_LEN] == PACKET_HEADER_LABEL_SEND: 
            continue

        if (len(line_str) > PACKET_INFO_END_STOP and line_str[PACKET_INFO_END_START:PACKET_INFO_END_STOP] == PACKET_INFO_END):
            msg_body_str = line_str[PACKET_INFO_END_STOP:] # don't take package header information part
            msg_list = msg_body_str.rstrip().strip(g_CR_LF).split(g_delimiter)
        else:
            msg_list = line_str.rstrip().strip(g_CR_LF).split(g_delimiter)

        if len(msg_list) < 3:
            continue
            
        msg_type = msg_list[1] # find msg_type
        if msg_type in MESSAGE_FORMAT_MAP:
            #msg header
            msg_header = formatMessage(MESSAGE_HEADER_FORMAT,msg_list[:2])
            new_msg_dat = struct.pack(MESSAGE_HEADER_FORMAT,*msg_header) 
            # msg body
            msg_format_arr = MESSAGE_FORMAT_MAP[msg_type]
            message_format = ""
            if(msg_format_arr[2] == True): # variable messgae like 'm'
                message_format = makeVariableMatch(msg_format_arr[0],findTxtVariableNum(msg_format_arr[0],msg_list[2:]))
            else:
                message_format = msg_format_arr[0]

            msg_body = formatMessage(message_format,msg_list[2:])
            new_msg_dat += struct.pack(message_format,*msg_body) 

            new_msg_size = len(new_msg_dat)
            sequence_num += 1
            if (new_msg_size + total_msg_size) < PCK_SIZE_MAX:
                # enough room to accommodate it
                file_line += new_msg_dat
                total_msg_size += new_msg_size
                msg_count += 1
            else:
                # hit packet size limitation, flush whole packet
                packPacketData(msg_content_out,packet_header_msg,sequence_num-msg_count,msg_count,file_line)
                # add the new message in
                total_msg_size = new_msg_size
                file_line = new_msg_dat
                msg_count  = 1

    if len(file_line) > 0:
        # flush all remaining data
        packPacketData(msg_content_out,packet_header_msg,sequence_num+1-msg_count,msg_count,file_line)

    writeJnlFile(msg_content_out, journal_file)
    
    text_file.close()
    journal_file.close()

def generateRecJnl():
    output_file_name = get_output_raw_name(g_file_name,'sjl')
    journal_file = open(output_file_name, 'wb+')

    text_file = open(g_file_name, 'rb')
    file_line = ''

    msg_count = 0
    total_msg_size=0
    

    msg_content_out = []

    print 'Generating Feed Recovery Journal'
    print 'Please stand by...'    
    print '->\n %s'%output_file_name

    while True:
        line_str = text_file.readline()
        
        if line_str == '':
            break
            
        # we don't take packet header, it will be calculated.
        elif line_str[0:PACKET_HEADER_LABEL_LEN] == PACKET_HEADER_LABEL: 
            continue
        elif line_str[0:PACKET_HEADER_LABEL_SEND_LEN] == PACKET_HEADER_LABEL_SEND:
            continue

        packet_info_end_index = line_str.find(PACKET_INFO_END)
        if packet_info_end_index != -1:
            msg_body_str = line_str[packet_info_end_index+PACKET_INFO_END_LEN:] # don't take package header information part
            msg_list = msg_body_str.rstrip().strip(g_CR_LF).split(g_delimiter)
        else:
            msg_list = line_str.rstrip().strip(g_CR_LF).split(g_delimiter)


        if len(msg_list) < 3:
            continue

        msg_header_format,msg_body_format = findGlanceFormatForG(msg_list)

        body_start_index = 3
        
        #msg header
        msg_header = formatMessage(msg_header_format,msg_list[:body_start_index])
        new_msg_dat = struct.pack(msg_header_format,*msg_header) 

        # msg body
        message_format = ""
        if(msg_body_format[2] == True): # variable messgae like 'm'
            message_format = makeVariableMatch(msg_body_format[0],findTxtVariableNum(msg_body_format[0],msg_list[body_start_index:]))
        else:
            message_format = msg_body_format[0]

        msg_body = formatMessage(message_format,msg_list[body_start_index:])
        new_msg_dat += struct.pack(message_format,*msg_body) 

        new_msg_size = len(new_msg_dat)

        if (new_msg_size + total_msg_size) < REC_SIZE_MAX:
            # enough room to accommodate it
            file_line += new_msg_dat
            total_msg_size += new_msg_size
        else:
            # hit packet size limitation, flush whole packet
            msg_content_out.append(file_line)
            # add the new message in
            total_msg_size = new_msg_size
            file_line = new_msg_dat

    if len(file_line) > 0:
        # flush all remaining data
        msg_content_out.append(file_line)

    writeJnlFile(msg_content_out, journal_file)

    text_file.close()
    journal_file.close()

    
def writeJnlFile(msg_content_out, journal_file):
    
    # flush packets data into jnl file
    PAGE_OFFSET_IDX = 1
    PACKAGE_SIZE_IDX = 3

    journal_page_head = [3, 0, JNL_ONE_PAGE_SIZE, int(time.time()), 377494019448199, 2396910000, 55, 0, 0]
    journal_package_head = [0, 1, 0, 0, 0, 377600777978373]

    total_package_count = len(msg_content_out)
    package_idx = 0
    while package_idx < total_package_count:
        
        page_len_ctrl = 0
        page_len_ctrl += PageHeadSize
        package_output = []
        while (package_idx < total_package_count):
            one_packet_data = msg_content_out[package_idx]
            package_msg_size =  PackageHeadSize + len(one_packet_data)
            # aligne it by 4 byte
            aligned_package_msg_size = getSharpByte(package_msg_size)
            if (page_len_ctrl+aligned_package_msg_size < JNL_ONE_PAGE_SIZE):
                # enough space, pack this package into current page
                journal_package_head[PACKAGE_SIZE_IDX] = package_msg_size # update message size in package header
                package_header_data = struct.pack(PackageHeadFormat, *journal_package_head)
                package_output.append(package_header_data + one_packet_data + ('\x00'*(aligned_package_msg_size - package_msg_size)))
                page_len_ctrl += aligned_package_msg_size
                package_idx += 1
            else:
                break # no room left, put it in next page

        # update page offset in page header
        journal_page_head[PAGE_OFFSET_IDX] = page_len_ctrl #next_package_offset + PageHeadSize
        page_header_dat = struct.pack(PageHeadFormat, *journal_page_head)
        
        journal_file.write(page_header_dat)
        for index in xrange(len(package_output)):
            journal_file.write(package_output[index])
        journal_file.write('\x00'*(JNL_ONE_PAGE_SIZE - page_len_ctrl))
    
def findGlanceFormatForI(msg_list,raw_data):
    # used for glance interpretation
    msg_header=''
    msg_body=''
    msg_type = ''
    type = msg_list[1]
    if type in GLANCE_FORMAT_MAP:
        msg_header = GLANCE_FORMAT_MAP[type]

    if(type == 'S'):
        # sequenced data
        ret = struct.unpack(GlanceSequencedData,raw_data[:struct.calcsize(GlanceSequencedData)])
        msg_type = ret[2]
            
        if msg_type in MESSAGE_FORMAT_MAP:
            msg_body = MESSAGE_FORMAT_MAP[msg_type]

    # return glance header format, sequence msg format, sequence msg type        
    return msg_header,msg_body,msg_type

def findGlanceFormatForG(msg_list):
    # used for glance generation
    msg_header=''
    msg_body=''
    type = msg_list[1]
    if type in GLANCE_FORMAT_MAP:
        msg_header = GLANCE_FORMAT_MAP[type]

    if(type == 'S'):
        # sequenced data
        msg_type = msg_list[2]
            
        if msg_type in MESSAGE_FORMAT_MAP:
            msg_body = MESSAGE_FORMAT_MAP[msg_type]

    # return glance header format, sequence msg format
    return msg_header,msg_body

    
def packPacketData(jnl_file_output,pkt_header,sequence,count,message_body):
    pkt_header[2] = count
    pkt_header[1] = sequence
    packet_header_dat = struct.pack(PACKET_HEADER_FORMAT, *pkt_header)

    # packet_head + msg_data
    jnl_file_output.append(packet_header_dat+message_body)

def getSharpByte(msg_size):
    return (msg_size + 3)/4 * 4

def print_usage():
    Message = '''USAGE(%s):
asx24_journal.py [-i <journal_file> | -g <text_file> | -t/-f <msg_type> | -c <contr_num> | -b <subid>
                  -k <key_words> | -n <num_of_msg> | -s <seq_num> |-p|-v|-h]  

COMMAND:  
    -i <journal_file_name>      Optional. Interpret jnl, convert jnl to readable text.
    -g <text_file_name>         Optional. Generate jnl, convert text to jnl file.
    -t <message type>           Optional. Filter by message type, separated by (,).
    -f <message type>           Optional. Filter out message type, seperated by (,).
    -c <contract number>        Optional. Filter by contract number, seperated by (,).
    -k <key workds>             Optional. Filter by key words
    -b <subid>                  Optional, Filter by subid
    -n <num_of_msg>             Optional, number of messages to interpret
    -s <sequence_number>        Optional, Generate jnl, sequence starts with this number.
    -d <delimiter>              Optional, Delimiter for field seperator, default '|'
    -r                          Optional, Recovery mode for data from TCP line.
    -p                          Optional, display packet header, no shown as default.
    -v                          Optional. Show version.
    -h                          Optional. Help info.

Examples:
    >> asx24_journal.py -g D:/ASX24.SJL.txt
    >> asx24_journal.py -i D:/ASX24.SJL 
    >> asx24_journal.py -i D:/ASX24.SJL  -t "g,O,T"
                              ^                 ^
                        journal_file_name  message type'''%g_version
    print Message
    sys.exit(1)
 
def parse_arg():
    global g_file_name,g_msgtype_list,g_contrnum_list,g_keywords,g_num_of_msg,g_not_msgtype_list,g_show_packet,g_sequence_num,g_delimiter,g_subid_list,g_rec_mode

    cmd_map = 0
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:t:f:c:k:g:n:s:d:b:rpvh")
    
    except getopt.GetoptError, err:
        print_usage()
    
    if opts == []:
        print_usage()

    for o, a in opts:
        if o in ("-i"):
            g_file_name = a.rstrip().strip("'").strip('"')
            if not os.path.exists(g_file_name):
                print "Error: jnl %s NOT found!" % g_file_name
                sys.exit()
            else:
                cmd_map = cmd_map | CMD_Interpret
        
        if o in ("-g"):
            g_file_name = a.rstrip().strip("'").strip('"')
            if not os.path.exists(g_file_name):
                print "Error: text %s NOT found!" % g_file_name
                sys.exit()
            else:
                cmd_map = cmd_map | CMD_Generate                         
        
        if o in ("-t"):
            g_msgtype_list = a.rstrip().strip("'").strip('"').split(",")

        if o in ("-f"):
            g_not_msgtype_list = a.rstrip().strip("'").strip('"').split(",")
            
        if o in ("-c"):
            g_contrnum_list = a.rstrip().strip("'").strip('"').split(",")

        if o in ("-b"):
            subid_list = a.rstrip().strip("'").strip('"').split(",")
            g_subid_list = [int(s_subid) for s_subid in subid_list]
        
        if o in ("-k"):
            g_keywords = a.rstrip().strip("'").strip('"')
        
        if o in ("-n"):
            g_num_of_msg = int(a.rstrip())
        
        if o in ("-s"):
            g_sequence_num = int(a.rstrip())

        if o in ("-r"):
           g_rec_mode = True

        if o in ("-d"):
            g_delimiter = a.rstrip().strip("'").strip('"')

        if o in ("-p"):
            g_show_packet = True
            
        if o in("-v"):
            cmd_map = cmd_map | CMD_Version

        if o in ("-h"):
            cmd_map = cmd_map | CMD_Help
                    
    return cmd_map
    
       
def main():
    cmd_map = parse_arg()

    if (cmd_map & CMD_Interpret != 0):
        interpretJnl()
        
    elif (cmd_map & CMD_Generate != 0):
        if (g_rec_mode):
            generateRecJnl()
        else:
            generateJnl()
        
    elif (cmd_map & CMD_Version !=0):
        print 'Version: %s' % g_version
        
    else:
        print_usage()    
    
if __name__ == '__main__':
    main()
