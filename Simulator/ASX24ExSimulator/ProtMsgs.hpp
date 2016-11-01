#pragma once

#include "stdafx.h"
#include "stdint.h"
#include <string>
#include <map>
#include <vector>
#include "../rapidxml/rapidxml.hpp"
#include "../rapidxml/rapidxml_print.hpp"

using namespace rapidxml;
using namespace std;

#define SESSION_LEN 10

#pragma pack(push,1)
struct BlinkRequestPacket
{
    char session[SESSION_LEN];
    uint64_t sequence;
    uint16_t count;
};

struct PacketHeader
{
    char session[SESSION_LEN];
    uint64_t sequence;
    uint16_t count;
};

// request 
struct GlanceRequestHeader
{
    uint16_t length;
    char type;  // A,J,Y,H,S,Z
};


struct LoginRequest
{
    uint16_t length;
    char type;  // L
    char member[64]; // member id
    char username[64];
    char password[64];
    uint64_t ticket; // always set to 0
    uint64_t requested_sequence_number; // will be ingored. set to 0
    char version[12]; // API version
};

struct LogoutRequest
{
    uint16_t length;
    char type; // O
};

struct ClientHeartbeat
{
    uint16_t length;
    char type;  // R
};

struct PasswordChangeRequest
{
    uint16_t length;
    char type; // W
    char member[64]; // member id
    char username[64];
    char old_password[64];
    char new_password[64];
};

// response
struct GlanceResponseHeader
{
    uint16_t length;
    char type;  // A,J,Y,H,S,Z
};

struct LoginAccepted
{
    uint16_t length;
    char type; // A
    char session[SESSION_LEN];
    uint64_t sequence_number; // always be 1
};

struct LoginRejected
{
    uint16_t length;
    char type; // J
    int32_t reject_reason_code;
    int32_t error_code;
};

struct PasswordChangeResponse
{
    uint16_t length;
    char type; // Y
    char member[64];
    char username[64];
    int32_t status;
};

struct SjlPageHeader
{
    uint32_t version;
    uint32_t offset;
    uint32_t jnl_page_size;
    uint32_t systime;
    uint64_t hp_counter;
    uint64_t hp_frequency;
    uint16_t millisec;
    uint16_t spare_0;
    uint32_t systime_high_lw;
};

struct SjlPackageHeader
{
    uint32_t dep;
    uint16_t bf0;
    uint16_t compid;
    uint32_t size;
    uint32_t spare_0;
    uint64_t hp_counter;
};

#pragma pack(pop)

#define UDP_BUFF_SIZE 1024*4
#define UDP_SIZE_MAX 1472
#define TCP_BUFF_SIZE 1024*32

enum ProtocalType
{
    ProUDP=0,
    ProTCP=1
};

struct DataRule
{
    uint64_t seq;
    uint16_t count;
    char *file_data;
    uint64_t file_size;
    string file_name;
    string user;
    string pass;
    string mem;
    string ver;
    bool is_expired;
};

struct ServerInfor
{
    ProtocalType prot;
    string ip;
    string name;
    short port;
    map<string,DataRule> rules;
};

struct RequestRule
{
    uint64_t sequence;
    uint16_t count;
    string output_file;
    string user;
    string pass;
    string mem;
    string ver;
    string session;
};

struct ClientInfor
{
    ProtocalType prot;
    string ip;
    string name;
    short port;
    HANDLE stop_event;
    vector<RequestRule> request;
};

xml_node<> *GetNode(xml_node<> *BaseNode,const char *NodePath)
{
    size_t PathLen= strlen(NodePath);
    char *TargetName= (char*)malloc(PathLen+1);
    TargetName[PathLen] = 0;
    strcpy_s(TargetName,PathLen+1,NodePath);

    const char *Sep="/";
    char *Token = NULL;
    char *NextToken = NULL;
    xml_node<> *Node = BaseNode;
    xml_node<> *SubNode = NULL;

    Token = strtok_s(TargetName,Sep,&NextToken);
    while (Token!=NULL)
    {    
         SubNode = Node->first_node(Token);
         if (SubNode!=NULL)
         {
            Node = SubNode;
            //get next token;
            Token = strtok_s(NULL,Sep,&NextToken);
         }
         else
         {
             break;
         }
    }  
    if(TargetName!=0)
        free(TargetName);
    return SubNode;
}

uint16_t ReverseEndian(uint16_t data)
{
    return ((data & 0xff00) >>8) | ((data & 0x00ff) << 8);
}

uint32_t ReverseEndian(uint32_t data)
{
    return ((data & 0xff000000) >> 24)
        | ((data & 0x00ff0000) >> 8)
        | ((data & 0x0000ff00) << 8)
        | ((data & 0x000000ff) << 24);
}

int32_t ReverseEndian(int32_t data)
{
    return ((data & 0xff000000) >> 24)
        | ((data & 0x00ff0000) >> 8)
        | ((data & 0x0000ff00) << 8)
        | ((data & 0x000000ff) << 24);
}

uint64_t ReverseEndian(uint64_t data)
{
    return ((data & 0xff00000000000000) >> 56)
        | ((data & 0x00ff000000000000) >> 40)
        | ((data & 0x0000ff0000000000) >> 24)
        | ((data & 0x000000ff00000000) >> 8)
        | ((data & 0x00000000ff000000) << 8)
        | ((data & 0x0000000000ff0000) << 24)
        | ((data & 0x000000000000ff00) << 40)
        | ((data & 0x00000000000000ff) << 56);
}