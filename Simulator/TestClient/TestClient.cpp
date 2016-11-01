// TestClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <iostream>
#include <memory>
#include "../ASX24ExSimulator/ProtMsgs.hpp"
#include <time.h>
#include <thread>
#include <algorithm>

using namespace std;

bool ParseConfig(vector<shared_ptr<ClientInfor>> &clinet_infor)
{
    ifstream ifs("request_test.xml");
    string XmlFile;
    if(ifs.is_open())
    {
        string buf;
        while(!ifs.eof())
        {
            getline(ifs,buf,'\n');
            XmlFile.append(buf);
        }
        ifs.close();
    }
    else
    {
        cout<<"request_test.xml fail to open!"<<endl;
        return false;
    }
    
    xml_document<> xml_doc;
    xml_doc.parse<0>((char*)XmlFile.c_str());
    xml_node<> *NodeRoot = xml_doc.first_node("Services");
    xml_node<> *NodeObj = GetNode(NodeRoot,"Server");
    bool is_ok = false;
    while (NodeObj)
    {
        auto pClient = make_shared<ClientInfor>();
        xml_attribute<> *attr_name = NodeObj->first_attribute("Name");
        xml_attribute<> *attr_enable = NodeObj->first_attribute("Enable");
        bool is_enabled = true;
        if (attr_enable != NULL )
        {
            string str_enable = attr_enable->value();
            transform(str_enable.begin(), str_enable.end(), str_enable.begin(), tolower);
            if (str_enable == "false")
            {
                is_enabled = false;
            }
        }
        xml_node<> *IpNode = GetNode(NodeObj,"Ip");
        xml_node<> *PortNode = GetNode(NodeObj,"Port");
        xml_node<> *ProtocalNode = GetNode(NodeObj,"Protocal");
        xml_node<> *DataNode = GetNode(NodeObj,"Data");
        if (attr_name != NULL && IpNode!=NULL && PortNode!=NULL && ProtocalNode!=NULL && DataNode!=NULL)
        {
            pClient->name = attr_name->value();
            pClient->ip = IpNode->value();
            pClient->port = atoi(PortNode->value());
            if(strcmp(ProtocalNode->value(),"UDP")==0)
            {
                pClient->prot = ProUDP;
            }
            else
            {
                pClient->prot = ProTCP;
            }
            // parse rules
            
            xml_node<> *RuleNode = GetNode(DataNode,"Rule");
            while (RuleNode)
            {
                RequestRule req_rule;
                
                if (pClient->prot == ProUDP)
                {
                    req_rule.sequence = atoi(RuleNode->first_attribute("Seq")->value());
                    req_rule.count = atoi(RuleNode->first_attribute("Count")->value());
                    req_rule.session = RuleNode->first_attribute("SessID")->value();
                }
                else
                {
                    req_rule.user = RuleNode->first_attribute("User")->value();
                    req_rule.pass = RuleNode->first_attribute("Pass")->value();
                    req_rule.mem = RuleNode->first_attribute("Mem")->value();
                    req_rule.ver = RuleNode->first_attribute("Ver")->value();
                }
                
                req_rule.output_file = RuleNode->value();
                pClient->request.push_back(req_rule);
                is_ok=true;
                RuleNode = RuleNode->next_sibling("Rule");
            }
            if(is_enabled) clinet_infor.push_back(pClient);
        }
        else
        {
            cout<<"invalid format"<<endl;
        }

        NodeObj = NodeObj->next_sibling("Server");
    }
    return is_ok;
}


void TestingThreadUDP(shared_ptr<ClientInfor> client_info)
{
    WSADATA              wsaData;
    SOCKET               SendingSocket;
    SOCKADDR_IN          ReceiverAddr;
    const char*          ip_addr_s = client_info->ip.c_str();
    int                  Port = client_info->port;
    
    char                 SendBuf[UDP_BUFF_SIZE];
    char                 ReceiveBuf[UDP_BUFF_SIZE];


    // Initialize Winsock version 2.2
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // Create a new socket to receive datagrams on.

    SendingSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Set up a SOCKADDR_IN structure that will identify who we
    // will send datagrams to. For demonstration purposes, let's
    // assume our receiver's IP address is 136.149.3.29 and waits
    // for datagrams on port 5150.

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(Port);    
    ReceiverAddr.sin_addr.s_addr = inet_addr(ip_addr_s);

    auto iter = client_info->request.begin();
    for (;iter!=client_info->request.end();iter++)
    {
        const RequestRule &request_info = (*iter);
        // Send a datagram to the receiver.
        memset(SendBuf,0,UDP_BUFF_SIZE);

        BlinkRequestPacket request;
        request.sequence=ReverseEndian(uint64_t(request_info.sequence));
        request.count = ReverseEndian(uint16_t(request_info.count));
        memcpy_s(&request.session, SESSION_LEN, request_info.session.c_str(), request_info.session.size());

        memcpy_s(SendBuf,UDP_BUFF_SIZE,&request,sizeof(request));
        int sent_data_size = sendto(SendingSocket, SendBuf, sizeof(request), 0, (SOCKADDR *)&ReceiverAddr, sizeof(ReceiverAddr));
        if (sent_data_size>0)
        {
            printf("[%s]send(%d)->%s,%u(%s|%I64u|%u)\n",client_info->name.c_str(),sent_data_size,
                inet_ntoa(ReceiverAddr.sin_addr), ntohs(ReceiverAddr.sin_port), 
                request_info.session.c_str(),request_info.sequence,request_info.count);
        }
        else
        {
            printf("[%s]send failed!\n",client_info->name.c_str());
        }
        memset(ReceiveBuf,0,UDP_BUFF_SIZE);
        int ReceiverAddrSize = sizeof(ReceiverAddr);
        int data_size = recvfrom(SendingSocket, ReceiveBuf, UDP_BUFF_SIZE, 0,(SOCKADDR *)&ReceiverAddr, &ReceiverAddrSize);
        printf("[%s]ReceiveFrom(%d)<= %s:%u\n",client_info->name.c_str(),data_size,
            inet_ntoa(ReceiverAddr.sin_addr),ntohs(ReceiverAddr.sin_port));
        if (data_size <= 0)
        {
            printf("[%s]ReceiveData failed, quit!\n",client_info->name.c_str());
            break;
        }
        const PacketHeader *pck_header = reinterpret_cast<const PacketHeader *>(ReceiveBuf);
        string sess_id(pck_header->session,SESSION_LEN);
        printf("[%s]=>id:%s,seq:%I64u,count:%u\n",client_info->name.c_str(),sess_id.c_str(),
            ReverseEndian(pck_header->sequence),ReverseEndian(pck_header->count));

        string output_file(request_info.output_file.c_str());
        ofstream data_file(output_file.c_str(),ios::binary);
        
        char sjl_buffer[1024 * 8] = { 0 };

        SjlPackageHeader sjl_package;
        sjl_package.size = data_size+sizeof(sjl_package);
        sjl_package.bf0 = 1;
        sjl_package.hp_counter = 377600777978373;

        SjlPageHeader sjl_page;
        sjl_page.version = 3;
        sjl_page.jnl_page_size = sizeof(sjl_buffer);
        sjl_page.offset = sizeof(sjl_package)+sizeof(sjl_page)+data_size;
        sjl_page.systime = time(NULL);
        sjl_page.hp_counter = 377494019448199;
        sjl_page.hp_frequency = 2396910000;
        sjl_page.millisec = 55;

        size_t written_len = 0;
        memcpy(sjl_buffer,&sjl_page,sizeof(sjl_page));
        written_len += sizeof(sjl_page);

        memcpy(sjl_buffer + written_len, &sjl_package, sizeof(sjl_package));
        written_len += sizeof(sjl_package);

        memcpy(sjl_buffer + written_len, &ReceiveBuf,data_size);
        written_len += data_size;

        if(data_file.is_open())
        {
            data_file.write(sjl_buffer,sizeof(sjl_buffer));
            data_file.flush();
            data_file.close();
             printf("[%s]JnlFile=>%s\n",client_info->name.c_str(),output_file.c_str());
        }
    }

    closesocket(SendingSocket);
    WSACleanup();
}

bool SendData(SOCKET client_socket, char *send_buff, size_t send_size)
{
    int total_sent_data = 0;
    int sent_data_size = 0;
    while (total_sent_data < send_size)
    {
        sent_data_size = send(client_socket, send_buff + total_sent_data, send_size - total_sent_data, 0);
        if(sent_data_size < 0)
        {
            cout << "SendData: send error:" << sent_data_size << endl;
            break;
        }
        else
        {
            total_sent_data += sent_data_size;
        }
    }
    return (total_sent_data == send_size);
}

#define TCP_RECV_BUF_SIZE 1024*2
#define TCP_SEND_BUF_SIZE 1024
static size_t tcp_data_expected = 0;
static char tcp_data_buffer[TCP_BUFF_SIZE];

void TestingThreadTCP(shared_ptr<ClientInfor> client_info)
{ 
    
    WSADATA              wsaData;
    SOCKET               ClientSocket;
    SOCKADDR_IN          ServerAddr;
    const char*          ip_addr_s = client_info->ip.c_str();
    int                  Port = client_info->port;
    
    char                 SendBuf[TCP_SEND_BUF_SIZE];
    char                 ReceiveBuf[TCP_RECV_BUF_SIZE];


    // Initialize Winsock version 2.2
    WSAStartup(MAKEWORD(2,2), &wsaData);
   
    auto iter = client_info->request.begin();
    for (;iter!=client_info->request.end();iter++)
    {
        // Create a new socket to receive datagrams on.
        ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        memset(&ServerAddr,0,sizeof(ServerAddr));
        ServerAddr.sin_family = AF_INET;
        ServerAddr.sin_port = htons(Port);    
        ServerAddr.sin_addr.s_addr = inet_addr(ip_addr_s);

        uint32_t net_time_out = 2000; // ms
        setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&net_time_out,sizeof(int));
        
        if (-1 == connect(ClientSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr)))
        {
            fprintf(stderr, "Failed to connect err(%d)\n", GetLastError());
            continue;
        }
        else
        {
            printf("[%s]Connected to %s at %u\n", client_info->name.c_str(), inet_ntoa(ServerAddr.sin_addr), ntohs(ServerAddr.sin_port));
        }
      
        if (SendLoginRequest(ClientSocket, SendBuf, TCP_SEND_BUF_SIZE, *iter))
        {
            printf("[%s]=>LoginRequest(usr:%s,pw:%s,mem:%s,ver:%s)\n", client_info->name.c_str(),
                request.username, request.password, request.member, request.version);
        }
        else
        {
            printf("[%s]LoginRequest failed!\n", client_info->name.c_str());
            continue;
        }
        
        
        int recv_data_size = 0;
        while (true)
        {
            recv_data_size = recv(ClientSocket, ReceiveBuf, TCP_RECV_BUF_SIZE, 0);
            
            if (recv_data_size >0 )
            {
                if(ProcessRecv(ReceiveBuf, recv_data_size))
                    ProcessSend();
            }
            else
            {
                cout << "recv: time out, quit! " << recv_data_size << endl;
            }
        }
        
        shutdown(ClientSocket,0);
        closesocket(ClientSocket);
    }
    WSACleanup();
    
}

bool SendLoginRequest(SOCKET ClientSocket, char *SendBuf, size_t SendBufSize, const RequestRule &request_info)
{
    // try to login request
    memset(SendBuf, 0, SendBufSize);
    LoginRequest request;
    memset(&request, 0, sizeof(request));
    memcpy_s(request.username, sizeof(request.username), request_info.user.c_str(), request_info.user.length());
    memcpy_s(request.password, sizeof(request.password), request_info.pass.c_str(), request_info.pass.length());
    memcpy_s(request.member, sizeof(request.member), request_info.mem.c_str(), request_info.mem.length());
    memcpy_s(request.version, sizeof(request.version), request_info.ver.c_str(), request_info.ver.length());
    request.type = 'L';
    request.length = ReverseEndian(sizeof(LoginRequest) - sizeof(request.length));
    request.requested_sequence_number = ReverseEndian(0);
    memcpy_s(SendBuf, SendBufSize, &request, sizeof(request));

    return SendData(ClientSocket, SendBuf, sizeof(request));
}

bool ProcessRecv(char *data_buffer, size_t data_size)
{
    if (tcp_data_expected == 0)
    {

    }

    const GlanceResponseHeader *return_data = reinterpret_cast<const LoginAccepted *>(ReceiveBuf);
    char login_status = return_data->type;

    printf("[%s]<=LoginStatus(%c),%c\n",client_info->name.c_str(),login_status,data_size);
    if (login_status == 'A')
    {
    SendInfo *send_infor = new SendInfo();
    send_infor->send_sock = ClientSocket;
    //send_infor->evt_stop = CreateEvent(NULL,true,false,NULL);
    HANDLE worker = CreateThread(NULL, 0, HeartbeatThread, (LPVOID)(send_infor),0,NULL);

    memset(ReceiveBuf,0,TCP_BUFF_SIZE);
    int data_size_recv = 0,data_processed = 0;
    bool is_last_pck = false;
    while(true)
    {
    int data_size = recv(ClientSocket, ReceiveBuf + data_size_recv, TCP_BUFF_SIZE - data_size_recv, 0);
    if (data_size <= 0)
    {
    printf("[%s] Waiting for data, timeout\n",client_info->name.c_str());
    break;
    }
    data_size_recv += data_size;
    printf("[%s]<=Data(%d|%d)\n",client_info->name.c_str(),data_size,data_size_recv);
    }
    if (data_size_recv <= sizeof(GlanceResponseHeader))
    {
    printf("[%s] Data less than min\n", client_info->name.c_str());
    continue;
    }
    string output_file(request_info.output_file);
    ofstream data_file(output_file.c_str(),ios::binary|ios::app);

    char sjl_buffer[1024 * 8] = { 0 };

    SjlPackageHeader sjl_package;
    sjl_package.size = data_size_recv + sizeof(sjl_package);
    sjl_package.bf0 = 1;
    sjl_package.hp_counter = 377600777978373;

    SjlPageHeader sjl_page;
    sjl_page.version = 3;
    sjl_page.jnl_page_size = sizeof(sjl_buffer);
    sjl_page.offset = sizeof(sjl_package) + sizeof(sjl_page) + data_size_recv;
    sjl_page.systime = time(NULL);
    sjl_page.hp_counter = 377494019448199;
    sjl_page.hp_frequency = 2396910000;
    sjl_page.millisec = 55;

    size_t written_len = 0;
    memcpy(sjl_buffer, &sjl_page, sizeof(sjl_page));
    written_len += sizeof(sjl_page);

    memcpy(sjl_buffer + written_len, &sjl_package, sizeof(sjl_package));
    written_len += sizeof(sjl_package);

    memcpy(sjl_buffer + written_len, &ReceiveBuf, data_size_recv);
    written_len += data_size_recv;

    if(data_file.is_open())
    {
    data_file.write(sjl_buffer, sizeof(sjl_buffer));
    data_file.flush();
    data_file.close();
    printf("[%s]JnlFile=>%s\n",client_info->name.c_str(),output_file.c_str());
    }
    
}

void ProcessSend(SOCKET client_socket, char *send_buffer, size_t send_size)
{
    ClientHeartbeat heartbeat;
    heartbeat.type = 'R';
    heartbeat.length = ReverseEndian(uint16_t(1));
    memcpy_s(send_buffer, TCP_BUFF_SIZE, &heartbeat, sizeof(heartbeat));
    SendData(client_socket,send_buffer,send_size);
}

int _tmain(int argc, char* argv[])
{
    vector<shared_ptr<ClientInfor>> client_infors;
    
    if (!ParseConfig(client_infors))
        return -1;

    vector<thread> client_threads;    
    
    for(auto cur_info : client_infors)
    {
        if (cur_info->prot == ProTCP)
        {
            client_threads.push_back(thread(TestingThreadTCP, cur_info));
        }
        else
        {
            client_threads.push_back(thread(TestingThreadUDP, cur_info));
        }
    }
    
    for (int i = 0; i < client_threads.size(); i++)
    {
        client_threads[i].join();
    }
    return 0;

}

