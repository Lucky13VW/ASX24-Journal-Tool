// ASX24ExSimulator.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <sys/stat.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <map>
#include <memory>
#include "ProtMsgs.hpp"

using namespace std;

 bool ParseConfig(vector<shared_ptr<ServerInfor>> &servers_infor)
{
    ifstream ifs("config.xml");
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
        cout<<"config.xml fail to open!"<<endl;
        return false;
    }
    
    xml_document<> xml_doc;
    xml_doc.parse<0>((char*)XmlFile.c_str());
    xml_node<> *NodeRoot = xml_doc.first_node("Services");
    xml_node<> *NodeObj = GetNode(NodeRoot,"Server");
    bool is_ok = false;
    while (NodeObj)
    {
        auto pServers = make_shared<ServerInfor>();
        xml_attribute<> *attr_name = NodeObj->first_attribute("Name");
        xml_node<> *IpNode = GetNode(NodeObj,"Ip");
        xml_node<> *PortNode = GetNode(NodeObj,"Port");
        xml_node<> *ProtocalNode = GetNode(NodeObj,"Protocal");
        xml_node<> *DataNode = GetNode(NodeObj,"Data");
        if (attr_name != NULL && IpNode!=NULL && PortNode!=NULL && ProtocalNode!=NULL && DataNode!=NULL)
        {
            pServers->name = attr_name->value();
            pServers->ip = IpNode->value();
            pServers->port = atoi(PortNode->value());
            if(strcmp(ProtocalNode->value(),"UDP")==0)
            {
                pServers->prot = ProUDP;
            }
            else
            {
                pServers->prot=ProTCP;
            }
            // parse rules
            
            xml_node<> *RuleNode = GetNode(DataNode,"Rule");
            while (RuleNode)
            {
                DataRule data_rule;
                xml_attribute<> *attr_key = NULL;
                if (pServers->prot == ProUDP)
                {
                    attr_key = RuleNode->first_attribute("Seq");
                    data_rule.seq = atoi(attr_key->value());
                }
                else
                {
                    attr_key = RuleNode->first_attribute("User");
                    data_rule.user = attr_key->value();
                    data_rule.pass = RuleNode->first_attribute("Pass")->value();
                    data_rule.mem = RuleNode->first_attribute("Mem")->value();
                    data_rule.ver = RuleNode->first_attribute("Ver")->value();
                    string is_expired = RuleNode->first_attribute("Expired")->value();
                    transform(is_expired.begin(), is_expired.end(), is_expired.begin(), tolower);
                    if (is_expired == "true") data_rule.is_expired = true;
                    else data_rule.is_expired = false;
                }
                
                data_rule.file_name = RuleNode->value();
                data_rule.count = 0;
                data_rule.file_data = NULL;
                data_rule.file_size = 0;
                pServers->rules[attr_key->value()] = data_rule;
                is_ok=true;
                RuleNode = RuleNode->next_sibling("Rule");
            }
            servers_infor.push_back(pServers);
        }
        else
        {
            cout<<"invalid format"<<endl;
        }

        NodeObj = NodeObj->next_sibling("Server");
    }
    return is_ok;
}

uint16_t CalculateFileCount(const char*file_buf,size_t file_size)
{
    uint16_t file_count=0,msg_size=0;
    size_t read_size = 0;
    while (read_size<file_size)
    {
        memcpy(&msg_size,file_buf+read_size,2);
        read_size+=ReverseEndian(msg_size)+2;
        ++file_count;
    }
    return file_count;
}

bool LoadDataFile(DataRule &data_rule)
{
    if (data_rule.file_size>0 && data_rule.file_data!=NULL)
    {
        free(data_rule.file_data);
    }
    ifstream data_file;
    string file_name = data_rule.file_name;
    struct stat st;
    stat(file_name.c_str(), &st);
    int file_size = st.st_size; 
    data_file.open(file_name,ios::binary|ios::in);
    if(data_file.is_open())
    {
        data_rule.file_size = file_size;
        data_rule.file_data = (char *)malloc(file_size);
        data_file.read(data_rule.file_data,file_size);
        data_rule.count = 0;
        data_file.close();
        return true;
    }
    else
    {
        return false;
    }
}

uint16_t MakeBlinkResponse(const string &session_id, uint64_t gap_begin,DataRule *data_rule, char *WriteData, size_t &WriteLen)
{
    // assume all data in one package
    uint16_t msg_count = 0;
    char *p_data = data_rule->file_data;
    
    // process one page of data
    p_data += sizeof(SjlPageHeader);
    // process one package of data
    auto *p_package = reinterpret_cast<SjlPackageHeader*>(p_data);
    p_data += sizeof(SjlPackageHeader);
    // modify base sequence/session id in packet header
    auto *p_packet = reinterpret_cast<PacketHeader*>(p_data);
    memcpy_s(&p_packet->session, SESSION_LEN, session_id.c_str(), SESSION_LEN);
    p_packet->sequence = ReverseEndian(gap_begin);
    msg_count = ReverseEndian(p_packet->count);
    // save one package in sending buffer
    size_t copy_size = p_package->size - sizeof(SjlPackageHeader);
    memcpy_s(WriteData, UDP_BUFF_SIZE, p_data, copy_size);
    WriteLen = copy_size;

    return msg_count;
}

bool ProcessUDPRequest(shared_ptr<ServerInfor> &server_info, char *ReadData,size_t ReadLen,char *WriteData, size_t &WriteLen)
{
    const BlinkRequestPacket &request = *(reinterpret_cast<const BlinkRequestPacket *>(ReadData));
    string session_id(request.session,SESSION_LEN);
    uint64_t gap_begin = ReverseEndian(request.sequence);
    uint16_t gap_count = ReverseEndian(request.count);
    printf("[%s]Request<=Session:%s,seq:%I64u,count:%u\n",server_info->name.c_str(),
        session_id.c_str(),gap_begin,gap_count);
    
    char gap_begin_str[25]={0};
    sprintf(gap_begin_str,"%I64u",gap_begin);
    auto data_rule = server_info->rules.find(gap_begin_str);
    if (data_rule==server_info->rules.end())
    {
        data_rule = server_info->rules.find("0");
        if (data_rule == server_info->rules.end())
        {
            return false;
        }
    }

    if(data_rule->second.file_size == 0 && !LoadDataFile(data_rule->second))
    {
        return false;
    }
    
    uint16_t msg_count = MakeBlinkResponse(session_id,gap_begin,&data_rule->second,WriteData,WriteLen);

    printf("[%s]Response=>Session:%s,seq:%I64u,count:%u\n",server_info->name.c_str(),session_id.c_str(), gap_begin, msg_count);
    return true;
}

DWORD WINAPI WorkingThreadUDP(LPVOID lpParam)
{
    shared_ptr<ServerInfor> server_info=*static_cast<shared_ptr<ServerInfor>*>(lpParam);
    WSADATA              wsaData;
    SOCKET               ReceivingSocket;
    SOCKADDR_IN          ReceiverAddr;
    int                  Port = server_info->port;
    char                 ReceiveBuf[UDP_BUFF_SIZE];
    char                 SendBuf[UDP_BUFF_SIZE];
    
    SOCKADDR_IN          SenderAddr;
    int                  SenderAddrSize = sizeof(SenderAddr);

    struct fd_set    fdread, fdwrite,fdexcept;
    struct timeval   timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    // Initialize Winsock version 2.2

    WSAStartup(MAKEWORD(2,2), &wsaData);

    // Create a new socket to receive datagrams on.

    ReceivingSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Set up a SOCKADDR_IN structure that will tell bind that we
    // want to receive datagrams from all interfaces using port
    // 5150.

    ReceiverAddr.sin_family = AF_INET;
    ReceiverAddr.sin_port = htons(Port);
    string listen_addr = "INADDR_ANY";
    if (server_info->ip == "" || server_info->ip == "-1")
    {
        ReceiverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        ReceiverAddr.sin_addr.s_addr = inet_addr(server_info->ip.c_str());
        listen_addr = inet_ntoa(ReceiverAddr.sin_addr);
    }

    // Associate the address information with the socket using bind.

    if(::bind(ReceivingSocket, (SOCKADDR *)&ReceiverAddr, sizeof(ReceiverAddr)) == 0)
    {
        printf("[%s] Listen@UDP %s:%u\n",server_info->name.c_str(),listen_addr.c_str(),ntohs(ReceiverAddr.sin_port));
    }
    else
    {
        printf("Bind failed!\n");
        return 0;
    }
    
    while(true)
    {
        FD_ZERO(&fdread);
        FD_ZERO(&fdexcept);

        FD_SET(ReceivingSocket, &fdread);
        FD_SET(ReceivingSocket, &fdexcept);

        int rc = select(0, &fdread,NULL, &fdexcept, &timeout);
        if (rc == SOCKET_ERROR)
        {
            printf("select error: %d\n",WSAGetLastError());
        }
        else if(rc == 0)
        {
            // timeout
            continue;
        }
        else
        {
            if (FD_ISSET(ReceivingSocket, &fdread))
            {
                memset(ReceiveBuf,0,UDP_BUFF_SIZE);
                int data_size = recvfrom(ReceivingSocket, ReceiveBuf, UDP_BUFF_SIZE, 0,(SOCKADDR *)&SenderAddr, &SenderAddrSize);
                printf("\n[%s]ReceiveFrom(%d)<- %s:%u\n",server_info->name.c_str(),
                    data_size,inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port));

                size_t send_size=0;
                memset(SendBuf,0,UDP_BUFF_SIZE);
                if(ProcessUDPRequest(server_info,ReceiveBuf,data_size,SendBuf,send_size))
                {
                    int sent_data_size = sendto(ReceivingSocket, SendBuf, send_size, 0, (SOCKADDR *)&SenderAddr, sizeof(SenderAddr));
                    if (sent_data_size>0)
                    {
                        printf("[%s]SendTo(%d)->%s:%u\n",server_info->name.c_str(),
                            sent_data_size,inet_ntoa(SenderAddr.sin_addr),ntohs(SenderAddr.sin_port));
                    }
                    else
                    {
                        printf("send failed!\n");
                    }
                }

            }
            if (FD_ISSET(ReceivingSocket,&fdexcept))
            {
                printf("socket io error!\n");
                break;
            }
        }
    }
    closesocket(ReceivingSocket);

    // When your application is finished call WSACleanup.

    WSACleanup();

    //SetEvent(hStopEvent);
    return 0;
}

struct DataSendInfor
{
    SOCKET fd;
    char *SendBuf;
    map<string,DataRule>::iterator account;
    string server_name;
};

size_t SendData(SOCKET client_socket, char *send_buff, size_t send_size)
{
    int total_sent_data = 0;
    int sent_data_size = 0;
    while (total_sent_data < send_size)
    {
        sent_data_size = send(client_socket, send_buff + total_sent_data, send_size - total_sent_data, 0);
        if (sent_data_size < 0)
        {
            cout << "SendData: send error:" << sent_data_size << endl;
            break;
        }
        else
        {
            total_sent_data += sent_data_size;
        }
    }
    return total_sent_data;
}

void MakeGlanceResponse(DataRule *data_rule, char *WriteData, size_t &WriteLen)
{
    // assume all data in one package
    size_t processed_data = 0;
    char *p_data = data_rule->file_data;
    WriteLen = 0;
    while (processed_data < data_rule->file_size)
    {
        // process one page of data
        auto *p_page = reinterpret_cast<SjlPageHeader*>(p_data);
        if (p_page->offset == 0) break;
        p_data += sizeof(SjlPageHeader);
        size_t cursor_offset = 0;
        while (cursor_offset < p_page->offset)
        {
            // process one package of data
            auto *p_package = reinterpret_cast<SjlPackageHeader*>(p_data);
            if (p_package->size == 0) break;
            p_data += sizeof(SjlPackageHeader);
            
            // save one package in sending buffer
            size_t copy_size = p_package->size - sizeof(SjlPackageHeader);
            memcpy_s(WriteData + WriteLen, TCP_BUFF_SIZE, p_data, copy_size);
            WriteLen += copy_size;
            p_data += copy_size;

            cursor_offset += p_package->size;
        }
        p_data = reinterpret_cast<char *>(p_page)+p_page->jnl_page_size;
        processed_data += p_page->jnl_page_size;
    }
}

DWORD WINAPI DataSendThread(LPVOID lpParam)
{
    DataSendInfor *send_info=static_cast<DataSendInfor*>(lpParam);
    char *SendBuf = send_info->SendBuf;
    SOCKET client_sockfd = send_info->fd;
    auto account = send_info->account;
    const char *server_name = send_info->server_name.c_str();

    size_t send_data_size = 0;
    memset(SendBuf,0,TCP_BUFF_SIZE);
    if(account->second.file_size == 0 && !LoadDataFile(account->second))
    {
        LogoutRequest logout_request;
        logout_request.type = 'O';
        logout_request.length = ReverseEndian(uint16_t(1));
        send_data_size = sizeof(LogoutRequest);
        memcpy_s(SendBuf,TCP_BUFF_SIZE,&logout_request,sizeof(LogoutRequest));
        printf("[%s]No data, Logout!",server_name);
    }
    else
    {
        MakeGlanceResponse(&account->second, SendBuf, send_data_size);
    }
    /*else
    {
        memcpy_s(SendBuf,TCP_BUFF_SIZE,account->second.file_data,account->second.file_size);
        SnapshotComplete rec_complete;
        rec_complete.packet_type = 'G';
        memset(rec_complete.sequence ,0,sizeof(rec_complete.sequence));
        strncpy_s(rec_complete.sequence,sizeof(rec_complete.sequence),"2",3);  // ???
        rec_complete.length = ReverseEndian(uint16_t(sizeof(rec_complete)-2));
        memcpy_s(SendBuf+account->second.file_size,TCP_BUFF_SIZE,&rec_complete,sizeof(SnapshotComplete));
        send_data_size = account->second.file_size + sizeof(SnapshotComplete);
        printf("[%s]DataTransfering(Total:%d)...\n",server_name,send_data_size);
    }*/

    
    size_t total_sent_data = SendData(client_sockfd, SendBuf, send_data_size);
    printf("[%s]=>SequencedData(%d bytes)\n",server_name,total_sent_data);
    

    /*send(client_sockfd,SendBuf,1,0);
    send(client_sockfd,SendBuf+1,1,0);
    send(client_sockfd,SendBuf+2,3,0);
    Sleep(1000);
    send(client_sockfd,SendBuf+5,3,0);
    send(client_sockfd,SendBuf+8,34,0);
    Sleep(5000);
    send(client_sockfd,SendBuf+42,6,0);
    Sleep(10000);
    send(client_sockfd,SendBuf+48,send_data_size-48,0);*/
    printf("[%s]DataTransferDone(%d)!\n",server_name,total_sent_data);
    
    delete send_info;

    return 0;
}

bool LoginRequestProcess(const shared_ptr<ServerInfor> &server_info,SOCKET client_sockfd,
    char *ReceiveBuf, size_t data_size_recv,
    char *SendBuf)
{
    const LoginRequest *login_request = reinterpret_cast<const LoginRequest*>(ReceiveBuf);
    bool check_auth = false;
    char login_user[sizeof(login_request->username)] = { 0 };
    char login_pass[sizeof(login_request->password)] = { 0 };
    char login_mem[sizeof(login_request->member)] = { 0 };
    char login_ver[sizeof(login_request->version)] = { 0 };
    strncpy_s(login_user,sizeof(login_user),login_request->username,sizeof(login_request->username));
    strncpy_s(login_pass,sizeof(login_pass),login_request->password,sizeof(login_request->password));
    strncpy_s(login_mem, sizeof(login_mem), login_request->member, sizeof(login_request->member));
    strncpy_s(login_ver, sizeof(login_ver), login_request->version, sizeof(login_request->version));
    auto account = server_info->rules.find(login_user);
    int reject_reason = 0;
    if(account!=server_info->rules.end())
    {
        //  && account->second.mem == login_mem
        if (account->second.pass != login_pass || account->second.is_expired)
        {
            reject_reason = -1;
        }
        else if (account->second.mem != login_mem)
        {
            reject_reason = -4;
        }
        else if (account->second.ver != login_ver)
        {
            reject_reason = -5;
        }
        else
        {
            check_auth = true;
        }
    }
    printf("[%s]<=LoginRequest(%s,%s,%s,%s)\n",server_info->name.c_str(),login_user,login_pass,login_mem,login_ver);
    
    size_t send_data_size = 0;
    memset(SendBuf,0,TCP_BUFF_SIZE);
    char login_status;
    if (check_auth)
    {
        LoginAccepted login_accept;
        login_status=login_accept.type = 'A';
        login_accept.length = ReverseEndian(uint16_t(sizeof(login_accept)-2));
        login_accept.sequence_number = ReverseEndian(uint64_t(1));
        memcpy(login_accept.session, "ASX24TR123", 10);
        memcpy_s(SendBuf,TCP_BUFF_SIZE,&login_accept,sizeof(LoginAccepted));
        send_data_size = sizeof(LoginAccepted);
        printf("[%s]=>LoginAccepted\n", server_info->name.c_str());
    }
    else
    {
        LoginRejected login_reject;
        login_status=login_reject.type = 'J';
        login_reject.length = ReverseEndian(uint16_t(sizeof(login_reject)-2));
        login_reject.reject_reason_code = reject_reason;
        login_reject.error_code = 0;
        memcpy_s(SendBuf, TCP_BUFF_SIZE, &login_reject, sizeof(LoginRejected));
        send_data_size = sizeof(LoginRejected);
        printf("[%s]=>LoginReject(%d)\n", server_info->name.c_str(),reject_reason);
    }
    int total_sent_data = 0;
    while(total_sent_data < send_data_size)
    {
        int sent_data_size = send(client_sockfd,SendBuf+total_sent_data,send_data_size-total_sent_data,0);
        total_sent_data += sent_data_size;
    }
    
    bool is_ok = true;
    if (login_status == 'J')
    {
        is_ok = false;
    }
    else
    {
        DataSendInfor *datasend_infor = new DataSendInfor();
        datasend_infor->SendBuf = SendBuf;
        datasend_infor->fd = client_sockfd;
        datasend_infor->server_name = server_info->name;
        datasend_infor->account = account;
        CreateThread(NULL, 0, DataSendThread, (LPVOID)(datasend_infor),0,NULL);
    }
    return is_ok;
}

bool SaveNewPassword(const char *user_name, const char *new_password)
{
    ifstream ifs("config.xml");
    string XmlFile;
    if (ifs.is_open())
    {
        string buf;
        while (!ifs.eof())
        {
            getline(ifs, buf, '\n');
            XmlFile.append(buf);
        }
        ifs.close();
    }
    else
    {
        cout << "config.xml fail to open!" << endl;
        return false;
    }

    xml_document<> xml_doc;
    xml_doc.parse<0>((char*)XmlFile.c_str());

    xml_node<> *NodeRoot = xml_doc.first_node("Services");
    xml_node<> *NodeObj = GetNode(NodeRoot, "Server");
    bool is_ok = false;
    while (NodeObj)
    {
        xml_node<> *ProtocalNode = GetNode(NodeObj, "Protocal");
        if (ProtocalNode != NULL && strcmp(ProtocalNode->value(), "TCP") == 0)
        {
            xml_node<> *DataNode = GetNode(NodeObj, "Data");
            xml_node<> *RuleNode = GetNode(DataNode, "Rule");
            while (RuleNode)
            {
                xml_attribute<> *attr_key = NULL;
                attr_key = RuleNode->first_attribute("User");
                if (strcmp(user_name, attr_key->value()) == 0)
                {
                    attr_key = RuleNode->first_attribute("Pass");
                    attr_key->value(new_password);
                    attr_key = RuleNode->first_attribute("Expired");
                    attr_key->value("false");
                    is_ok = true;
                    break;
                }
                RuleNode = RuleNode->next_sibling("Rule");
            }
        }
        if (is_ok) 
            break;
        NodeObj = NodeObj->next_sibling("Server");
    }
    if (is_ok)
    {
        std::string text;
        print(std::back_inserter(text), xml_doc, 0);
        std::ofstream out("config.xml");
        out << xml_doc;
    }
    return is_ok;
}

bool ChangePasswordProcess(const shared_ptr<ServerInfor> &server_info, SOCKET client_sockfd,
    char *ReceiveBuf, size_t data_size_recv,char *SendBuf)
{
    const PasswordChangeRequest *password_request = reinterpret_cast<const PasswordChangeRequest*>(ReceiveBuf);
    auto account = server_info->rules.find(password_request->username);
    bool is_ok = true;
    if (account != server_info->rules.end())
    {
        if (account->second.pass != password_request->old_password)
            is_ok = false;
        else if (account->second.mem != password_request->member)
            is_ok = false;
        if (is_ok)
        {
             bool save_ok = SaveNewPassword(password_request->username,password_request->new_password);
             account->second.is_expired = false;
             account->second.pass = password_request->new_password;
             printf("[%s]SaveNewPassword(%d)\n", server_info->name.c_str(),save_ok);
        }

        PasswordChangeResponse password_response;
        password_response.length = ReverseEndian(uint16_t(sizeof(password_response) - sizeof(password_response.length)));
        password_response.type = 'Y';
        strcpy_s(password_response.username, sizeof(password_response.username), password_request->username);
        strcpy_s(password_response.member, sizeof(password_response.member), password_request->member);
        
        int32_t status_n = 3001;
        if (!is_ok)
            status_n = 52006; // invalid username or password
            
        password_response.status = ReverseEndian(status_n);

        size_t total_sent_data = 0;
        size_t send_data_size = sizeof(password_response);
        memcpy_s(SendBuf, TCP_BUFF_SIZE, &password_response, send_data_size);
        total_sent_data = SendData(client_sockfd, SendBuf, send_data_size);
       
        printf("[%s]=>PasswordResetResponse(status:%d)\n", server_info->name.c_str(), status_n);

        SnapShotComplete snap_shot_complate;
        snap_shot_complate.length = ReverseEndian(uint16_t(sizeof(snap_shot_complate) - sizeof(snap_shot_complate.length)));
        snap_shot_complate.type = 'S';
        snap_shot_complate.packet_type = 'G';
        snap_shot_complate.sequence = ReverseEndian(uint64_t(0));

        send_data_size = sizeof(snap_shot_complate);
        memcpy_s(SendBuf, TCP_BUFF_SIZE, &snap_shot_complate, send_data_size);
        SendData(client_sockfd, SendBuf, send_data_size);
        printf("[%s]=>PasswordResetDone\n", server_info->name.c_str());
    }
    
    return is_ok;
}

struct ClientHandleInfo
{
    shared_ptr<ServerInfor> server_info;
    SOCKET client_sockfd;
};

DWORD WINAPI ClientHandleThread(LPVOID lpParam)
{
    ClientHandleInfo *handle_infor = static_cast<ClientHandleInfo*>(lpParam);
    SOCKET client_sockfd = handle_infor->client_sockfd;
    auto server_info = handle_infor->server_info;

    char                 ReceiveBuf[TCP_BUFF_SIZE];
    char                 SendBuf[TCP_BUFF_SIZE];

    struct fd_set    fdread, fdwrite,fdexcept;
    struct timeval   timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    int hb_inter = 0;
    while(true)
    {
        FD_ZERO(&fdread);
        FD_ZERO(&fdexcept);

        FD_SET(client_sockfd, &fdread);
        FD_SET(client_sockfd, &fdexcept);

        int rc = select(0, &fdread, NULL, &fdexcept, &timeout);
        if (rc == SOCKET_ERROR)
        {
            printf("select error: %d\n",WSAGetLastError());
        }
        else if(rc == 0)
        {
            // timeout
            continue;
        }
        else
        { 
            if (FD_ISSET(client_sockfd,&fdread))
            {
                memset(ReceiveBuf,0,TCP_BUFF_SIZE);
                int data_size_recv = 0;
                while(data_size_recv<sizeof(GlanceRequestHeader))
                {
                    int data_size = recv(client_sockfd, ReceiveBuf+data_size_recv, TCP_BUFF_SIZE-data_size_recv, 0);
                    data_size_recv+= data_size;
                }
                const GlanceRequestHeader *glance_request = reinterpret_cast<const GlanceRequestHeader*>(ReceiveBuf);
                uint16_t req_len = ReverseEndian(glance_request->length);
                while (req_len > data_size_recv-2)
                {
                    int data_size = recv(client_sockfd, ReceiveBuf+data_size_recv, TCP_BUFF_SIZE-data_size_recv, 0);
                    data_size_recv+= data_size;
                }
                bool is_login= false;
                switch(glance_request->type)
                {
                case 'L':
                    is_login = LoginRequestProcess(server_info,client_sockfd,ReceiveBuf,data_size_recv,SendBuf);
                    break;
                case 'O':
                    is_login = false;
                    printf("[%s]<=Logout(%d)\n",server_info->name.c_str(),data_size_recv);
                    break;
                case 'R':
                    is_login = true;
                    if (hb_inter++ % 10 == 0)
                    {
                        printf("[%s]<=Heartbeat(%d)\n",server_info->name.c_str(),data_size_recv);
                        hb_inter = 0;
                    }
                    break;
                case 'W':
                    ChangePasswordProcess(server_info, client_sockfd, ReceiveBuf, data_size_recv, SendBuf);
                    is_login = false;
                    break;
                }

                if (!is_login)
                {
                    shutdown(client_sockfd,0);
                    closesocket(client_sockfd);
                    printf("[%s]request type:%c, disconnect!",server_info->name.c_str(), glance_request->type);
                    break;
                }
            }
            if (FD_ISSET(client_sockfd,&fdexcept))
            {
                printf("socket io error!\n");
                break;
            }
        }
    }
    delete handle_infor;
    return 0;
}

DWORD WINAPI WorkingThreadTCP(LPVOID lpParam)
{
    shared_ptr<ServerInfor> server_info=*static_cast<shared_ptr<ServerInfor>*>(lpParam);
    WSADATA              wsaData;
    SOCKET               ServerSocket, ClientSocket;
    SOCKADDR_IN          ServerAddr, ClientAddr;
    int                  Port = server_info->port;
  
    
    int                  ClientAddrSize = sizeof(ClientAddr);

    struct fd_set    fdread, fdwrite,fdexcept;
    struct timeval   timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    
    // Initialize Winsock version 2.2
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // Create a new socket to receive datagrams on.

    ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Set up a SOCKADDR_IN structure that will tell bind that we
    // want to receive datagrams from all interfaces using port
    // 5150.

    ServerAddr.sin_family = AF_INET;
    ServerAddr.sin_port = htons(Port);
    string listen_addr = "INADDR_ANY";
    if (server_info->ip == "" || server_info->ip == "-1")
    {
        ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        ServerAddr.sin_addr.s_addr = inet_addr(server_info->ip.c_str());
        listen_addr = inet_ntoa(ServerAddr.sin_addr);
    }

    if(::bind(ServerSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr)) != 0)
    {
        printf("Bind failed!\n");
        return -1;
    }
    int backlog = 0;
    if (::listen(ServerSocket,backlog) == 0)
    {
        printf("[%s] Listen@TCP %s:%u\n",server_info->name.c_str(),listen_addr.c_str(),ntohs(ServerAddr.sin_port));
    }
    else
    {
        printf("Listen failed!\n");
        return -1;
    }

    while(true)
    {
        FD_ZERO(&fdread);
        //FD_ZERO(&fdwrite);
        FD_ZERO(&fdexcept);

        FD_SET(ServerSocket, &fdread);
        //FD_SET(ServerSocket, &fdwrite);
        FD_SET(ServerSocket, &fdexcept);

        int rc = select(0, &fdread, NULL, &fdexcept, &timeout);
        if (rc == SOCKET_ERROR)
        {
            printf("select error: %d\n",WSAGetLastError());
        }
        else if(rc == 0)
        {
            // timeout
            continue;
        }
        else
        {
            if (FD_ISSET(ServerSocket, &fdread))
            {
                ClientSocket = accept(ServerSocket,(struct sockaddr*)&ClientAddr,&ClientAddrSize);
                if (ClientSocket < 0)
                {
                    printf("Accept error!\n");
                    return -2;
                }
                printf("\n[%s]Connected <- %s:%u\n",server_info->name.c_str(),inet_ntoa(ClientAddr.sin_addr),ntohs(ClientAddr.sin_port));
                ClientHandleInfo *handle_info = new ClientHandleInfo();
                handle_info->client_sockfd = ClientSocket;
                handle_info->server_info = server_info;
                CreateThread(NULL, 0, ClientHandleThread, (LPVOID)(handle_info),0,NULL);
            }
            
            if (FD_ISSET(ServerSocket,&fdexcept))
            {
                printf("socket io error!\n");
                break;
            }
        }
    }
    closesocket(ServerSocket);

    // When your application is finished call WSACleanup.

    WSACleanup();

    //SetEvent(hStopEvent);
    return 0;
}

int _tmain(int argc, char**argv)
{
    vector<shared_ptr<ServerInfor>> servers_infor;
    if(!ParseConfig(servers_infor))
        return -1;
    
    cout<<"Ctl+c or 'q[Enter]' to stop...."<<endl;

    DWORD (WINAPI *worker_thread)(LPVOID) = WorkingThreadUDP;
    for (int i=0;i<servers_infor.size();i++)
    {
        if (servers_infor[i]->prot == ProTCP)
            worker_thread = WorkingThreadTCP;
        HANDLE worker = CreateThread(NULL, 0, *worker_thread, (LPVOID)(&servers_infor[i]),0,NULL);
        if (worker == NULL)
        {
            fprintf(stderr, "CreateThread failed: %d\n", GetLastError());
            return -2;
        }
    }
    
    string input;
    while (cin>>input)
    {
        if (input=="q")
        {
            break;
        }
    }
    
    return 0;
}

