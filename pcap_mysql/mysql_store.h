/**
 * AUTHOR:张鑫
 */
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <stdarg.h>  

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

//需要包含mysql的头文件＿usr/include/mysql/  
//编译的时候需要加丿L/usr/lib/ -lmysqlclient -I/usr/include/mysql选项  
  
#include <mysql.h> //基本的头文件，一些重要结构体的声昿 
#include <errmsg.h>//错误信息的存政 
#include <mysql_version.h>  //包含当前mysql的版本信恿 
//////////////////全部变量，宏定义//////////////////////  
#define DEBUG  
#define SERVER_HOST "localhost"  //mysql的远程地址  
#define SERVER_USER "root"      //数据库登录名  
#define SERVER_PWD  "root"  //数据库登录密砿 
#define BUFFER_SIZE 512
  
#define DB_NAME     "sendOrNot_clean"    //新建数据库的名字  
#define TABLE_NAME_SEND  "sendInfoTable"  //发送信息的存储衿 
#define TABLE_NAME_RECEIVE "receiveInfoTable" //接收信息的存储表
#define TABLE_NAME_MEM_MONITOR "memMonitorInfoTable" //内存监控信息的存储表

MYSQL init_db();
int disconnect(MYSQL* mysql);

int insert_sendInfoTable(MYSQL* mysql,char* srcip,char* desip,int srcport,int desport,char* sendtime,int packetlength);
int insert_receiveInfoTable(MYSQL* mysql,char* srcip,char* desip,int srcport,int desport,char* arrivetime,int packetlength);
int insert_memMonitorInfoTable(MYSQL* mysql,vmi_pid_t pid,reg_t cr3,char* procname,unsigned long long time_,addr_t page,int access,addr_t gfn,addr_t gfn_offset,addr_t gla,uint32_t vcpuid);

int check_table_sendInfoTable(MYSQL* mysql,char* name);
int check_table_receiveInfoTable(MYSQL* mysql,char* name); 
int check_table_memMonitorInfoTable(MYSQL* mysql,char* name);  
int check_db(MYSQL* mysql,char* db_name);  

static size_t strcat2(char **dst_out,...);


static char* sql = NULL;
static char* ins_send = "insert into sendInfoTable (srcip,desip,srcport,desport,sendtime,packetlength) ";
static char* ins_receive = "insert into receiveInfoTable (srcip,desip,srcport,desport,arrivetime,packetlength) ";
static char* ins_mem = "insert into memMonitorInfoTable (pid,cr3,procname,time,page,access,gfn,gfn_offset,gla,vcpuid) ";


char sql_str_[BUFFER_SIZE];




MYSQL init_db(){
    int err=0;  
    MYSQL mysql;  
  
    if(!mysql_init(&mysql)){  
        perror("mysql_init:");  
        exit(1);  
    }     
  
    if(!mysql_real_connect(&mysql,SERVER_HOST,SERVER_USER,SERVER_PWD,NULL,0,NULL,0))  
    {     
        perror("mysql_real_connect");  
        exit(1);  
    }     
    printf("connected.....\n");  
  
    return mysql; 
}

int disconnect(MYSQL* mysql){
    mysql_close(mysql);
    return 0;
}
  
int check_db(MYSQL* mysql,char* db_name)  
{  
    MYSQL_ROW row = NULL;  
    MYSQL_RES *res = NULL;  
  
    res = mysql_list_dbs(mysql,NULL);  
    if(res)  
    {  
        while((row = mysql_fetch_row(res))!=NULL)  
        {  
            printf("db is %s\n",row[0]);  
            if(strcmp(row[0],db_name)==0)  
            {  
                printf("find db %s\n",db_name);  
                break;  
            }  
        }  
        //mysql_list_dbs会分配内存，需要使用mysql_free_result释放  
        mysql_free_result(res);  
    }  
    if(!row)  //没有这个数据库，则建竿 
    {  
        char buf[128]={0};  
        strcpy(buf,"CREATE DATABASE ");  
        strcat(buf,db_name);  
#ifdef DEBUG  
        printf("%s\n",buf);  
#endif  
        if(mysql_query(mysql,buf)){  
            fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql));  
            exit(1);  
        }  
    }  
    return 0;  
}  
  
int check_table_sendInfoTable(MYSQL* mysql,char* name)  
{  
    if(name == NULL)  
        return 0;  
    MYSQL_ROW row=NULL;  
    MYSQL_RES *res = NULL;  
    res = mysql_list_tables(mysql,NULL);  
    if(res)  
    {  
        while((row = mysql_fetch_row(res))!=NULL)  
        {  
            printf("tables is %s\n",row[0]);  
            if(strcmp(row[0],name) == 0)  
            {  
                printf("find the table !\n");  
                break;  
            }  
        }  
        mysql_free_result(res);  
    }  
    if(!row) //create table  
    {  
        char buf[256]={0};  
        char qbuf[256]={0};  
        snprintf(buf,sizeof(buf),"%s (id int(11) AUTO_INCREMENT primary key,srcip VARCHAR(20),desip VARCHAR(20),srcport int(5),desport int(5),sendtime VARCHAR(20),packetlength int(5));",TABLE_NAME_SEND);  
        strcpy(qbuf,"CREATE TABLE ");  
        strcat(qbuf,buf);  
//#ifdef DEBUG  
        printf("%s\n",qbuf);  
//#endif  
        if(mysql_query(mysql,qbuf)){  
            fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql));  
            exit(1);  
        }  
    }  
    return 0;  
}  

int check_table_receiveInfoTable(MYSQL* mysql,char* name)  
{  
    if(name == NULL)  
        return 0;  
    MYSQL_ROW row=NULL;  
    MYSQL_RES *res = NULL;  
    res = mysql_list_tables(mysql,NULL);  
    if(res)  
    {  
        while((row = mysql_fetch_row(res))!=NULL)  
        {  
            printf("tables is %s\n",row[0]);  
            if(strcmp(row[0],name) == 0)  
            {  
                printf("find the table !\n");  
                break;  
            }  
        }  
        mysql_free_result(res);  
    }  
    if(!row) //create table  
    {  
        char buf[256]={0};  
        char qbuf[256]={0};  
        snprintf(buf,sizeof(buf),"%s (id int(11) AUTO_INCREMENT primary key,srcip VARCHAR(20),desip VARCHAR(20),srcport int(5),desport int(5),arrivetime VARCHAR(20),packetlength int(5));",TABLE_NAME_RECEIVE);  
        strcpy(qbuf,"CREATE TABLE ");  
        strcat(qbuf,buf);  
//#ifdef DEBUG  
        printf("%s\n",qbuf);  
//#endif  
        if(mysql_query(mysql,qbuf)){  
            fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql));  
            exit(1);  
    }
  }
    return 0;
}  

int check_table_memMonitorInfoTable(MYSQL* mysql,char* name)  
{  
    if(name == NULL)  
        return 0;  
    MYSQL_ROW row=NULL;  
    MYSQL_RES *res = NULL;  
    res = mysql_list_tables(mysql,NULL);  
    if(res)  
    {  
        while((row = mysql_fetch_row(res))!=NULL)  
        {  
            printf("tables is %s\n",row[0]);  
            if(strcmp(row[0],name) == 0)  
            {  
                printf("find the table !\n");  
                break;  
            }  
        }  
        mysql_free_result(res);  
    }  
    if(!row) //create table  
    {  
        char buf[256]={0};  
        char qbuf[256]={0};  
        snprintf(buf,sizeof(buf),"%s (id int(11) AUTO_INCREMENT primary key,pid int(10),cr3 VARCHAR(20),procname VARCHAR(20),time int(11),page int(10),access int(5),gfn VARCHAR(20),gfn_offset VARCHAR(20),gla VARCHAR(20),vcpuid VARCHAR(20));",TABLE_NAME_MEM_MONITOR);  
        strcpy(qbuf,"CREATE TABLE ");  
        strcat(qbuf,buf);  
//#ifdef DEBUG  
        printf("%s\n",qbuf);  
//#endif  
        if(mysql_query(mysql,qbuf)){  
            fprintf(stderr,"Query failed (%s)\n",mysql_error(mysql));  
            exit(1);  
        }  
    }  
    return 0;  
}  

static size_t strcat2(char **dst_out, ...)
{
    size_t len = 0, len_sub;
    va_list argp;
    char *src;
    char *dst = NULL, *dst_p;

    *dst_out = NULL;

    va_start(argp, dst_out);
    for (;;)
    {
        if ((src = va_arg(argp, char *)) == NULL) break;
        len += strlen(src);
    }
    va_end(argp);

    if (len == 0) return 0;

    dst = (char *)malloc(sizeof(char) * (len + 1));
    if (dst == NULL) return -1;
    dst_p = dst;

    va_start(argp, dst_out);
    for (;;)
    {
        if ((src = va_arg(argp, char *)) == NULL) break;
        len_sub = strlen(src);
        memcpy(dst_p, src, len_sub);
        dst_p += len_sub;
    }
    va_end(argp);
    *dst_p = '\0';

    *dst_out = dst;

    return len;
}

int insert_sendInfoTable(MYSQL* mysql,char* srcip,char* desip,int srcport,int desport,char* sendtime,int packetlength){
    int res = 0;
    size_t len;
    sprintf(sql_str_," values('%s','%s',%d,%d,'%s',%d)",
                               srcip,desip,srcport,desport,sendtime,packetlength); 
    len = strcat2(&sql,ins_send,sql_str_,NULL);   
//    fwrite(sql,len,1,stdout);
    res = mysql_query(mysql,sql);
    if(res){
        printf("sendInfoTable insert error!");
    }
    return 0;
}


int insert_receiveInfoTable(MYSQL* mysql,char* srcip,char* desip,int srcport,int desport,char* arrivetime,int packetlength){
    int res = 0;
    size_t len;
    sprintf(sql_str_," values('%s','%s',%d,%d,'%s',%d)",
                               srcip,desip,srcport,desport,arrivetime,packetlength);  
    len = strcat2(&sql,ins_receive,sql_str_,NULL);   
//    fwrite(sql,len,1,stdout);
    res = mysql_query(mysql,sql);
    if(res){
        printf("receiveInfoTable insert error!");
    }   
    return 0;
};
/*
int insert_memMonitorInfoTable(MYSQL* mysql,vmi_pid_t pid,reg_t cr3,char* procname,unsigned long long time_,addr_t page,int access,addr_t gfn,addr_t gfn_offset,addr_t gla,uint32_t vcpuid){
    int res = 0;
    size_t len;
    sprintf(sql_str_," values(%"PRIi32",'%"PRIx64"','%s','%llu','%"PRIx64"',%d,'%"PRIx64"','%06"PRIx64"','%016"PRIx64"',%"PRIu32" )",
                              pid,       cr3,       procname,time_,page,    access,gfn,     gfn_offset,   gla,          vcpuid);
    
    len = strcat2(&sql,ins_mem,sql_str_,NULL);
//    fwrite(sql,len,1,stdout);
    res = mysql_query(mysql,sql);
    if(res){
        printf("memMonitorInfoTable insert error!");
    }   
    return 0;
};
*/
/*
int main(){
    int err;
    MYSQL mysql;
    mysql = init_db();
    err = check_db(&mysql,DB_NAME);
    if(err != 0)
    {
        printf("create db is err!\n");
        mysql_close(&mysql);  
        exit(1);  
    }    
    //select which db  
    if(mysql_select_db(&mysql,DB_NAME)) //return 0 is success ,!0 is err  
    {   
        perror("mysql_select_db:");  
        mysql_close(&mysql);  
        exit(1);  
    } 
  
    if((err=check_table_sendInfoTable(&mysql,TABLE_NAME_SEND))!=0)  
    {   
        printf("create send table is err!\n");  
        mysql_close(&mysql);  
        exit(1);  
    }  

    if((err=check_table_receiveInfoTable(&mysql,TABLE_NAME_RECEIVE))!=0)  
    {   
        printf("create receive table is err!\n");  
        mysql_close(&mysql);  
        exit(1);  
    } 

    if((err=check_table_memMonitorInfoTable(&mysql,TABLE_NAME_MEM_MONITOR))!=0)  
    {   
        printf("create mem table is err!\n");  
        mysql_close(&mysql);  
        exit(1);  
    } 
    
    insert_sendInfoTable(&mysql,"qwe","rty",10,10,"uio",10);
    insert_receiveInfoTable(&mysql,"qwe","rty",10,10,"uio",10);
    insert_memMonitorInfoTable(&mysql,10,"asd","fgh",10,10,10,"jkl","hello");
    disconnect(&mysql);
    return 0;  
}  
*/




