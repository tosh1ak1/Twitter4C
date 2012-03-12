/* Last Modified: March 13, 2012. by Plemling138 */
/* twilib.h   ---   Generate OAuth request message for use Twitter API
   Copyright (C) 2012. by Plemling138 Plemling138 

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  
*/

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netdb.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/time.h>
#include "hmac.h"
#include "base64.h"
#include "urlenc.h"
#include "extract.h"
#include "twilib.h"
#include "session.h"

int Twitter_GetRequestToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r)
{
  int i;
  struct timeval tv;

  char buf[BUF_SIZE] = {0};

  char encpath[100] = {0}; //エンコードしたURL
  char nonce[100] = {0};
  char nonce_urlenc[100] = {0};
  char nonce_tmp[100] = {0};
  char tstamp[100] = {0};

  char tmp_token[200] = {0};
  char tmp_secret[200] = {0};

  char reqheader[1500] = {0};//POSTヘッダ
  char auth_tmpmsg[800] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ
  char auth_encmsg[800] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ(URL-Encoded)

  char hmacmsg[300] = {0};
  char b64msg[300] = {0};
  char b64urlenc[300] = {0};
  char oauth_signature_key[200] = {0};

  //署名キー
  sprintf(oauth_signature_key, "%s&", c->consumer_secret);

  //時間を取得してタイムスタンプと一意な値をセット
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  //OAuth用メッセージ結合
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_VER, VER_1_0);
  URLEncode(auth_tmpmsg, auth_encmsg);
  URLEncode(REQUEST_TOKEN_URL, encpath);
  for(i=0; i<400; i++) auth_tmpmsg[i] = 0;
  sprintf(auth_tmpmsg, "%s&%s&%s", MSG_POST, encpath, auth_encmsg);

  //シグネイチャ生成
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_tmpmsg, strlen(auth_tmpmsg), hmacmsg);

  //シグネイチャの文字数カウント
  //HMAC署名では署名中に\0記号が出てくることもあるため、今チェックしているポイントから3連続で
  //\0が続いた時にbreakするようにしている
  i=0;
  while(i<300) {
    if(hmacmsg[i] == 0 && hmacmsg[i+1] == 0 && hmacmsg[i+2] == 0) break;
    i++;
  }

  //署名文字列をBASE64エンコード、さらにURLエンコード
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //POST用メッセージ生成
  sprintf(reqheader, "%s %s?%s%s&%s%s&%s%s&%s%s&%s%s&%s%s %s\r\n\r\n", MSG_POST, REQUEST_TOKEN_URL, OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_VER, VER_1_0 , MSG_HTTP);

  //SSL通信で送受信
  SSL_send_and_recv(reqheader, buf);

  if(ExtractQuery(buf, "oauth_token=", tmp_token) < 0) return -8;
  if(ExtractQuery(buf, "oauth_token_secret=", tmp_secret) < 0) return -9;

  r->request_token = (char *)calloc((strlen(tmp_token))+1, sizeof(char));
  if(r->request_token == NULL) return -10;
  memcpy(r->request_token, tmp_token, strlen(tmp_token));

  r->request_secret = (char *)calloc((strlen(tmp_secret))+1, sizeof(char));
  if(r->request_secret == NULL) return -11;
  memcpy(r->request_secret, tmp_secret, strlen(tmp_secret));

  return 0;
}

int Twitter_GetAccessToken(struct Twitter_consumer_token *c, struct Twitter_request_token *r, struct Twitter_access_token *a)
{
  int i;
  struct timeval tv;

  char buf[BUF_SIZE] = {0};

  char encpath[100] = {0}; //エンコードしたURL
  char nonce[100] = {0};
  char nonce_urlenc[100] = {0};
  char nonce_tmp[100] = {0};
  char tstamp[100] = {0};

  char tmp_token[200] = {0};
  char tmp_secret[200] = {0};
  char tmp_usrid[200] = {0};
  char tmp_usrname[200] = {0};

  char reqheader[800] = {0};//POSTヘッダ
  char auth_tmpmsg[800] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ
  char auth_encmsg[800] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ(URL-Encoded)

  char hmacmsg[300] = {0}, b64msg[300] = {0}, b64urlenc[300] = {0};
  char oauth_signature_key[200] = {0};

  //署名キー
  sprintf(oauth_signature_key, "%s&%s", c->consumer_secret, r->request_secret);

  //時間を取得してタイムスタンプと一意な値をセット
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  //OAuth用メッセージ結合
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_TOKEN, r->request_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, VER_1_0);
  URLEncode(auth_tmpmsg, auth_encmsg);
  URLEncode(ACCESS_TOKEN_URL, encpath);
  for(i=0; i<400; i++) auth_tmpmsg[i] = 0;
  sprintf(auth_tmpmsg, "%s&%s&%s", MSG_POST, encpath, auth_encmsg);

  //シグネイチャ生成
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_tmpmsg, strlen(auth_tmpmsg), hmacmsg);

  //シグネイチャの文字数カウント
  //HMAC署名では署名中に\0記号が出てくることもあるため、今チェックしているポイントから3連続で
  //\0が続いた時にbreakするようにしている
  i=0;
  while(i<300) {
    if(hmacmsg[i] == 0 && hmacmsg[i+1] == 0 && hmacmsg[i+2] == 0) break;
    i++;
  }

  //署名文字列をBASE64エンコード、さらにURLエンコード
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //POST用メッセージ生成
  sprintf(reqheader, "%s %s?%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s %s\r\n\r\n", MSG_POST, ACCESS_TOKEN_URL, OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_TOKEN, r->request_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, VER_1_0, MSG_HTTP);

  SSL_send_and_recv(reqheader, buf);

  if(ExtractQuery(buf, "oauth_token=", tmp_token) < 0) return -8;
  if(ExtractQuery(buf, "oauth_token_secret=", tmp_secret) < 0) return -9;
  if(ExtractQuery(buf, "user_id=", tmp_usrid) < 0) return -10;
  if(ExtractQuery(buf, "screen_name=", tmp_usrname) < 0) return -11;

  a->access_token = (char *)calloc((strlen(tmp_token))+1, sizeof(char));
  if(a->access_token == NULL) return -12;
  memcpy(a->access_token, tmp_token, strlen(tmp_token));

  a->access_secret = (char *)calloc((strlen(tmp_secret))+1, sizeof(char));
  if(a->access_secret == NULL) return -13;
  memcpy(a->access_secret, tmp_secret, strlen(tmp_secret));

  a->user_id = (char *)calloc((strlen(tmp_usrid))+1, sizeof(char));
  if(a->user_id == NULL) return -14;
  memcpy(a->user_id, tmp_usrid, strlen(tmp_usrid));

  a->screen_name = (char *)calloc((strlen(tmp_usrname))+1, sizeof(char));
  if(a->screen_name == NULL) return -15;
  memcpy(a->screen_name, tmp_usrname, strlen(tmp_usrname));

  return 0;
}

int Twitter_UpdateStatus(struct Twitter_consumer_token *c,  struct Twitter_access_token *a, char *status)
{
  int i;
  struct timeval tv;

  char buf[BUF_SIZE];

  char encpath[100] = {0}; //エンコードしたURL
  char nonce[100] = {0};
  char nonce_urlenc[100] = {0};
  char nonce_tmp[100] = {0};
  char tstamp[100] = {0};

  char reqheader[2000] = {0};//POSTヘッダ
  char auth_tmpmsg[2000] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ
  char auth_encmsg[2000] = {0};//HMAC-SHA1でメッセージ作るときの仮メッセージ(URL-Encoded)
  char encstatus[2000] = {0};

  char hmacmsg[300] = {0}, b64msg[300] = {0}, b64urlenc[300] = {0};
  char oauth_signature_key[200] = {0};

  //署名キー
  sprintf(oauth_signature_key, "%s&%s", c->consumer_secret, a->access_secret);

  //時間を取得してタイムスタンプと一意な値をセット
  gettimeofday(&tv, NULL);
  sprintf(tstamp, "%ld", tv.tv_sec);

  sprintf(nonce_tmp, "%ld", tv.tv_usec);
  base64_encode(nonce_tmp, strlen(nonce_tmp), nonce, 128);
  URLEncode(nonce, nonce_urlenc);

  URLEncode(status, encstatus);

  //OAuth用メッセージ結合
  sprintf(auth_tmpmsg, "%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s", OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp,  OAUTH_TOKEN, a->access_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, VER_1_0, STATUS, encstatus);
  URLEncode(auth_tmpmsg, auth_encmsg);
  URLEncode(STATUS_UPDATE_URL, encpath);
  for(i=0; i<400; i++) auth_tmpmsg[i] = 0;
  sprintf(auth_tmpmsg, "%s&%s&%s", MSG_POST, encpath, auth_encmsg);

  //シグネイチャ生成
  hmac_sha1(oauth_signature_key, strlen(oauth_signature_key), auth_tmpmsg, strlen(auth_tmpmsg), hmacmsg);

  //シグネイチャの文字数カウント
  //HMAC署名では署名中に\0記号が出てくることもあるため、今チェックしているポイントから3連続で
  //\0が続いた時にbreakするようにしている
  i=0;
  while(i<300) {
    if(hmacmsg[i] == 0 && hmacmsg[i+1] == 0 && hmacmsg[i+2] == 0) break;
    i++;
  }

  //署名文字列をBASE64エンコード、さらにURLエンコード
  base64_encode(hmacmsg, i, b64msg, 128);
  URLEncode(b64msg, b64urlenc);

  //POST用メッセージ生成
  sprintf(reqheader, "%s %s?%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s&%s%s %s\r\n\r\n", MSG_POST, STATUS_UPDATE_URL, OAUTH_CONSKEY, c->consumer_key, OAUTH_NONCE, nonce_urlenc, OAUTH_SIG, b64urlenc, OAUTH_SIGMETHOD, HMAC_SHA1, OAUTH_TSTAMP, tstamp, OAUTH_TOKEN, a->access_token, OAUTH_VERIFIER, a->pin, OAUTH_VER, VER_1_0, STATUS, encstatus, MSG_HTTP);

  SSL_send_and_recv(reqheader, buf);

  return 0;
}
