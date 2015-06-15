/*
 * Copyright (c) 2012-2014, FRiCKLE <info@frickle.com>
 * Copyright (c) 2012-2014, Piotr Sikora <piotr.sikora@frickle.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NGX_EVENT_ZEROMQ_H_INCLUDED_
#define _NGX_EVENT_ZEROMQ_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_connect.h>


#define NGX_ZEROMQ_REQ   0
#define NGX_ZEROMQ_PUSH  1
#define NGX_ZEROMQ_PULL  2

typedef struct ngx_zeromq_connection_s  ngx_zeromq_connection_t;

//为zeromq支持几种模式，各种模式对应的值及能够处理的行为都是固定的
typedef struct {
	//模式名
    ngx_str_t                 name;
	//此模式对应的值
    int                       value;
	//是否能发送
    unsigned                  can_send:1;
	//是否能接收 
    unsigned                  can_recv:1;
} ngx_zeromq_socket_t;


typedef struct {
	//zeromq scoket的类型
    ngx_zeromq_socket_t      *type;
	//zeromq socket的地址
    ngx_str_t                 addr;
	//是否绑定端口
    unsigned                  bind:1;
	//端口是否随机
    unsigned                  rand:1;
} ngx_zeromq_endpoint_t;


struct ngx_zeromq_connection_s {
	//保存0MQ连接的fd的连接结构
    ngx_connection_t          connection;
	//存放0MQ连接的fd的连接结构地址
    ngx_connection_t         *connection_ptr;
	//端点信息
    ngx_zeromq_endpoint_t    *endpoint;
	//0MQ创建的套接字
    void                     *socket;

    ngx_event_handler_pt      handler;
	//保存send结构
    ngx_zeromq_connection_t  *send;
	//保存recv结构
    ngx_zeromq_connection_t  *recv;
	//请求是否已发送
    unsigned                  request_sent:1;
};

ngx_zeromq_endpoint_t *ngx_zeromq_randomized_endpoint(
    ngx_zeromq_endpoint_t *zep, ngx_pool_t *pool);

ngx_chain_t *ngx_zeromq_headers_add_http(ngx_chain_t *in,
    ngx_zeromq_endpoint_t *zep, ngx_pool_t *pool);
void ngx_zeromq_headers_set_http(ngx_buf_t *b, ngx_zeromq_endpoint_t *zep);

ngx_int_t ngx_zeromq_connect(ngx_peer_connection_t *pc, void *zmq_skt, int zmq_fd);
void ngx_zeromq_close(ngx_zeromq_connection_t *zc,  int flag);


extern ngx_zeromq_socket_t  ngx_zeromq_socket_types[];
extern ngx_int_t            ngx_zeromq_used;


#endif /* _NGX_EVENT_ZEROMQ_H_INCLUDED_ */
