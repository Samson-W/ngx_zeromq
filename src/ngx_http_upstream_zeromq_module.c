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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_zeromq.h>
#include <ngx_http.h>
#include <nginx.h>


#ifndef nginx_version
#error This module cannot be build against an unknown nginx version.
#endif

//0MQ Handle模块的配置项结构体
typedef struct {
	//若当前模式为可发送的，将配置的模式类型和对端地址等保存到此
    ngx_zeromq_endpoint_t    *send;
	//若当前模式为可接收的，将配置的模式类型和对端地址等保存到此
    ngx_zeromq_endpoint_t    *recv;
	//使用本地端点预定义的端口号，只有一个工作进程可以绑定到，且只有进行了nginx
	//reload后才会停止，不建议在生产中使用
    ngx_flag_t                single;
	//最大缓存连接个数，zeromq_keepalive的参数指定
	ngx_uint_t                max_cached;
	//可用连接缓存列表
	ngx_queue_t               cache;
	//不可用或正在使用的连接缓存列表
	ngx_queue_t               free;

} ngx_http_upstream_zeromq_srv_conf_t;

//此结构是保存在u->peer.data，在get和free时使用的data数据
typedef struct {
	ngx_http_upstream_zeromq_srv_conf_t  *conf;
	//发送端点信息
    ngx_zeromq_connection_t   			send;
	//接收端点信息
    ngx_zeromq_connection_t   			recv;
	//保存请求结构地址
    ngx_http_request_t       			*request;
	//非REQ模式下的头部信息链
    ngx_chain_t              			*headers;
} ngx_http_upstream_zeromq_peer_data_t;

//一个0MQ连接缓存的元素结构
typedef struct {
	//当前模块配置
	ngx_http_upstream_zeromq_srv_conf_t  	*conf;
	//当前缓存元素的链表地址
	ngx_queue_t                        		queue;
	//zmq socket连接
	void                     				*zmq_socket;
	//zmq socket对应的fd
	int 									zmq_fd;
} ngx_http_upstream_zeromq_kpalive_cache_t;

static ngx_int_t ngx_http_upstream_init_zeromq(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_init_zeromq_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_zeromq_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_zeromq_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void *ngx_http_upstream_zeromq_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_zeromq_endpoint(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_zeromq_keepalive(ngx_conf_t *cf, 
	ngx_command_t *cmd, void *conf);
//此模块对应的配置项的各种属性和选项，以下配置都只能在upstream块中进行配置
static ngx_command_t  ngx_http_upstream_zeromq_commands[] = {

    { ngx_string("zeromq_local"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE2,
      ngx_http_upstream_zeromq_endpoint,
      NGX_HTTP_SRV_CONF_OFFSET,
      1,
      NULL },

    { ngx_string("zeromq_remote"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE2,
      ngx_http_upstream_zeromq_endpoint,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("zeromq_single"),
      NGX_HTTP_UPS_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_zeromq_srv_conf_t, single),
      NULL },

    { ngx_string("zeromq_keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_zeromq_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_zeromq_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_zeromq_create_conf,  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_zeromq_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_zeromq_module_ctx,  /* module context */
    ngx_http_upstream_zeromq_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_upstream_init_zeromq(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	ngx_uint_t 									i;
    ngx_http_upstream_zeromq_srv_conf_t  		*zcf;
	ngx_http_upstream_zeromq_kpalive_cache_t	*cached;
	//得到此模块在upstream模块中的配置参数
    zcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_zeromq_module);

    if (zcf->send == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing sending endpoint in upstream \"%V\"",
                           &us->host);
        return NGX_ERROR;
    }

    if (zcf->recv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "missing receiving endpoint in upstream \"%V\"",
                           &us->host);
        return NGX_ERROR;
    }
	//模式为REQ时此值为0
    if ((zcf->single != 1)
        && ((zcf->send->bind && !zcf->send->rand)
            || (zcf->recv->bind && !zcf->recv->rand)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "local endpoint must use random port numbers,"
                           " use \"tcp://A.B.C.D:*\" in upstream \"%V\"",
                           &us->host);
        return NGX_ERROR;
    }
	//处理请求阶段的初始化函数，会在每个请求处理时作为初始化函数调用，此方法在ngx_http_upstream_init_request调用
    us->peer.init = ngx_http_upstream_init_zeromq_peer;
	
	/* allocate cache items and add to free queue */
	
	cached = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_zeromq_kpalive_cache_t) * zcf->max_cached);
	if (cached == NULL) {
		return NGX_ERROR;
	}

	ngx_queue_init(&zcf->cache);
	ngx_queue_init(&zcf->free);

	for (i = 0; i < zcf->max_cached; i++) {
		ngx_queue_insert_head(&zcf->free, &cached[i].queue);
		cached[i].conf = zcf;
	}

    return NGX_OK;
}

//处理请求阶段的初始化函数，会在每个请求处理时作为初始化函数调用，此方法在ngx_http_upstream_init_request调用
static ngx_int_t
ngx_http_upstream_init_zeromq_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_zeromq_peer_data_t  *zp;
    ngx_http_upstream_zeromq_srv_conf_t   *zcf;
    ngx_http_upstream_t                   *u;

    zp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_zeromq_peer_data_t));
    if (zp == NULL) {
        return NGX_ERROR;
    }

    zcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_zeromq_module);

	//若设置了rand项，表示端口随机，则随机分配一个endpoint
    if (zcf->send->rand) {
        zp->send.endpoint = ngx_zeromq_randomized_endpoint(zcf->send, r->pool);
        if (zp->send.endpoint == NULL) {
            return NGX_ERROR;
        }
	//将使用zeromq srv conf中的数据
    } else {
        zp->send.endpoint = zcf->send;
    }
	//接收和发送的端点不一样
    if (zcf->recv != zcf->send) {
        if (zcf->recv->rand) {
            zp->recv.endpoint = ngx_zeromq_randomized_endpoint(zcf->recv,
                                                               r->pool);
            if (zp->recv.endpoint == NULL) {
                return NGX_ERROR;
            }

        } else {
            zp->recv.endpoint = zcf->recv;
        }
	//接收和发送都是一样的端点
    } else {
        zp->recv.endpoint = zp->send.endpoint;
    }
	//将请求的上下文地址保存
    zp->request = r;
	zp->conf = zcf;
	//将upstream上下文地址保存
    u = r->upstream;
	//这个data仅用于和上面的get free方法配合传递参数
    u->peer.data = zp;
	//远端服务器的地址
    u->peer.name = &zp->send.endpoint->addr;
	//获取连接的方法，如果使用长连接构成的连接池，那么必须实现get方法
    u->peer.get = ngx_http_upstream_get_zeromq_peer;
	//与get方法对应的释放连接的方法
    u->peer.free = ngx_http_upstream_free_zeromq_peer;
	//若端点的类型不是REQ
    if (zp->recv.endpoint->type != &ngx_zeromq_socket_types[NGX_ZEROMQ_REQ]) {
		//conf->module表示使用upstream的模块名称
        if (u->conf->module.len == sizeof("proxy") - 1
            && ngx_strncmp(u->conf->module.data, "proxy",
                           sizeof("proxy") - 1) == 0)
        {
            zp->headers = ngx_zeromq_headers_add_http(u->request_bufs,
                                                      zp->recv.endpoint,
                                                      r->pool);
            if (zp->headers == NGX_CHAIN_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_zeromq_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_zeromq_peer_data_t  		*zp = data;
	ngx_http_upstream_zeromq_kpalive_cache_t 	*item = NULL;
    ngx_int_t                              		rc;
	ngx_queue_t       							*q, *cache;
	
	/*
	//若发送接收端点不是同一个时
    if (zp->recv.endpoint != zp->send.endpoint) {
        pc->data = &zp->recv;
        rc = ngx_zeromq_connect(pc);
        pc->data = data;

        if (rc != NGX_OK) {
            return rc;
        }

        zp->recv.connection.data = zp->request;
    }*/
	//现在只考虑模式为REQ的情况(即发送端和接收端是一样的)
	 /* search cache for suitable connection */
	cache = &zp->conf->cache;
	//从cache列表中查找一个可重用的0MQ连接，若没有可用的，则按照原来的方法进行生成连接
	q = ngx_queue_head(cache);
	if (q != ngx_queue_sentinel(cache)){
		item = ngx_queue_data(q, ngx_http_upstream_zeromq_kpalive_cache_t, queue);
		ngx_queue_remove(q);
		ngx_queue_insert_head(&zp->conf->free, q);	
	}
	
	//配置data数据，若没有在cache中查找到可重用的0MQ连接的话，则自己创建连接
    pc->data = &zp->send;
	if (item != NULL) {
	    rc = ngx_zeromq_connect(pc, item->zmq_socket, item->zmq_fd);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "------yygy get zmq keepalive peer zmq_socket %p zmq_fd %d", item->zmq_socket, item->zmq_fd);
	}
	else
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "-----yygy get zmq keepalive peer item is NULL");
		rc = ngx_zeromq_connect(pc, NULL, 0);
	}
    pc->data = data;

    if (rc != NGX_OK) {
		//如果使用的是重用的0MQ连接的话，在出错时要将此此连接还到cache中
		if ( item != NULL ){
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "-----yygy get zmq keeplive connect is fail!");
			if (!ngx_queue_empty(&zp->conf->free)){
				q = ngx_queue_head(&zp->conf->free);
			    ngx_queue_remove(q);
				ngx_queue_insert_head(&zp->conf->cache, q);
			}
		}
        return rc;
    }

    zp->send.connection.data = zp->request;

    if (zp->recv.endpoint != zp->send.endpoint) {
        zp->send.recv = zp->recv.recv;
        zp->recv.send = zp->send.send;
    }

    if (zp->recv.endpoint->rand && zp->headers) {
        ngx_zeromq_headers_set_http(zp->headers->buf, zp->recv.endpoint);
    }

    if (pc->connection->pool == NULL) {
        pc->connection->pool = ngx_create_pool(128, pc->log);
        if (pc->connection->pool == NULL) {
            return NGX_ERROR;
        }
    }

    pc->sockaddr = ngx_pcalloc(pc->connection->pool, sizeof(struct sockaddr));
    if (pc->sockaddr == NULL) {
        return NGX_ERROR;
    }

    pc->sockaddr->sa_family = AF_UNSPEC;
    pc->socklen = sizeof(struct sockaddr);

    return NGX_DONE;
}


void
ngx_http_upstream_free_zeromq_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_zeromq_peer_data_t  		*zp = data;
	ngx_http_upstream_zeromq_kpalive_cache_t    *item = NULL;
	ngx_queue_t          						*q;

    if (pc->connection) {
#if (nginx_version >= 1001004)
        if (pc->connection->pool) {
            ngx_destroy_pool(pc->connection->pool);
        }
#endif

        pc->connection = NULL;
    }

	if (!ngx_queue_empty(&zp->conf->free)) {
		q = ngx_queue_head(&zp->conf->free);
		ngx_queue_remove(q);

		item = ngx_queue_data(q, ngx_http_upstream_zeromq_kpalive_cache_t, queue);
		ngx_queue_insert_head(&zp->conf->cache, q);
		item->zmq_fd = zp->send.connection.fd;
		item->zmq_socket = zp->send.socket;
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "-----------yygy free zmq keepalive peer item zmq_socket %p zmq_fd is %d", item->zmq_socket, item->zmq_fd );
		if (zp->send.socket) {
			ngx_zeromq_close(&zp->send, 1);
		}
	}
	else{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "----------yygy  free zmq keepalive peer close orign");
    	if (zp->recv.endpoint != zp->send.endpoint) {
        	if (zp->recv.socket) {
            	ngx_zeromq_close(&zp->recv, 0);
        	}
    	}

    	if (zp->send.socket) {
        	ngx_zeromq_close(&zp->send, 0);
    	}
	}
}

//创建upstream_zeromq_srv_conf结构
static void *
ngx_http_upstream_zeromq_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_zeromq_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_zeromq_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc(ngx_http_upstream_zeromq_keepalive NULL;
     *     conf->recv = NULL;
     */

    conf->single = NGX_CONF_UNSET;

	conf->max_cached = 1;

    return conf;
}


static char *
ngx_http_upstream_zeromq_endpoint(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                            *value = cf->args->elts;
	//conf是分配给此模块的conf结构体
    ngx_http_upstream_zeromq_srv_conf_t  *zcf = conf;
	//upstream模块的conf结构体
    ngx_http_upstream_srv_conf_t         *uscf;
	//0MQ中不同类型的模式所对应的操作方法
    ngx_zeromq_socket_t                  *type;
	//一个0MQ端点指针
    ngx_zeromq_endpoint_t                *zep;
    ngx_uint_t                            i;
	//得到upstream模块的配置参数
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
	//得到ngx_zeromq所支持的类型列表
    type = ngx_zeromq_socket_types;
	//对比配置参数是否是有效的参数
    for (i = 0; type[i].value; i++) {
        if (ngx_strcmp(value[1].data, type[i].name.data) == 0) {
            break;
        }
    }
	//为0时表示配置的参数为无效的
    if (type[i].value == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid socket type \"%V\" in upstream \"%V\"",
                           &value[1], &uscf->host);
        return NGX_CONF_ERROR;
    }

    if (type[i].can_send) {
        if (zcf->send) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "sending endpoint already set to"
                               " \"%V\" (%V) in upstream \"%V\"",
                               &zcf->send->addr, &zcf->send->type->name,
                               &uscf->host);
            return NGX_CONF_ERROR;
        }
    }

    if (type[i].can_recv) {
        if (zcf->recv) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "receivng endpoint already set to"
                               " \"%V\" (%V) in upstream \"%V\"",
                               &zcf->recv->addr, &zcf->recv->type->name,
                               &uscf->host);
            return NGX_CONF_ERROR;
        }
    }
	//申请一个zep空间
    zep = ngx_pcalloc(cf->pool, sizeof(ngx_zeromq_endpoint_t));
    if (zep == NULL) {
        return NGX_CONF_ERROR;
    }
	//由配置项赋值给zeq结构
    zep->type = &type[i];
	//得到配置的上游服务器地址
    zep->addr = value[2];
	//通过commands中的参数配置项的倒数第二个值来配置是否进行绑定，当为remote时不绑定
    zep->bind = cmd->offset;

    if ((ngx_strncmp(zep->addr.data, "tcp://", sizeof("tcp://") - 1) == 0)
        && (ngx_strncmp(zep->addr.data + zep->addr.len - (sizeof(":*") - 1),
                        ":*", sizeof(":*") - 1) == 0))
    {
		//端口号若是*表示是随机的
        zep->rand = 1;
        zep->addr.len -=  sizeof("*") - 1;
    }

    if (zep->rand && !zep->bind) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "random port numbers don't make sense for remote"
                           " endpoint in upstream \"%V\"", &uscf->host);
        return NGX_CONF_ERROR;
    }
	//若此模式是可以发送的，将本模块的配置项中的send赋值
    if (type[i].can_send) {
        zcf->send = zep;
    }

	//若此模式是可以接收的，将本模块的配置项中的recv赋值
    if (type[i].can_recv) {
        zcf->recv = zep;
    }
	//若upstream服务数组为空，则分配一个数组
    if (uscf->servers == NULL) {
        uscf->servers = ngx_pcalloc(cf->pool, sizeof(ngx_array_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (uscf->servers->nelts == 0) {
        uscf->servers->nelts = 1;
    }
	//此回调方法在upstream模块进行init main configuration时进行调用
    uscf->peer.init_upstream = ngx_http_upstream_init_zeromq;
	//表示是否使用了此模块
    ngx_zeromq_used = 1;

    return NGX_CONF_OK;
}

static char *
ngx_http_upstream_zeromq_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                            *value = cf->args->elts;
	//conf是分配给此模块的conf结构体
    ngx_http_upstream_zeromq_srv_conf_t  *zcf = conf;

	ngx_int_t    n;

	/* read options */

	n = ngx_atoi(value[1].data, value[1].len);

	if (n == NGX_ERROR || n == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"invalid value \"%V\" in \"%V\" directive",
						&value[1], &cmd->name);		        
		return NGX_CONF_ERROR;
	}
	//得到最大缓存连接数
	zcf->max_cached = n;

    return NGX_CONF_OK;
}
