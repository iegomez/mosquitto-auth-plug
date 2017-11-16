/*
 * Copyright (c) 2013 Jan-Piet Mens <jp@mens.de> wendal
 * <wendal1985()gmai.com> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions
 * in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. Neither the name of mosquitto
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef BE_GOLANG
#include "backends.h"
#include "be-golang.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "log.h"
#include "envs.h"
#include <curl/curl.h>
#include "parson.h"
#include "go-auth.h"

void *be_golang_init()
{
	struct golang_backend *conf;
	char *ip;
	char *getuser_uri;
	char *superuser_uri;
	char *aclcheck_uri;

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		_fatal("init curl fail");
		return (NULL);
	}
	if ((ip = p_stab("http_ip")) == NULL) {
		_fatal("Mandatory parameter `http_ip' missing");
		return (NULL);
	}
	if ((getuser_uri = p_stab("http_getuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_getuser_uri' missing");
		return (NULL);
	}
	if ((superuser_uri = p_stab("http_superuser_uri")) == NULL) {
		_fatal("Mandatory parameter `http_superuser_uri' missing");
		return (NULL);
	}
	if ((aclcheck_uri = p_stab("http_aclcheck_uri")) == NULL) {
		_fatal("Mandatory parameter `http_aclcheck_uri' missing");
		return (NULL);
	}
	conf = (struct golang_backend *)malloc(sizeof(struct golang_backend));
	conf->ip = ip;
	conf->port = p_stab("http_port") == NULL ? 80 : atoi(p_stab("http_port"));
	if (p_stab("http_hostname") != NULL) {
		conf->hostheader = (char *)malloc(128);
		sprintf(conf->hostheader, "Host: %s", p_stab("http_hostname"));
	} else {
		conf->hostheader = NULL;
	}
	conf->getuser_uri = getuser_uri;
	conf->superuser_uri = superuser_uri;
	conf->aclcheck_uri = aclcheck_uri;

	conf->getuser_envs = p_stab("http_getuser_params");
	conf->superuser_envs = p_stab("http_superuser_params");
	conf->aclcheck_envs = p_stab("http_aclcheck_params");

	if (p_stab("http_with_tls") != NULL) {
		conf->with_tls = p_stab("http_with_tls");
	} else {
		conf->with_tls = "false";
	}

	if (p_stab("http_verify_peer") != NULL) {
		conf->verify_peer = p_stab("http_verify_peer");
	} else {
		conf->verify_peer = "false";
	}

	_log(LOG_DEBUG, "with_tls=%s", conf->with_tls);
	_log(LOG_DEBUG, "verify_peer=%s", conf->verify_peer);
	_log(LOG_DEBUG, "getuser_uri=%s", getuser_uri);
	_log(LOG_DEBUG, "superuser_uri=%s", superuser_uri);
	_log(LOG_DEBUG, "aclcheck_uri=%s", aclcheck_uri);
	_log(LOG_DEBUG, "getuser_params=%s", conf->getuser_envs);
	_log(LOG_DEBUG, "superuser_params=%s", conf->superuser_envs);
	_log(LOG_DEBUG, "aclcheck_paramsi=%s", conf->aclcheck_envs);

	return (conf);
};
void be_golang_destroy(void *handle)
{
	struct golang_backend *conf = (struct golang_backend *)handle;

	if (conf) {
		curl_global_cleanup();
		free(conf);
	}
};

char *be_golang_getuser(void *handle, const char *token, const char *pass, int *authenticated)
{
	if (token == NULL) {
		return NULL;
	}

	struct golang_backend *conf = (struct golang_backend *)handle;

	GoString goHost = {conf->ip, strlen(conf->ip)};
	GoInt32 goPort = conf->port;
	GoString goUri = {conf->getuser_uri, strlen(conf->getuser_uri)};
	GoString goToken = {token, strlen(token)};
	GoString goWithTLS = {conf->with_tls, strlen(conf->with_tls)};
	GoString goVerifyPeer = {conf->verify_peer, strlen(conf->verify_peer)};

	if(User(goHost, goUri, goToken, goWithTLS, goVerifyPeer, goPort)){
		*authenticated = 1;
	}

	return NULL;
};

int be_golang_superuser(void *handle, const char *token)
{
	struct golang_backend *conf = (struct golang_backend *)handle;

	GoString goHost = {conf->ip, strlen(conf->ip)};
	GoInt32 goPort = conf->port;
	GoString goUri = {conf->superuser_uri, strlen(conf->superuser_uri)};
	GoString goToken = {token, strlen(token)};
	GoString goWithTLS = {conf->with_tls, strlen(conf->with_tls)};
	GoString goVerifyPeer = {conf->verify_peer, strlen(conf->verify_peer)};

	return Superuser(goHost, goUri, goToken, goWithTLS, goVerifyPeer, goPort);
};

int be_golang_aclcheck(void *handle, const char *clientid, const char *token, const char *topic, int acc)
{
	struct golang_backend *conf = (struct golang_backend *)handle;

	GoString goHost = {conf->ip, strlen(conf->ip)};
	GoInt32 goPort = conf->port;
	GoString goUri = {conf->aclcheck_uri, strlen(conf->aclcheck_uri)};
	GoString goToken = {token, strlen(token)};
	GoString goTopic = {topic, strlen(topic)};
	GoString goWithTLS = {conf->with_tls, strlen(conf->with_tls)};
	GoString goVerifyPeer = {conf->verify_peer, strlen(conf->verify_peer)};
	GoString goClientID = {clientid, strlen(clientid)};
	GoInt32 goAcc = acc;

	return Acl(goHost, goUri, goToken, goWithTLS, goVerifyPeer, goTopic, goClientID, goAcc, goPort);
};

#endif /* BE_GOLANG */
