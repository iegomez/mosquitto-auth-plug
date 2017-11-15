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

#ifdef BE_LORASERVER
#include "backends.h"
#include "be-loraserver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "log.h"
#include "envs.h"
#include <curl/curl.h>
#include "parson.h"
#include "go-auth.h"

/*
static int get_string_envs(CURL * curl, const char *required_env, char *querystring)
{
	char *data = NULL;
	char *escaped_key = NULL;
	char *escaped_val = NULL;
	char *env_string = NULL;

	char *params_key[MAXPARAMSNUM];
	char *env_names[MAXPARAMSNUM];
	char *env_value[MAXPARAMSNUM];
	int i, num = 0;

	//_log(LOG_DEBUG, "sys_envs=%s", sys_envs);

	env_string = (char *)malloc(strlen(required_env) + 20);
	if (env_string == NULL) {
		_fatal("ENOMEM");
		return (-1);
	}
	sprintf(env_string, "%s", required_env);

	//_log(LOG_DEBUG, "env_string=%s", env_string);

	num = get_sys_envs(env_string, ",", "=", params_key, env_names, env_value);
	//sprintf(querystring, "");
	for (i = 0; i < num; i++) {
		escaped_key = curl_easy_escape(curl, params_key[i], 0);
		escaped_val = curl_easy_escape(curl, env_value[i], 0);

		//_log(LOG_DEBUG, "key=%s", params_key[i]);
		//_log(LOG_DEBUG, "escaped_key=%s", escaped_key);
		//_log(LOG_DEBUG, "escaped_val=%s", escaped_envvalue);

		data = (char *)malloc(strlen(escaped_key) + strlen(escaped_val) + 1);
		if (data == NULL) {
			_fatal("ENOMEM");
			return (-1);
		}
		sprintf(data, "%s=%s&", escaped_key, escaped_val);
		if (i == 0) {
			sprintf(querystring, "%s", data);
		} else {
			strcat(querystring, data);
		}
	}

	if (data)
		free(data);
	if (escaped_key)
		free(escaped_key);
	if (escaped_val)
		free(escaped_val);
	free(env_string);
	return (num);
}


#define URL_SZ 256
#define BUF_SZ 10*1024

long written = 0;

static int receive( void* buffer, size_t length, size_t size, void* data ) {
    size_t l = length * size;

    if ( l > 0 ) {
        if ( written + l >= BUF_SZ ) {
            fprintf( stderr, "Buffer size exceeded.\n" );
            return 0;
        }
        memcpy( &( (char*) data )[ written ], buffer, l );
        written += l;
    }

    _log(LOG_DEBUG, "data: %s", data);

    return l;
}
*/

/*
static int http_post(void *handle, char *uri, const char *clientid, const char *token, const char *topic, int acc, int method)
{
	struct loraserver_backend *conf = (struct loraserver_backend *)handle;
	CURL *curl;
	struct curl_slist *headerlist = NULL;
	int re;
	int respCode = 0;
	int ok = FALSE;
	char *url;
	char *data;


  char rData[ BUF_SZ ];

  memset( rData, 0, BUF_SZ );
	written = 0;

	if (token == NULL) {
		return (FALSE);
	}
	clientid = (clientid && *clientid) ? clientid : "";
	topic = (topic && *topic) ? topic : "";

	if ((curl = curl_easy_init()) == NULL) {
		_fatal("create curl_easy_handle fails");
		return (FALSE);
	}
	if (conf->hostheader != NULL)
		headerlist = curl_slist_append(headerlist, conf->hostheader);
	headerlist = curl_slist_append(headerlist, "Expect:");

	//_log(LOG_NOTICE, "u=%s p=%s t=%s acc=%d", username, password, topic, acc);

	url = (char *)malloc(strlen(conf->ip) + strlen(uri) + 20);
	if (url == NULL) {
		_fatal("ENOMEM");
		return (FALSE);
	}
	//enable the https
		if (strcmp(conf->with_tls, "true") == 0) {
		sprintf(url, "https://%s:%d%s", conf->ip, conf->port, uri);
	} else {
		sprintf(url, "http://%s:%d%s", conf->ip, conf->port, uri);
	}

	char *escaped_token = curl_easy_escape(curl, token, 0);
	char *escaped_topic = curl_easy_escape(curl, topic, 0);
	char *escaped_clientid = curl_easy_escape(curl, clientid, 0);

	char string_acc[20];
	snprintf(string_acc, 20, "%d", acc);

	char *string_envs = (char *)malloc(MAXPARAMSLEN);
	if (string_envs == NULL) {
		_fatal("ENOMEM");
		return (FALSE);
	}
	memset(string_envs, 0, MAXPARAMSLEN);

	//get the sys_env from here
		int env_num = 0;
	if (method == METHOD_GETUSER && conf->getuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->getuser_envs, string_envs);
	} else if (method == METHOD_SUPERUSER && conf->superuser_envs != NULL) {
		env_num = get_string_envs(curl, conf->superuser_envs, string_envs);
	} else if (method == METHOD_ACLCHECK && conf->aclcheck_envs != NULL) {
		env_num = get_string_envs(curl, conf->aclcheck_envs, string_envs);
	}
	if (env_num == -1) {
		return (FALSE);
	}
	//----over-- --

		data = (char *)malloc(strlen(string_envs) + strlen(escaped_topic) + strlen(string_acc) + strlen(escaped_clientid) + 30);
	if (data == NULL) {
		_fatal("ENOMEM");
		return (FALSE);
	}
	sprintf(data, "%stopic=%s&acc=%s&clientid=%s",
		string_envs,
		escaped_topic,
		string_acc,
		clientid);

	_log(LOG_DEBUG, "url=%s", url);
	_log(LOG_DEBUG, "data=%s", data);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	char *token_header = (char *)malloc(strlen(escaped_token) + 22);
	if (token_header == NULL) {
		_fatal("ENOMEM");
		return (FALSE);
	}
	sprintf(token_header, "Authorization: Bearer %s", escaped_token);
	headerlist = curl_slist_append(headerlist, token_header);


	if (method == METHOD_ACLCHECK) {

		headerlist = curl_slist_append(headerlist, "Accept: application/json");
		headerlist = curl_slist_append(headerlist, "Content-Type: application/json");
		headerlist = curl_slist_append(headerlist, "charsets: utf-8");

		JSON_Value *jsonRoot = json_value_init_object();
  	JSON_Object *jsonObject = json_value_get_object(jsonRoot);
  	char *serialized_string = NULL;
	  json_object_set_string(jsonObject, "topic", escaped_topic);
	  json_object_set_string(jsonObject, "clientid", clientid);
	  json_object_set_number(jsonObject, "acc", acc);
	  serialized_string = json_serialize_to_string(jsonRoot);
	  _log(LOG_NOTICE, "json: %s", serialized_string);


	  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, serialized_string);
	  //curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);
	  
	  json_free_serialized_string(serialized_string);
  	json_value_free(jsonRoot);
	} else {
		//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		_log(LOG_NOTICE, "sending without data");
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
	

	if (strcmp(conf->verify_peer, "true") == 0) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	} else {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rData);

	_log(LOG_NOTICE, "using token_header: %s", token_header);

	re = curl_easy_perform(curl);
	if (re == CURLE_OK) {

		JSON_Value *jsonResponse = json_parse_string(rData);
  	JSON_Object *jsonObject = json_value_get_object(jsonResponse);
  	int respOk = json_object_get_boolean(jsonObject, "ok");
  	const char* respErr = json_object_get_string(jsonObject, "error");

  	_log(LOG_NOTICE, "got these values:  ok: %d  error: %s", respOk, respErr);

		re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
		if (re == CURLE_OK && respCode >= 200 && respCode < 300 && respOk) {
			ok = TRUE;
		} else if (re == CURLE_OK && respCode >= 500) {
			ok = BACKEND_ERROR;
		} else {
			_log(LOG_NOTICE, "http auth fail re=%d respCode=%d error=%s", re, respCode, respErr);
		}
		json_value_free(jsonResponse);
	} else {
		_log(LOG_NOTICE, "http req fail url=%s re=%s", url, curl_easy_strerror(re));
		ok = BACKEND_ERROR;
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(headerlist);
	free(url);
	free(data);
	free(string_envs);
	free(escaped_token);
	free(token_header);
	free(escaped_topic);
	free(escaped_clientid);

	return (ok);
}

*/

void *be_loraserver_init()
{
	struct loraserver_backend *conf;
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
	conf = (struct loraserver_backend *)malloc(sizeof(struct loraserver_backend));
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
void be_loraserver_destroy(void *handle)
{
	struct loraserver_backend *conf = (struct loraserver_backend *)handle;

	if (conf) {
		curl_global_cleanup();
		free(conf);
	}
};

char *be_loraserver_getuser(void *handle, const char *token, const char *pass, int *authenticated)
{
	if (token == NULL) {
		return NULL;
	}

	struct loraserver_backend *conf = (struct loraserver_backend *)handle;
	GoString goUri = {conf->getuser_uri, strlen(conf->getuser_uri)};
	GoString goToken = {token, strlen(token)};

	if(User(goUri, goToken)){
		*authenticated = 1;
	}

	return NULL;
};

int be_loraserver_superuser(void *handle, const char *token)
{
	struct loraserver_backend *conf = (struct loraserver_backend *)handle;
	GoString goUri = {conf->superuser_uri, strlen(conf->superuser_uri)};
	GoString goToken = {token, strlen(token)};

	return Superuser(goUri, goToken);
};

int be_loraserver_aclcheck(void *handle, const char *clientid, const char *token, const char *topic, int acc)
{
	struct loraserver_backend *conf = (struct loraserver_backend *)handle;
	GoString goUri = {conf->aclcheck_uri, strlen(conf->superuser_uri)};
	GoString goToken = {token, strlen(token)};
	GoString goTopic = {topic, strlen(topic)};

	return Acl(goUri, goToken, goTopic);
};

#endif /* BE_LORASERVER */
