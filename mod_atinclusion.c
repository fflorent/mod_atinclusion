#include <string.h>
#include <stdio.h>
#include <httpd.h>
#include <http_protocol.h>
#include <apr_general.h>
#include <http_config.h>
#include <http_request.h>
#include <http_log.h>
#include <apr_hash.h>
#include <apr_strings.h>
#include <libxml/HTMLparser.h>

#define URI_LENGTH 	strlen(r->uri)
#define __DEFAULT 	"__default"

#define SPLIT_OK 	 0
#define SPLIT_REDIR	 1
#define log(r,type, ...) ap_log_error(APLOG_MARK, type, 0, (r)->server, __VA_ARGS__)
#define loginfo(r,...)	 log(r, APLOG_INFO, __VA_ARGS__)
#define logerror(r,...)	 log(r, APLOG_ERR, __VA_ARGS__)

typedef struct req_cfg {
	apr_hash_t *hash;
	htmlParserCtxtPtr parser;
}Req_cfg;

typedef struct ctx {
	request_rec *r;
} Ctx;

/* global module structure */
module AP_MODULE_DECLARE_DATA atinclusion_module ;
static char* stringify_atinclusions(request_rec *r);
static char* split_and_next(char* str, char splitter);
static int storeatinclusions(char *atinclusions, request_rec *r);
static int remove_atinclusions(request_rec *r);


static char* stringify_atinclusions(request_rec *r){
	Req_cfg *rc = ap_get_module_config(r->request_config,
		&atinclusion_module);
	apr_hash_t *h = rc->hash;
	apr_pool_t *p = r->pool;
	apr_hash_index_t *hi;
	char splitter[] = {'@',','};
	int iSplitter = 0;
	char ret[500] = "", *key, *val, *pair;
	if(h == NULL)
	{
		return NULL;
	}
	for(hi = apr_hash_first(p, h); hi; hi =apr_hash_next(hi))
	{
		apr_hash_this(hi, (const void**)&key, NULL, (void**)&val);
		sprintf(ret, "%s%c%s=%s", ret, splitter[iSplitter], key, val);
		iSplitter = 1;
	}
	// remove the first comma and allocate:
	return apr_pstrdup(p, ret );
}

static apr_status_t freeParser(void* p){
	htmlParserCtxtPtr parser = (htmlParserCtxtPtr) p;
	htmlFreeParserCtxt(parser);
	return OK;
}



static char* split_and_next(char* str, char splitter)
{
	char *next = strchr(str, splitter);
	if(next != NULL){
		next[0]='\0';
		next++;
	}
	return next;
}

static void pStartElement(void *vCtx, xmlChar *uname, xmlChar **uattr)
{
	Ctx *ctx = (Ctx*) vCtx;
	int i = 0;
	xmlChar *attr;
	while((attr = uattr[i]) != NULL) 
	{
		loginfo(ctx->r, "%s", (const char*) attr);
	}
	loginfo(ctx->r, "fin startElement");	
}

static Req_cfg* set_config(request_rec *r){
	Req_cfg *rc = apr_palloc(r->pool, sizeof(Req_cfg));
	htmlSAXHandler *sax = apr_palloc(r->pool, sizeof(htmlSAXHandler));
	Ctx *ctx = apr_palloc(r->pool, sizeof(Ctx));
	loginfo(r, "ok kikou");
	ctx->r = r;
	rc->hash = apr_hash_make(r->pool);
	rc->parser = htmlCreatePushParserCtxt(sax, ctx, NULL, 0, NULL, 0);
	sax->startElement = pStartElement;
	loginfo(r, "ok création parser");
	ap_set_module_config(r->request_config, &atinclusion_module, rc);
	apr_pool_cleanup_register(r->pool, rc->parser, htmlFreeParserCtxt, apr_pool_cleanup_null);
	return rc;
}

static int remove_atinclusions(request_rec *r)
{
	char *atinclusions, *redir, *new_uri;
	int res;
	
	// if atinclusions is null, we do not have to treat anything, so we decline
	if ( (r->uri[0] != '/' && r->uri[0] != '\0')) {
		return DECLINED;
	}
	
	atinclusions = strchr(r->uri, '@');
	if(atinclusions == NULL)
		return DECLINED;
	// we split the uri, so we remove the atinclusions from it :
	atinclusions[0] = '\0'; // we replace '@' by '\0'
	atinclusions++; // and we move the pointer to the next character
	set_config(r);
	res = storeatinclusions(atinclusions, r);
	if(res == SPLIT_REDIR){
		// NOTE : seems like apr_pstrcat does not provide the correct behaviour, 
		// so we use apr_pstrcat to concatene these strings :
		redir = apr_pstrcat(r->pool,  r->uri, stringify_atinclusions(r), NULL); 
		apr_table_setn(r->headers_out, "Location", redir);
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,  "redir : %s  ", redir);
		return HTTP_MOVED_TEMPORARILY;
	}	       
	//ap_internal_redirect(new_uri, r);
	return OK;
}



static int storeatinclusions(char *atinclusions, request_rec *r){
	char *c , *key, *value;
	int ret = SPLIT_OK;
	Req_cfg *rc = ap_get_module_config(r->request_config, &atinclusion_module);
	c = atinclusions;
	while(c != NULL){
		key = c;
		// split : 
		value = split_and_next(c, '=');
		if(value == NULL)
			break;
		// c goes to the next pair now, so value has only the value
		c = split_and_next(value, ',');
		
		if(strcmp(value, __DEFAULT) == 0){
			// if value === "__default", we remove the key :
			value = NULL;
			ret = SPLIT_REDIR;
		}
		else{
			value = apr_pstrdup(r->pool, value);
		}
		// do we replace a key that already exist ?
		if( apr_hash_get(rc->hash, key, APR_HASH_KEY_STRING) ){
			apr_hash_set(rc->hash, key, 
				     APR_HASH_KEY_STRING, NULL); // we remove the old key
			ret = SPLIT_REDIR;
		}
		
		// we store :
		apr_hash_set(rc->hash, key, APR_HASH_KEY_STRING, 
				value);
		
	}
	return ret;
}


static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb) 
{
	apr_bucket* b;
	request_rec *r = f->r;
	char* buf = 0 ;
	apr_size_t bytes = 0 ;
	int rs;
	Req_cfg* rc = ap_get_module_config(r->request_config, &atinclusion_module );
	if(!rc){
		loginfo(r, "rc is null");
		return ap_pass_brigade(f->next, bb);
	}
	loginfo(r, "ok");
	loginfo(r, "content-type: %s", r->content_type);
	// if non-(x)html document, we abort
	if(strncasecmp(r->content_type, "text/html", 9) &&
	    strncasecmp(r->content_type, "application/xhtml+xml", 21)){
		loginfo(r, "Non-HTML File, do not treat it : %s", r->filename);
		return APR_SUCCESS;
	}
	loginfo(r, "ok2");
	loginfo(r, "test");
	loginfo(r, "pointer : %i", rc==NULL);
	for (b = APR_BRIGADE_FIRST(bb) ;
	     b != APR_BRIGADE_SENTINEL(bb) ;
	     b = APR_BUCKET_NEXT(b) ) {
			// inspired from mod_proxy_html : 
		    if ( APR_BUCKET_IS_METADATA(b) ) {
			if ( APR_BUCKET_IS_EOS(b) ) {
				if ( rc->parser != NULL ) {
					htmlParseChunk(rc->parser, "", 0, 1);
				}
				APR_BUCKET_REMOVE(b);
				APR_BRIGADE_INSERT_TAIL(bb, b);
				ap_pass_brigade(f->next, bb) ;
			} else if ( APR_BUCKET_IS_FLUSH(b) ) {
				/* pass on flush, except at start where it would cause
				 * headers to be sent before doc sniffing
				 */
				if ( rc->parser != NULL ) {
					ap_fflush(f->next, bb) ;
				}
			}
		} else if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
			== APR_SUCCESS ) {
			htmlParseChunk(rc->parser, buf, bytes, 0);
		}
		else{
			logerror(r, "Error in bucket read");
		}
	}
	return APR_SUCCESS;
}

static void atinclusion_filter_insert(request_rec *r)
{
	ap_add_output_filter("atinsert", NULL, r, r->connection);
}

static void register_hooks(apr_pool_t* pool)
{
	static const char* aszSucc[] = { "mod_filter.c", NULL };
	ap_hook_post_read_request(remove_atinclusions,NULL,NULL,APR_HOOK_FIRST );
	ap_register_output_filter_protocol("atinsert", atinclusion_filter,
					   NULL, AP_FTYPE_RESOURCE,
					   AP_FILTER_PROTO_CHANGE|
					   AP_FILTER_PROTO_CHANGE_LENGTH) ;
	ap_hook_insert_filter(atinclusion_filter_insert, NULL, aszSucc, APR_HOOK_MIDDLE) ;
}

module AP_MODULE_DECLARE_DATA atinclusion_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};



