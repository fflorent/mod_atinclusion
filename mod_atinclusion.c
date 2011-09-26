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
#include <apr_buckets.h>
#include <libxml/HTMLparser.h>

#define URI_LENGTH 	strlen(r->uri)
#define __DEFAULT 	"__default"

#define SPLIT_OK 	 0
#define SPLIT_REDIR	 1
#define log(r,type, ...) ap_log_error(APLOG_MARK, type, 0, (r)->server, __VA_ARGS__)
#define loginfo(r,...)	 log(r, APLOG_INFO, __VA_ARGS__)
#define logerror(r,...)	 log(r, APLOG_ERR, __VA_ARGS__)
//#define splitbucket(ctx) apr_bucket_split((ctx->curBucket), ctx->length_read - xmlByteConsumed(ctx->parser) +1)

typedef struct content2rem{
	apr_bucket* from;
	apr_bucket* to;
	char* tNodeName;
	int stackNodeName; // since there are sub-elements having the same name than the target,
			   // we use this variable, so it is greater than 0 when they are being processed
	int enabled; // are we removing the content of a target ?
}Content2Rem;

typedef struct ctx {
	request_rec *r;
	htmlParserCtxt* parser;
	unsigned long length_read;
	apr_bucket *curBucket;
	apr_hash_t *hash;
	Content2Rem *c2r;
	char* tmp_buf;
} Ctx;
typedef struct req_cfg {
	htmlSAXHandler *sax;
	Ctx* ctx;
}Req_cfg;


/* global module structure */
module AP_MODULE_DECLARE_DATA atinclusion_module ;
static char* stringify_atinclusions(request_rec *r);
static char* split_and_next(char* str, char splitter);
static int storeatinclusions(char *atinclusions, request_rec *r);
static int remove_atinclusions(request_rec *r);
static void splitbucket(Ctx* ctx, int correction);

static char* stringify_atinclusions(request_rec *r){
	Req_cfg *rc = ap_get_module_config(r->request_config,
		&atinclusion_module);
	apr_hash_t *h = rc->ctx->hash;
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

static void splitbucket(Ctx* ctx, int correction){
	long offset = xmlByteConsumed(ctx->parser) + correction - ctx->length_read;
	apr_bucket_split((ctx->curBucket), offset);
	ctx->length_read += offset;
}

static void pStartElement(void *vCtx, xmlChar *uname, xmlChar **uattr)
{
	Ctx *ctx = (Ctx*) vCtx;
	request_rec *r = ctx->r;
	int i = 0;
	Content2Rem* c2r = ctx->c2r;
	xmlChar *attrname, *attrval;
	loginfo(r, "analyzing %s", uname);
	if(c2r->enabled){ // if we are in a target element
		// if the current elements have the same name than the target element :
		if(strcasecmp(c2r->tNodeName, uname)) 
			c2r->stackNodeName++; 
		return; // we can directly abort since this element will be removed soon
	}
	if(uattr == NULL)
		return;
	if(ctx->parser == NULL){
		logerror(r, "parser is NULL");
		return;
	}
		
	for(i = 0; (attrname = uattr[i]) != NULL &&
		   (attrval = uattr[i+1]) != NULL; i+=2) 
	{
		loginfo(r, "%s = %s", (const char*) attrname, (const char*) attrval);
		if( strcasecmp(attrname, "href") == 0){
			
		}
		else if(strcasecmp(attrname, "id") == 0 && apr_hash_get( ctx->hash, attrval, APR_HASH_KEY_STRING )){
			loginfo(r, "found id : %s", attrval);
			c2r->enabled = 1;
			splitbucket(ctx, +1);
			c2r->from = ctx->curBucket = APR_BUCKET_NEXT(ctx->curBucket);
			loginfo(r, "from : %i", c2r->from);
			loginfo(r, "next : %s", &ctx->tmp_buf[xmlByteConsumed(ctx->parser)]);
			//qloginfo(r, "will be removed : %s", ctx->tmp_buf + ctx->length_read - xmlByteConsumed(ctx->parser) +1);
			c2r->tNodeName = apr_pstrdup(r->pool, uname);
			c2r->stackNodeName = 0;
			//*(ctx->curBucket) = c2r->from;
		}
	}
	
	loginfo(r, "consummed : %i", xmlByteConsumed(ctx->parser));
	loginfo(r, "fin startElement");
}

static void pEndElement(void *vCtx, xmlChar* uname){
	Ctx* ctx = (Ctx*) vCtx;
	Content2Rem *c2r = ctx->c2r;
	apr_bucket *b;
	const char* uri;
	request_rec* rr;
	int rrv;
	loginfo(ctx->r,"end of %s",uname);
	if(c2r->enabled){
		loginfo(ctx->r, "testing %s", c2r->tNodeName);
		if(strcasecmp(uname, c2r->tNodeName)){
			if(c2r->stackNodeName)
				c2r->stackNodeName--;
			else{
				c2r->enabled = 0;
				splitbucket(ctx, -3-strlen(uname));
				c2r->to = APR_BUCKET_NEXT(ctx->curBucket);
				loginfo(ctx->r, "to : %i", c2r->to);
				//loginfo(ctx->r, "%s", &ctx->tmp_buf[xmlByteConsumed(ctx->parser) -3-strlen(uname) - ctx->length_read]);
				//APR_BUCKET_REMOVE(c2r->from);
				for(b = c2r->from; b != c2r->to; 
				      b = APR_BUCKET_NEXT(b)){
					loginfo(ctx->r, "removing bucket : %i", b);
					APR_BUCKET_REMOVE(b);
				}
				uri = apr_hash_get(ctx->hash, c2r->tNodeName, APR_HASH_KEY_STRING);
				rr = ap_sub_req_lookup_uri(uri, ctx->r, NULL);
				if(rr== NULL || rr->status != HTTP_OK){
					logerror(ctx->r, "MOD_ATINCLUSION : could not include %s", uri);
					return;
				}
				//if(rr->content_type)
				rrv = ap_run_sub_req(rr);
				if(rrv){
					logerror(ctx->r, "MOD_ATINCLUSION : could not run the request");
					return;
				}
				ctx->curBucket = c2r->from;
				
				memset(c2r, 0, sizeof(Content2Rem));
			}
		}
	}
}

static Req_cfg* set_config(request_rec *r){
	loginfo(r, "test");
	Req_cfg *rc = apr_palloc(r->pool, sizeof(Req_cfg));
	rc->sax = apr_palloc(r->pool, sizeof(htmlSAXHandler));
	memset(rc->sax, 0, sizeof(rc->sax));
	Ctx *ctx = apr_palloc(r->pool, sizeof(Ctx));
	ctx->r = r;
	ctx->parser = NULL;
	loginfo(r, "ctx : %i", ctx->r);
	ctx->hash = apr_hash_make(r->pool);
	ctx->c2r = apr_palloc(r->pool, sizeof(Content2Rem));
	memset(ctx->c2r, 0, sizeof(Content2Rem));
	//rc->parser = htmlCreatePushParserCtxt(sax, ctx, NULL, 4, NULL, 0);
	rc->sax->startElement = pStartElement;
	rc->sax->endElement = pEndElement;
	rc->ctx = ctx;
	ap_set_module_config(r->request_config, &atinclusion_module, rc);
	//apr_pool_cleanup_register(r->pool, rc->sax, htmlFreeParserCtxt, apr_pool_cleanup_null);
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
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,  "redir : %s ", redir);
		return HTTP_MOVED_TEMPORARILY;
	}	       
	//ap_internal_redirect(new_uri, r);
	return OK;
}



static int storeatinclusions(char *atinclusions, request_rec *r){
	char *c , *key, *value;
	int ret = SPLIT_OK;
	Req_cfg *rc = ap_get_module_config(r->request_config, &atinclusion_module);
	apr_hash_t* hash = rc->ctx->hash;
	if(!rc)
		return -1;
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
		if( apr_hash_get(hash, key, APR_HASH_KEY_STRING) ){
			apr_hash_set(hash, key, 
				     APR_HASH_KEY_STRING, NULL); // we remove the old key
			ret = SPLIT_REDIR;
		}
		
		// we store :
		apr_hash_set(hash, key, APR_HASH_KEY_STRING, 
				value);
		
	}
	return ret;
}


static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	apr_bucket* b;
	request_rec *r = f->r;
	const char* buf = 0 ;
	apr_size_t bytes = 0 ;
	int rs, enabled_before;
	htmlParserCtxtPtr parser = NULL;
	Req_cfg* rc = ap_get_module_config(r->request_config, &atinclusion_module );
	if(rc == NULL){
		loginfo(r, "MOD_ATINCLUSION : rc is null, abort");
		return ap_pass_brigade(f->next, bb);
	}
	// if non-(x)html document, we abort
	if(strncasecmp(r->content_type, "text/html", 9) &&
	    strncasecmp(r->content_type, "application/xhtml+xml", 21)){
		loginfo(r, "Non-HTML File, do not treat it : %s", r->filename);
		return APR_SUCCESS;
	}
	
	
	loginfo(r, "parser creation ok");
	for (b = APR_BRIGADE_FIRST(bb) ;
	     b != APR_BRIGADE_SENTINEL(bb) ;
	     b = APR_BUCKET_NEXT(b) ) {
		rc->ctx->curBucket = b;
			// inspired from mod_proxy_html : 
		if ( APR_BUCKET_IS_METADATA(b) ) {
			if ( APR_BUCKET_IS_EOS(b) ) {
				loginfo(r, "ok?");
				if ( parser != NULL ) {
					htmlParseChunk(parser, buf, 0, 1);
					loginfo(r, "finished");
				}
				
				APR_BUCKET_REMOVE(b);
				APR_BRIGADE_INSERT_TAIL(bb, b);
			} else if ( APR_BUCKET_IS_FLUSH(b) ) {
				/* 
				 * pass on flush, except at start where it would cause
				 * headers to be sent before doc sniffing
				 */
				if ( parser != NULL ) {
					ap_fflush(f->next, bb) ;
				}
			}
		} 
		else if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
			== APR_SUCCESS ) {
			
			rc->ctx->tmp_buf = buf;
			if(parser == NULL){
				parser = htmlCreatePushParserCtxt(rc->sax, rc->ctx, 0, 0, NULL, XML_CHAR_ENCODING_NONE);
				apr_pool_cleanup_register(r->pool, parser, 
							  (int(*)(void*))htmlFreeParserCtxt, apr_pool_cleanup_null) ;
				rc->ctx->parser = parser;
				/*buf += 4;
				bytes -= 4;*/
				if(parser == NULL){
					int rv = ap_pass_brigade(f->next, bb);
					htmlFreeParserCtxt(parser);
					logerror(r, "MOD_ATINCLUSION : parser creation failed");
					return rv;
				}
			}
			loginfo(r, "creation ok : %i", rc->ctx);
			htmlParseChunk(parser, buf, bytes, 0);
			b = rc->ctx->curBucket; // if we moved the bucket
			rc->ctx->length_read += bytes;
			
			
			loginfo(r, "parse ok");
		}
		else{
			logerror(r, "Error in bucket read");
		}
	}
	loginfo(r,"???");
	
	return ap_pass_brigade(f->next, bb) ;
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



