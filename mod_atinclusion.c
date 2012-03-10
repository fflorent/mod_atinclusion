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
#include <util_script.h>


#define SPLIT_OK 	 0
#define SPLIT_REDIR	 1
#define SPLIT_ERROR	-1
#define remove_from_hash(hash, key) 
#define log(r,type, ...) ap_log_error(APLOG_MARK, type, 0, (r)->server, __VA_ARGS__)
#define loginfo(r,...)	 log(r, APLOG_INFO, __VA_ARGS__)
#define logerror(r,...)	 log(r, APLOG_ERR, __VA_ARGS__)


//#define splitbucket(ctx) apr_bucket_split((ctx->curBucket), ctx->length_read - xmlByteConsumed(ctx->parser) +1)
typedef struct Bucket2Rem {
	apr_bucket* from;
	apr_bucket* to;
	const char* urlReplaceWith;
	struct Bucket2Rem* next;
}Bucket2Rem;

typedef struct content2rem{
	apr_bucket* curFrom;
	Bucket2Rem* stackB2R;
	char* tNodeName;
	char* tNodeId;
	int stackNodeName; // since there are sub-elements having the same name than the target,
			   // we use this variable, so it is greater than 0 when they are being processed
	int enabled; // are we removing the content of a target ?
}Content2Rem;

typedef struct ctx {
	request_rec *r;
	ap_filter_t* f;
	apr_bucket_brigade* bb;
	htmlParserCtxt* parser;
	unsigned long length_read;
	apr_bucket *curBucket;
	apr_hash_t *hash_atpairs;
	Content2Rem *c2r;
	char* tmp_buf;
	apr_bucket* insertBefore;
} Ctx;
typedef struct req_cfg {
	htmlSAXHandler *sax;
	Ctx* ctx;
}Req_cfg;







/* global module structure */
module AP_MODULE_DECLARE_DATA atinclusion_module ;
static char* split_and_next(char* str, char splitter);
static char* stringify_atinclusions(Ctx* ctx, apr_hash_t* hash, int prefixWithFilename);
static int remove_atinclusions(request_rec *r);
static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb);
static long lookforStr(Ctx* ctx, char* str, int dir);
static int splitbucket(Ctx* ctx, long offset);
static const char* rewrite_href(Ctx* ctx, xmlChar* href);
static int storeatinclusions(char *atinclusions, request_rec *r, apr_hash_t* hash, int useOp);

static Bucket2Rem* unshiftBuck2Rem(apr_bucket* from, apr_bucket* to, const char* urlReplaceWith, Ctx* ctx){
	Content2Rem* c2r = ctx->c2r;
	Bucket2Rem* b2r = apr_palloc(ctx->r->pool, sizeof(Bucket2Rem));
	b2r->from = from;
	b2r->to = to;
	b2r->urlReplaceWith =  urlReplaceWith;
	b2r->next = c2r->stackB2R;
	c2r->stackB2R = b2r;
	return b2r;
}
static Bucket2Rem* shiftBuck2Rem(Ctx* ctx){
	Content2Rem* c2r = ctx->c2r;
	Bucket2Rem* b2r= c2r->stackB2R;
	c2r->stackB2R = c2r->stackB2R->next;
	return b2r;
}
static int isEndBuck2Rem(Ctx* ctx){
	return ctx->c2r->stackB2R == NULL;
}
static char* stringify_atinclusions(Ctx* ctx, apr_hash_t* hash, int prefixWithFilename)
{
	apr_hash_index_t *hi;
	char splitter[] = {'@',','};
	int iSplitter = 0;
	char ret[500], *key, *val;
	request_rec* mainReq = (ctx->r->main ? ctx->r->main : ctx->r);
	if(prefixWithFilename)
		strcpy(ret, mainReq->uri);
	else
		ret[0] = '\0';
	if(hash == NULL)
	{
		return NULL;
	}
	for(hi = apr_hash_first(ctx->r->pool, hash); hi; hi =apr_hash_next(hi))
	{
		apr_hash_this(hi, (const void**)&key, NULL, (void**)&val);
		sprintf(ret, "%s%c%s=%s", ret, splitter[iSplitter], key, val);
		iSplitter = 1;
	}
	// remove the first comma and allocate:
	return apr_pstrdup(ctx->r->pool, ret );
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

static long getParserPosition(Ctx* ctx){
	//loginfo(ctx->r, "cur=%s, base=%s, else = %i", input->cur, input->base, input->cur - input->base);
	//loginfo(ctx->r, "consumed = %i, %i", xmlByteConsumed(ctx->parser), input->cur - input->base);
	return xmlByteConsumed(ctx->parser);
}
/**
 * strrstr : like strstr but for reverse search
 */
static char* strrstr(char* str, char* looked_for){
	int i, l_lf = strlen(looked_for);
	for(i=strlen(str)-l_lf; i >= 0 && strncmp(str+i, looked_for, l_lf); i--);
	return i >=0 ? str+i : NULL;
}


static long lookforStr(Ctx* ctx, char* looked_for, int dir)
{
	loginfo(ctx->r, "splitbucket : %s", ctx->tmp_buf);
	char* str2 = ctx->tmp_buf; 
	char* found ;
	dir = dir >= 0 ? 1 : -1; // we ensure dir equals to 1 or -1. 1 => forward, -1 => bakward
	long offset, parserPos = getParserPosition(ctx) - ctx->length_read;
	loginfo(ctx->r, "length_read=%ld, offset=%ld ; dir=%i; looked_for='%s'; start='%s'", ctx->length_read, parserPos, dir, looked_for, &str2[parserPos]);
	if(dir == -1){
		// we shorten str2 in order to make a reverse search
		loginfo(ctx->r, "strncpy ?");
		char* cp_str2 = strndup(str2, parserPos / sizeof(char)); // we make a copy of the original str2, so str is not affected by the shortening
		loginfo(ctx->r, "offset : '%s'", cp_str2);
		found = strrstr(cp_str2, looked_for);
		if(found == NULL){
			logerror(ctx->r, "splitbucket : occurrence not found : %s", looked_for);
			free(cp_str2);
			return -1;
		}
		offset = (found - cp_str2) * sizeof(char);
		free(cp_str2);
		loginfo(ctx->r, "ok : %s", &str2[offset]);
	}
	else{
		found = strstr(&str2[parserPos], looked_for);
		if(found == NULL)
			return -1;
		offset =  (strlen(looked_for)+(found - str2)) * sizeof(char);
	}
	return offset;
}


static int splitbucket(Ctx* ctx, long offset)
{

		
	
	loginfo(ctx->r, "offset=%ld", offset);
	//for(;str2[offset] != looked_for && offset > 0; offset += dir);
	//if(dir == 1) offset ++;
	apr_bucket_split((ctx->curBucket), offset);
	// we udpate str : 
	
	loginfo(ctx->r, "apres split");
	ctx->tmp_buf += offset;
	ctx->length_read += offset ;
	ctx->curBucket = APR_BUCKET_NEXT(ctx->curBucket) ;
	
	//loginfo(ctx->r, ">>> remove from : %s", "from":"before", &str2[offset]);
	return 0;
}


static void pStartElement(void *vCtx, xmlChar *uname, xmlChar **uattr)
{
	Ctx *ctx = (Ctx*) vCtx;
	request_rec *r = ctx->r;
	int i = 0, rv;
	long offset;
	Content2Rem* c2r = ctx->c2r;
	xmlChar *attrname, *attrval;
	const char* new_href;
	char c;
	loginfo(ctx->r, "analysing %s", uname);
	if(c2r->enabled){ // if we are in a target element
		// if the current elements have the same name than the target element :
		if(strcasecmp(c2r->tNodeName, (const char*) uname) == 0) {
			c2r->stackNodeName++; 
		}
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
		if( strcasecmp((const char*)attrname, "href") == 0 && attrval[0]=='@'){
			
			loginfo(r, "replacing : %s", attrval);
			new_href = rewrite_href(ctx, attrval);
			// put the content of the attribute in a seperate bucket
			offset = lookforStr(ctx, attrname, -1);
			if(offset < 0)
				continue;
			rv = splitbucket(ctx, offset);
			if(rv){
				continue;
			}
			loginfo(ctx->r, ">>> remove from : %s", &ctx->tmp_buf[offset]);
			offset =strlen(attrname)+2;
			for(; offset < strlen(ctx->tmp_buf)-1 && c != '"' && c != '\'' && c != ' ' && c != '>';
			    offset++, c = ctx->tmp_buf[offset-1]);
			if(offset >= strlen(ctx->tmp_buf)){
				loginfo(ctx->r, "attribute not found");
				continue;
			}
			apr_bucket* replaced = ctx->curBucket; 
			
			rv = splitbucket(ctx, offset);
			loginfo(ctx->r, ">>> [remove] to : %s", &ctx->tmp_buf[offset]);
			if(rv)
				continue;
			// set the new content of the attribute
			char *sReplacement = apr_palloc(r->connection->pool, strlen(attrname)+strlen(new_href)+3);
			sprintf(sReplacement, "%s=\"%s\"", attrname, new_href);
			loginfo(r, "replacement=%s", sReplacement);
			apr_bucket* replacement = apr_bucket_transient_create(sReplacement, strlen(sReplacement) * sizeof(char), r->connection->bucket_alloc);
			loginfo(r, "bucket created");
			APR_BUCKET_INSERT_BEFORE(replaced, replacement);
			APR_BUCKET_REMOVE( replaced );
			apr_bucket_destroy(replaced);
		}
		else if(strcasecmp(attrname, "id") == 0 && apr_hash_get( ctx->hash_atpairs, attrval, APR_HASH_KEY_STRING )){
			loginfo(r, "found id : %s", attrval);
			c2r->enabled = 1;
			offset = lookforStr(ctx, ">", +1);
			splitbucket(ctx, offset);
			c2r->curFrom = ctx->curBucket;
			c2r->tNodeName = apr_pstrdup(r->pool, uname);
			c2r->tNodeId = apr_pstrdup(r->pool, attrval);
			c2r->stackNodeName = 0;
		}
	}
	
}

static void pEndElement(void *vCtx, xmlChar* uname){
	Ctx* ctx = (Ctx*) vCtx;
	Content2Rem *c2r = ctx->c2r;
	const char* uri;
	int offset;
	//loginfo(ctx->r,"end of %s",uname);
	if(c2r->enabled){
		loginfo(ctx->r, "testing %s", c2r->tNodeName);
		if(strcasecmp((const char*)uname, c2r->tNodeName) == 0){
			
			//loginfo(ctx->r, "decrementing for %s", c2r->tNodeName);
			if(c2r->stackNodeName)
				c2r->stackNodeName--;
			else
			{
				c2r->enabled = 0;
				offset = lookforStr(ctx, "</", -1);
				splitbucket(ctx, offset);
				uri = apr_hash_get(ctx->hash_atpairs, c2r->tNodeId, APR_HASH_KEY_STRING);
				unshiftBuck2Rem(c2r->curFrom,  ctx->curBucket, uri, ctx);
			}
		}
	}
}

static Req_cfg* set_config(request_rec *r){
	loginfo(r, "setconfig");
	apr_pool_t* pool = r->pool;
	Req_cfg *rc = apr_palloc(pool, sizeof(Req_cfg));
	Req_cfg *rcParent = NULL;
	if(r->main)
		rcParent = ap_get_module_config(r->main->request_config, &atinclusion_module);
	rc->sax = apr_palloc(r->pool, sizeof(htmlSAXHandler));
	memset(rc->sax, 0, sizeof(rc->sax));
	Ctx *ctx = apr_palloc(pool, sizeof(Ctx));
	ctx->r = r;
	ctx->parser = NULL;
	ctx->length_read = 0;
	if(rcParent != NULL)
		ctx->hash_atpairs = rcParent->ctx->hash_atpairs;
	else 
		ctx->hash_atpairs = apr_hash_make(pool);
	ctx->c2r = apr_palloc(r->pool, sizeof(Content2Rem));
	ctx->c2r->stackB2R = NULL;
	//rc->parser = htmlCreatePushParserCtxt(sax, ctx, NULL, 4, NULL, 0);
	rc->sax->startElement = pStartElement;
	rc->sax->endElement = pEndElement;
	

	
	rc->ctx = ctx;
	ap_set_module_config(r->request_config, &atinclusion_module, rc);
	//apr_pool_cleanup_register(r->pool, rc->sax, htmlFreeParserCtxt, apr_pool_cleanup_null);
	return rc;
}

static const char* rewrite_href(Ctx* ctx, xmlChar* href){
	loginfo(ctx->r, "rewrite_href");
	request_rec *r = ctx->r;
	const char* ret;
	apr_hash_t* hash ;
	int rv;
	loginfo(ctx->r, "changing : %s", href);
	if(href[0] != '@'){
		loginfo(r, "wrong format for this href : %s", href);
		return NULL;
	}
	// if this is static "at inclusion"
	if(href[1] != '+' && href[1] != '-'){
		loginfo(r,"no operation, exit");
		return (const char*) href;
	}
	// below is the treatment for the "at inclusion" operations
	// it can be an addition of a pair with '+' (ex. : +key=value)
	// or a removal with '-' (ex. : -key)
	hash = apr_hash_copy(r->pool, ctx->hash_atpairs);
	rv = storeatinclusions(href+1, r, hash, 1);
	if(rv == SPLIT_ERROR){
		loginfo(r, "++failed to split : %s", href+1);
		return (const char*) href; // silent failed
	}
	ret = stringify_atinclusions(ctx, hash, 1);
	loginfo(r, "rewrite_href : return %s", ret);
	apr_hash_clear(hash);
	return ret;
}
/**
 * remove_atinclusions : removes @... from the requested URI
 */
static int remove_atinclusions(request_rec *r)
{
	char *atinclusions, *redir;
	int res;
	
	
	// if atinclusions is null, we do not have to treat anything, so we decline
	if ((r->uri[0] != '/' && r->uri[0] != '\0') ||
	    !strchr(r->unparsed_uri, '@')) {
		loginfo(r, "NOT OK : %s", r->unparsed_uri);
		return DECLINED;
	}
	loginfo(r, "remove_atinclusions");
	atinclusions = strchr(r->uri, '@'); // if not in query string
	if(atinclusions == NULL ){ // is it in query string ?
		atinclusions= strchr( r->args, '@');
		if(atinclusions == NULL)
			return DECLINED;
	}
	else{
		// we split the uri, so we remove the atinclusions from it :
		atinclusions[0] = '\0'; // we replace '@' by '\0'
	}
	atinclusions++; // and we move the pointer to the next character
	
	// we are sure that we will filter content from here
	// so we call set_config here
	Req_cfg* rc = set_config(r);
	res = storeatinclusions(atinclusions, r,  rc->ctx->hash_atpairs, 0);
	if(res == SPLIT_REDIR){
		// NOTE : seems like apr_pstrcat does not provide the correct behaviour, 
		// so we use apr_pstrcat to concatene these strings :
		
		redir = apr_pstrcat(r->pool,  r->unparsed_uri, 
				    stringify_atinclusions(rc->ctx, rc->ctx->hash_atpairs, 0), NULL); 
		loginfo(r, "REDIR : %s", redir);
		apr_table_setn(r->headers_out, "Location", redir);
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,  "redir : %s ", redir);
		return HTTP_MOVED_TEMPORARILY;
	}
	return OK;
}


static int storeatinclusions(char *atinclusions, request_rec *r, apr_hash_t* hash, int useOp){
	loginfo(r, "storeatinclusions : %s", atinclusions);
	char *c , *key, *value, op;
	int ret = SPLIT_OK;
	Req_cfg *rc = ap_get_module_config(r->request_config, &atinclusion_module);
	if(!rc)
		return SPLIT_ERROR;
	c = atinclusions;
	while(c != NULL){
		key = c;
		if(useOp && key[0] == '-'){ // '-' is used to remove a pair using its key (see rewrite_href), and so does not have value
			key++;
			c = split_and_next(c, ',');
			if(apr_hash_get(hash, key, APR_HASH_KEY_STRING)){
				apr_hash_set(hash, key, 
					     APR_HASH_KEY_STRING, NULL); // we remove the old key
			}
			continue;
		}
		// split : 
		value = split_and_next(c, '=');
		if(value == NULL)
			break;
		// c goes to the next pair now, so value has only the value
		c = split_and_next(value, ',');
		value = apr_pstrdup(r->pool, value);
		if(useOp) {
			op = key[0]; // operation, see rewrite_href
			key++;
			if(op != '+'){
				loginfo(r, "expected '+', found %c", op);
				return SPLIT_ERROR;
			}
		}
		
		// do we replace a key that already exist ?
		if( apr_hash_get(hash, key, APR_HASH_KEY_STRING) ){
			apr_hash_set(hash, key, 
				     APR_HASH_KEY_STRING, NULL); // we remove the old key
			ret = SPLIT_REDIR;
		}
		
		// we store :
		apr_hash_set(hash, key, APR_HASH_KEY_STRING, value);
		loginfo(r, "storeatinclusions : ok for %s=%s", key, value);
	}
	return ret;
}
/**
 * get_subr_content_filter : gets the content of a subrequest 
 * 			      and stores it in ctx->subr_buf
 */
static apr_status_t get_subr_content_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	loginfo(f->r, "entering in get_subr_content_filter");
	request_rec* r = f->r;
	if(!r->main) // if we are not in a sub-request
		return OK; // we abort
	Req_cfg *parentRc, *rc;
	parentRc = ap_get_module_config(r->main->request_config, &atinclusion_module);
	rc = ap_get_module_config(r->request_config, &atinclusion_module);
	

	apr_bucket *b , *next, *insertBefore;
	
	if( parentRc && rc ){
		insertBefore = parentRc->ctx->insertBefore;
		//apr_table_set(r->notes, "subr_buf", buf);
		for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);
			b = next) {
			next = APR_BUCKET_NEXT(b);
			if(!APR_BUCKET_IS_METADATA(b)){
				APR_BUCKET_REMOVE(b); 
				apr_bucket_setaside(b, f->c->pool);
				APR_BUCKET_INSERT_BEFORE(insertBefore, b);
			}
			
		}
		apr_brigade_cleanup(bb);
		
	}
	else
		return parentRc ? OK : DECLINED;
	return OK; // we do not output yet : the output will go through atinclusion_filter later
}

static void replaceContents(Ctx* ctx) {
	loginfo(ctx->r, "replaceContents");
	apr_bucket *from, *to, *b, *next;
	//apr_bucket_brigade* pass_bb;
	Bucket2Rem* b2r;
	const char* uri;
	request_rec *rr, *r = ctx->r;
	apr_status_t rrv;
	while( ! isEndBuck2Rem(ctx) ){
		b2r = shiftBuck2Rem(ctx);
		from = (b2r->from);
		to = (b2r->to);
		uri = b2r->urlReplaceWith;
		
		if (uri == NULL) {
			continue;
		}
		// we load the content before we remove the buckets between from and to
		// so if there is an error, we keep the original content
		loginfo(r, "attempting to run create request with this uri : %s", uri);
		// NOTE : second argument is r->main in order to keep the same "current" directory 
		//	  for redirections
		rr = ap_sub_req_lookup_uri(uri, r,  ctx->f->next);
		if (rr== NULL || rr->status != HTTP_OK) {
			logerror(r, "MOD_ATINCLUSION : could not include %s (status : %i)", uri, rr->status);
			continue;
		}
		for(b = from; b != to;b = next){
			next = APR_BUCKET_NEXT(b);
			APR_BUCKET_REMOVE(b);
			apr_bucket_destroy(b);
		}
		
		
		
		ctx->insertBefore = to;
		rrv = ap_run_sub_req(rr);
		if (rrv) {
			logerror(r, "MOD_ATINCLUSION : could not run the request for %s (code : %i)", uri, rrv);
			continue;
		}
		
		
		ap_destroy_sub_req(rr);
	}
}

static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	apr_bucket* b;
	request_rec *r = f->r;
	// if non-(x)html document, we abort
	if(!r->content_type || (strncasecmp(r->content_type, "text/html", 9) &&
	    strncasecmp(r->content_type, "application/xhtml+xml", 21))){
		loginfo(r, "Non-HTML File, do not treat it : %s", r->filename);
		return ap_pass_brigade(f->next, bb);
	}
	loginfo(r, "entering in atinclusion_filter");
	char* buf = 0 ;
	apr_size_t bytes = 0 ;
	htmlParserCtxtPtr parser = NULL;
	Req_cfg *rc = NULL;
	if(r->main)
		rc = set_config(r);
	else 	
		rc = ap_get_module_config(r->request_config, &atinclusion_module );
	/*if(parent){
		parentRc = ap_get_module_config(parent->request_config, &atinclusion_module);
		//parser = rc->ctx->parser;
	}*/
	if(rc == NULL){
		loginfo(r, "MOD_ATINCLUSION : rc is null, abort");
		return ap_pass_brigade(f->next, bb);
	}
	//if(!parent){
		rc->ctx->f = f;
		rc->ctx->bb = bb;
	//}
	loginfo(r, "create parser");
	parser = htmlCreatePushParserCtxt(rc->sax, rc->ctx, 0, 0, NULL, XML_CHAR_ENCODING_NONE);
	
	rc->ctx->parser = parser;
	if(parser == NULL){
		htmlFreeParserCtxt(parser);
		logerror(r, "MOD_ATINCLUSION : parser creation failed");
		return ap_pass_brigade(f->next, bb);
	}
	apr_pool_cleanup_register(r->pool, parser, 
					(int(*)(void*))htmlFreeParserCtxt, apr_pool_cleanup_null) ;
	loginfo(r, "parser created");
	loginfo(r, "loop begins");
	for (b = APR_BRIGADE_FIRST(bb) ;
	     b != APR_BRIGADE_SENTINEL(bb) ;
	     b = APR_BUCKET_NEXT(b) ) {
		rc->ctx->curBucket = b;
			// inspired from mod_proxy_html : 
		if ( APR_BUCKET_IS_METADATA(b) ) {
			if ( APR_BUCKET_IS_EOS(b) ) {
				if ( parser != NULL ) {
					htmlParseChunk(parser, buf, 0, 1);
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
		else if ( apr_bucket_read(b, (const char**)&buf, &bytes, APR_BLOCK_READ)
			== APR_SUCCESS ) {
			rc->ctx->tmp_buf = (char*)buf;
			if(parser == NULL){

			}
			loginfo(r,"parsing : %s", buf);
			htmlParseChunk(parser, buf, bytes, 0);
			loginfo(r,"parsed");
			b = rc->ctx->curBucket; // if we moved the bucket
			rc->ctx->length_read += bytes/sizeof(char);
			
			
		}
		else{
			logerror(r, "Error in bucket read");
			continue;
		}
		loginfo(r, "loop");
	}
	
	
	loginfo(r, "before replaceContents");	
	replaceContents(rc->ctx);
	if(!r->main) loginfo(r, "end for atinclusion_filter " );
	return ap_pass_brigade(f->next, bb);
}

static void atinclusion_filter_insert(request_rec *r)
{
	ap_add_output_filter("ATINSERT", NULL, r, r->connection);
	if(r->main){
		ap_add_output_filter("GET_SUBR_CONTENT", NULL, r, r->connection);
	}
}

static void register_hooks(apr_pool_t* pool)
{
	static const char* aszSucc[] = {  NULL };
	ap_hook_post_read_request(remove_atinclusions,NULL,NULL,APR_HOOK_FIRST );
	ap_register_output_filter_protocol("ATINSERT", atinclusion_filter,
					   NULL, AP_FTYPE_RESOURCE,
					   AP_FILTER_PROTO_CHANGE|
					   AP_FILTER_PROTO_CHANGE_LENGTH) ;
	/*ap_register_output_filter("ATINSERT", atinclusion_filter, NULL,
				  AP_FTYPE_RESOURCE);*/
	ap_register_output_filter_protocol("GET_SUBR_CONTENT", get_subr_content_filter,
					   NULL, AP_FTYPE_RESOURCE,
					   0) ;
	/*ap_register_output_filter("GET_SUBR_CONTENT", get_subr_content_filter, 
				  NULL, AP_FTYPE_RESOURCE);*/
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



