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
//#define GO_FASTER
#define remove_from_hash(hash, key) 
#define log(r,type, ...) ap_log_error(APLOG_MARK, type, 0, (r)->server, __VA_ARGS__)
#define loginfo(r,...)	 log(r, APLOG_INFO, __VA_ARGS__)
#define logerror(r,...)	 log(r, APLOG_ERR, __VA_ARGS__)

#define stroffset(begin, end)	(end-begin)*sizeof(char)
static htmlSAXHandler sax ;


//#define splitbucket(ctx) apr_bucket_split((ctx->curBucket), ctx->length_read - xmlByteConsumed(ctx->parser) +1)

//TODO : use structure for URL rewriting
typedef struct content2rem{
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
	apr_hash_t *hash_atpairs;
	Content2Rem *c2r;
	char* buf;
	char* main_uri;
} Ctx;
typedef struct req_cfg {
	//htmlSAXHandler *sax;
	Ctx* ctx;
}Req_cfg;







/* global module structure */
module AP_MODULE_DECLARE_DATA atinclusion_module ;
static char* split_and_next(char* str, char splitter);
static char* stringify_atinclusions(Ctx* ctx, apr_hash_t* hash, int prefixWithFilename);
static int remove_atinclusions(request_rec *r);
static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb);
static long lookforStr(Ctx* ctx, char* str, int dir);
static const char* rewrite_href(Ctx* ctx, xmlChar* href);
static int storeatinclusions(char *atinclusions, request_rec *r, apr_hash_t* hash, int useOp);
static void includeContents(Ctx* ctx, const char* uri);


static inline apply_offset(Ctx* ctx, long offset)
{
	ctx->buf += offset;
	ctx->length_read += offset;
}

static char* stringify_atinclusions(Ctx* ctx, apr_hash_t* hash, int prefixWithFilename)
{
	apr_hash_index_t *hi;
	char splitter[] = {'@',','};
	int iSplitter = 0;
	char ret[500], *key, *val;
	if(prefixWithFilename)
		strcpy(ret, ctx->main_uri);
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

static inline long get_parser_position(Ctx* ctx){
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
	char *str2 = ctx->buf; 
	char *found, *cp_str2;
	long offset, parserPos;
	//loginfo(ctx->r, "splitbucket : %s", ctx->buf);
	dir = dir >= 0 ? 1 : -1; // we ensure dir equals to 1 or -1. 1 => forward, -1 => bakward
	parserPos = get_parser_position(ctx) - ctx->length_read;
	loginfo(ctx->r, "length_read=%ld, offset=%ld ; dir=%i; looked_for='%s'; start='%s'", ctx->length_read, parserPos, dir, looked_for, &str2[parserPos]);
	if(dir == -1){
		// we shorten str2 in order to make a reverse search
		loginfo(ctx->r, "strncpy ?");
		cp_str2 = strndup(str2, parserPos / sizeof(char)); // we make a copy of the original str2, so str is not affected by the shortening
		loginfo(ctx->r, "offset : '%s'", cp_str2);
		found = strrstr(cp_str2, looked_for);
		if(found == NULL){
			logerror(ctx->r, "lookforStr : occurrence not found : %s", looked_for);
			free(cp_str2);
			return -1;
		}
		offset = stroffset( cp_str2, found);
		free(cp_str2);
		loginfo(ctx->r, "ok : %s", &str2[offset]);
	}
	else{
		found = strstr(&str2[parserPos], looked_for);
		if(found == NULL)
			return -1;
		offset =  strlen(looked_for) * sizeof(char) + stroffset(str2, found);
	}
	return offset;
}
static void printbucket(Ctx* ctx, long length)
{
	loginfo(ctx->r, "printing : %.*s", length, ctx->buf);
	ap_fwrite(ctx->f->next, ctx->bb, ctx->buf, length);
	apply_offset(ctx, length);
}


static void pStartElement(void *vCtx, xmlChar *uname, xmlChar **uattr)
{
	Ctx *ctx = (Ctx*) vCtx;
	request_rec *r = ctx->r;
	int i = 0, rv;
	long offset;
	Content2Rem *c2r = ctx->c2r;
	xmlChar *attrname, *attrval;
	const char *new_href;
	char delimiter;
	char *sReplacement, *found;
	char* uri_content;
	loginfo(ctx->r, "analysing %s", uname);
	if(!c2r)
		return;
	if(c2r->enabled){ // if we are in a target element
		// if the current elements have the same name than the target element :
		if(c2r->tNodeName && strcasecmp(c2r->tNodeName, uname) == 0) {
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
			offset = lookforStr(ctx, attrname, -1) ;
			if(offset < 0)
				continue;
			// we print everything before href="..."
			printbucket(ctx, offset);
			// we move the cursor (offset) after the old attribute, without printing it : 
			loginfo(ctx->r, ">>> remove from : %s", ctx->buf);
			offset =strlen(attrname)+1; // moving cursor : |href= -> href=|
			delimiter = ctx->buf[offset];
			if(delimiter != '"' && delimiter != '\''){
				logerror(r, "attribute value without quotes... aborting : %s=%s", attrname, attrval);
				continue ;
			}
			found = strchr(&ctx->buf[offset+1], delimiter);
			if(!found)
				continue;
			offset = stroffset(ctx->buf, found);
			offset++;// moving cursor : href="value|" -> href="value"|
			// we apply the offset : 
			apply_offset(ctx, offset);
			
			// we print the new attribute : 
			ap_fprintf(ctx->f, ctx->bb, "href=\"%s\"", new_href);
		}
		else if(strcasecmp(attrname, "id") == 0 && (uri_content = apr_hash_get( ctx->hash_atpairs, attrval, APR_HASH_KEY_STRING ))){
			loginfo(r, ">> found id : %s", attrval);
			c2r->enabled = 1;
			// TODO : uncomment when using a structure instead of a string : 
			// apr_hash_set( ctx->hash_atpairs, attrval, APR_HASH_KEY_STRING, NULL);
			offset = lookforStr(ctx, ">", +1);
			printbucket(ctx, offset);
			includeContents(ctx, uri_content);
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
		if(c2r->tNodeName && strcasecmp((const char*)uname, c2r->tNodeName) == 0){
			
			//loginfo(ctx->r, "decrementing for %s", c2r->tNodeName);
			if(c2r->stackNodeName)
				c2r->stackNodeName--;
			else
			{
				c2r->enabled = 0;
				offset = lookforStr(ctx, "</", -1);
				if(offset < 0){
					logerror(ctx->r, "cannot split at the end of the element, abort");
					return;
				}
				apply_offset(ctx, offset);
			}
		}
	}
}

static Req_cfg* set_config(request_rec *r){
	apr_pool_t* pool = r->pool;
	Req_cfg *rc = apr_palloc(pool, sizeof(Req_cfg));
	Req_cfg *rcParent = NULL;
	Ctx *ctx;
	char *atInclusions;
	loginfo(r, "setconfig");
	if(r->main)
		rcParent = ap_get_module_config(r->main->request_config, &atinclusion_module);
	memset(&sax, 0, sizeof(htmlSAXHandler));
	ctx = apr_palloc(pool, sizeof(Ctx));
	memset(ctx, 0, sizeof(Ctx));
	ctx->r = r;
	ctx->parser = NULL;
	ctx->length_read = 0;
	if(rcParent != NULL){
		ctx->hash_atpairs = rcParent->ctx->hash_atpairs;
		ctx->main_uri = rcParent->ctx->main_uri;
		ctx->bb = rcParent->ctx->bb;
	}
	else{ 
		ctx->hash_atpairs = apr_hash_make(pool);
		atInclusions = strchr(r->unparsed_uri, '@');
		ctx->main_uri = apr_pstrndup(r->pool, r->unparsed_uri, (atInclusions - r->unparsed_uri) * sizeof(char));
		ctx->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	}
	loginfo(r, "remove Content-Length");
	
	ctx->c2r = apr_palloc(r->pool, sizeof(Content2Rem));
	memset(ctx->c2r, 0, sizeof(Content2Rem));
	sax.startElement = pStartElement;
	sax.endElement = pEndElement;
	
	rc->ctx = ctx;
	ap_set_module_config(r->request_config, &atinclusion_module, rc);
	return rc;
}

static inline const char* rewrite_href(Ctx* ctx, xmlChar* href){
	request_rec *r = ctx->r;
	const char* ret;
	apr_hash_t* hash ;
	int rv;
	loginfo(ctx->r, "rewrite_href");
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
	Req_cfg* rc;
	
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
	rc = set_config(r);
	res = storeatinclusions(atinclusions, r,  rc->ctx->hash_atpairs, 0);
	if(res == SPLIT_REDIR){
		// we use apr_pstrcat to concatene these strings :
		
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
	char *c , *key, *value, op;
	int ret = SPLIT_OK;
	Req_cfg *rc = ap_get_module_config(r->request_config, &atinclusion_module);
	loginfo(r, "storeatinclusions : %s", atinclusions);
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

static void includeContents(Ctx* ctx, const char* uri) {
	request_rec *rr, *r = ctx->r;
	apr_status_t rrv;
	loginfo(ctx->r, "includeContents");
	
	if (uri == NULL) {
		return; // TODO : error code
	}
	
	loginfo(r, "attempting to run create request with this uri : %s", uri);
	rr = ap_sub_req_lookup_uri(uri, r,  NULL);
	if (rr== NULL || rr->status != HTTP_OK) {
		logerror(r, "MOD_ATINCLUSION : could not include %s (status : %i)", uri, rr->status);
		return;
	}
	loginfo(r, "running subr : %s", uri);
	rrv = ap_run_sub_req(rr);
	if (rrv) {
		logerror(r, "MOD_ATINCLUSION : could not run the request for %s (code : %i)", uri, rrv);
		return;
	}
	ap_destroy_sub_req(rr);
}

static apr_status_t atinclusion_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	apr_bucket* b;
	request_rec *r = f->r;
	char* buf;
	apr_size_t bytes;
	htmlParserCtxtPtr parser;
	Req_cfg *rc;
	Ctx* ctx;
	long length_read;
	// if non-(x)html document, we abort
	loginfo(r, "entering in atinclusion_filter");
	if(!r->content_type || (strncasecmp(r->content_type, "text/html", 9) &&
	    strncasecmp(r->content_type, "application/xhtml+xml", 21))){
		loginfo(r, "Non-HTML File, do not treat it : %s", r->filename);
		return ap_pass_brigade(f->next, bb);
	}
	buf = 0 ;
	bytes = 0 ;
	parser = NULL;
	rc = NULL;
	if(r->main)
		rc = set_config(r);
	else {
		rc = ap_get_module_config(r->request_config, &atinclusion_module );
	}
	if(rc == NULL){
		loginfo(r, "MOD_ATINCLUSION : rc is null, abort");
		return ap_pass_brigade(f->next, bb);
	}
	ctx = rc->ctx;
	ctx->f = f;
	
	loginfo(r, "create parser");
	parser = htmlCreatePushParserCtxt(&sax, rc->ctx, NULL, 0, NULL, XML_CHAR_ENCODING_NONE);

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
	apr_table_unset(r->headers_out, "Content-Length") ;
	ctx->buf = NULL;
	for (b = APR_BRIGADE_FIRST(bb) ;
	     b != APR_BRIGADE_SENTINEL(bb) ;
	     b = APR_BUCKET_NEXT(b) ) {
		
			// inspired from mod_proxy_html : 
		if ( APR_BUCKET_IS_METADATA(b) ) {
			if ( APR_BUCKET_IS_EOS(b) ) {
				loginfo(r, "EOS");
				break;
			} else if ( APR_BUCKET_IS_FLUSH(b) ) {
				loginfo(r, "FLUSH");
				/* 
				 * pass on flush, except at start where it would cause
				 * headers to be sent before doc sniffing
				 */
				if(ctx->buf != NULL)
					ap_fflush(f->next, ctx->bb) ;
			}
		} 
		else if ( apr_bucket_read(b, (const char**)&buf, &bytes, APR_BLOCK_READ)
			== APR_SUCCESS ) {
			ctx->buf = (char*)buf;
			length_read = ctx->length_read;
			loginfo(r,"parsing : %s", buf);
			htmlParseChunk(parser, buf, bytes, 0);
			loginfo(r,"parsed");
			printbucket(ctx,  strlen(ctx->buf));
			ctx->length_read = length_read + bytes;
			
		}
		else{
			logerror(r, "Error in bucket read");
			continue;
		}
		loginfo(r, "loop");
	}
	htmlParseChunk(parser, buf, 0, 1);
	apr_brigade_cleanup(bb);
	loginfo(r, "retuning : %s", r->uri);	
	//replaceContents(ctx);
	// if this is the main request, we create the EOS bucket
	if(! r->main){
		APR_BRIGADE_INSERT_TAIL(ctx->bb,
			apr_bucket_eos_create(ctx->bb->bucket_alloc));
	}
	return ap_pass_brigade(f->next, ctx->bb) ;
	
}

static void atinclusion_filter_insert(request_rec *r)
{
	ap_add_output_filter("ATINSERT", NULL, r, r->connection);
}

static void register_hooks(apr_pool_t* pool)
{
	static const char* aszSucc[] = {  NULL };
	ap_hook_post_read_request(remove_atinclusions,NULL,NULL,APR_HOOK_FIRST );
	ap_register_output_filter_protocol("ATINSERT", atinclusion_filter,
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



