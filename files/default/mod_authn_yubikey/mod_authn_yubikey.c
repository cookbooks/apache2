/*
 * Copyright [2008] [Jens Frey]
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You
 * may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 */

/*
 * If you have any questions feel free to contact me
 * at jens.frey@coffeecrew.org
 * 
 */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "mod_auth.h"
#include "libykclient.h"
#include "ap_provider.h"
#include "apr_strings.h"
#include "apr_dbm.h"
#include "apr_time.h"
#include "http_core.h"
#include "http_request.h"

#define APR_WANT_STRFUNC        /* for strcasecmp */
#include "apr_want.h"


#define YUBIKEY_TOKEN_LENGTH 44
#define YUBIKEY_ID_LENGTH 12
#define LOG_PREFIX "[mod_authn_yubikey] "
#define MOD_AUTHN_YUBIKEY_NAME "mod_authn_yubikey"
#define MOD_AUTHN_YUBIKEY_VERSION "0.1"
#define ERROR_TEXT "<html> <head>" \
"<title>Error: SSL (https) connection required</title></head>" \
"<body style=\"background-color: black; color: #FF3700;\">" \
"<div style=\"border: 1px dashed #FFE268; height: 64px; padding: 2px;\">" \
"<img src=\"data:image/png;base64,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\" alt=\"Lock image\" width=\"64\" height=\"64\" style=\"float: left;\"/>" \
"<div style=\"border-left: 2px solid #FFE268; margin-left: 68px; padding-left:8px;\"><span style=\"font-size: 160%; font-weight: bold;\">This site is configured to require an SSL (https) connection.</span></div>" \
"</div>" \
"<p style=\"clear: both;\">" \
"You may want to try chaning http to https in your address bar.<br/>" \
"If you think this is an error, please contact the administrator." \
"</p></body></html>"

#define HDR_YK_AUTH_TYPE "X-Yubi-Auth-Type"
/* One factor (just token) */
#define YK_AUTH_TYPE_OF "OneFactor"
/* Two factor , password and token */
#define YK_AUTH_TYPE_TF "TwoFactor"

module AP_MODULE_DECLARE_DATA authn_yubikey_module;

/* Default values */
#define DEFAULT_TIMEOUT 43200 /* 12h */
#define DEFAULT_REQUIRE_SECURE (TRUE)
#define DEFAULT_EXTERNAL_ERROR_PAGE (FALSE)
#define DEFAULT_USER_DB "conf/ykUserDb"
#define DEFAULT_TMP_DB "conf/ykTmpDb"
#define UNSET -1

typedef struct
{
  /* This is the actual timeout after which the session finally expires,
   * there is NO recovery from this, so this timeout is not renewed everytime
   * a user makes a request
   */
  int timeoutSeconds;
  /* This flag requires the protected location to be accessed via an secure Url
   * this is especially useful if you use the two factor authentication,
   * since passwords would otherwise be sent in the clear.
   */
  int requireSecure;
  /* If any error happens, this will redirect you to the given error page,
   * or an internally generated error page will be shown. 
   * Use this is you want to customize the error page.
   */
  int externalErrorPage;
  /* This is the temporary filename authenticated user are saved in. 
   * This could possibly be done with an in memory version of s.th. similar
   * to the database
   */
  const char *tmpAuthDbFilename;
  /* This is the file where the actual user/password connection happens. So 
   * the module knows where it can find the file where the tokenId/username 
   * mapping happens.
   */
  const char *userAuthDbFilename;
  /* TODO: NYI 
   * This is required to be given if you want to use another authentication 
   * provider which supports the yubikey token, but not via yubicos site.
   */
  //const char *validationUrl;
} yubiauth_dir_cfg;

/* A helper */
static apr_datum_t string2datum(const char * toStore, request_rec *r)
{
    apr_datum_t dt;
    dt.dptr = apr_pstrdup(r->pool, (char*) toStore);
#ifndef NETSCAPE_DBM_COMPAT
    dt.dsize = strlen(dt.dptr);
#else
    dt.dsize = strlen(dt.dptr) + 1;
#endif

    return dt;
}

static void openDb(apr_dbm_t **userDbm, const char *dbFilename, request_rec *r)
{
    apr_status_t rv;
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Opening db ...");
    rv = apr_dbm_open(userDbm, dbFilename, APR_DBM_RWCREATE, APR_FPROT_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX "Error opening db %s ...", dbFilename);
    }
}

static void closeDb(apr_dbm_t *userDbm, request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Closing db ...");
    apr_dbm_close(userDbm);
}

/* User Key because the username is the key to the db */
static void deleteKeyFromDb(apr_dbm_t *userDbm, const char *userKey, request_rec *r)
{
    apr_datum_t key;
    apr_status_t rv;
    key = string2datum(userKey, r);
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                  LOG_PREFIX "Deleting key %s",
                  key.dptr);
    rv = apr_dbm_delete(userDbm, key);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      LOG_PREFIX "Could not delete key %s",
                      key.dptr);
    }
}

static apr_status_t setUserInDb(apr_dbm_t *userDbm,
                                const char *user,
                                const char *password,
                                request_rec *r)
{
    char *timeAuthenticated = NULL;
    char *dbToken = NULL; //This is used to store pw:date

    apr_datum_t key, value;
    apr_status_t rv;

    /* Built up some combination of token:time */
    timeAuthenticated = apr_psprintf(r->pool, "%" APR_TIME_T_FMT, (apr_time_t) (apr_time_sec(apr_time_now())));
    dbToken = apr_pstrcat(r->pool, password, ":", timeAuthenticated, NULL);

    /* store OTP:time combo with username as key in DB */
    key = string2datum(user, r);
    value = string2datum(dbToken, r);

    /* Pump user into db, store un, cookie value, creation date,
     * let this expire sometime
     */
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Writing key: %s and value: %s to db",
                  key.dptr, value.dptr);
    rv = apr_dbm_store(userDbm, key, value);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX "Error writing to db ... with key: %s and value: %s",
                      key.dptr, value.dptr);
    }
    /* Spit back, so we can decide wheather s.th. went wrong or not */
    return rv;
}

static int passwordExpired(const char *user,
                           apr_time_t lookedUpDate,
                           apr_time_t timeout,
                           request_rec *r)
{
    if ((apr_time_sec(apr_time_now())) > (lookedUpDate + timeout)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Session expired for user %s", user);
        return TRUE;
    }

    return FALSE;
}

static int isUserValid(const char *user, 
		       const char *password, 
		       yubiauth_dir_cfg *cfg, 
		       request_rec *r)
{

    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    apr_status_t status;
    char *file_password = NULL;
    char *yubiKeyId = NULL;
    char *userPassword = NULL;
    apr_size_t passwordLength = 0;
    char *realName = NULL;
    int userWasFound = FALSE;
    /* This is TRUE when we store a combination of yubikeyId:username:password,
     * we then have a two factor authentication.
     */
    int tokenHasPassword = FALSE;

    status = ap_pcfg_openfile(&f, r->pool, cfg->userAuthDbFilename);

    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      LOG_PREFIX "Could not open AuthYkUserFile file: %s", 
		      cfg->userAuthDbFilename);
        return FALSE;
    }

    /* Do length check of at least the password part,
     * to be a yubikey token, it has to have at least 44
     * characters from where the first 12 are the ID of the user.
     */
    if (strlen(password) < YUBIKEY_TOKEN_LENGTH) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		    LOG_PREFIX "The entered password cannot be a yubikey generated token");
      ap_cfg_closefile(f);
      return FALSE;
    }

    

    /* If the password is bigger then 44 characters, then we have an additional password
     * set into the field, since the produced token by the yubikey is 44 characters long
     */
    passwordLength = (apr_size_t) strlen(password) - YUBIKEY_TOKEN_LENGTH;
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
		  LOG_PREFIX "The length of the entered password is: %d", passwordLength);

    /* We have to distinct between a 44 character string which is the
     * toke output only and a longer string, which would contain a
     * password at its beginning
     */
    if (strlen(password) > YUBIKEY_TOKEN_LENGTH) {
	/* copy off the password part from the password string */
	userPassword = apr_pstrndup(r->pool, password, passwordLength);
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
		  LOG_PREFIX "The entered password is: %s", userPassword);
    }

    /* Now move the password pointer forward the number of calculatd characters for the userPassword,
     * we move the pointer beyond the last read character (not -1), to start reading the real stuff
     */
     yubiKeyId = apr_pstrndup(r->pool, &password[passwordLength], (apr_size_t) YUBIKEY_ID_LENGTH);
     ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
		  LOG_PREFIX "The calculated YubiKey ID is: %s", yubiKeyId);

    /* Find the TokenID/UN:PW solution in the file */
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *rpw, *w;
	char *unPw = NULL;

        /* Skip # or blank lines. */
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }

        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');
        
	/* The first 12 chars are the ID which must be available in this file
	 * else the user might be a yubikey user, but possibly a user we don't
	 * want.
	 */
        if (!strncmp(yubiKeyId, w, 12)) {
	  /* This would fetch the real username,
	   * after the ID could be located
	   */
	  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
			LOG_PREFIX "Could find the ID: %s", w);
	  /* remember, since we are working with the passwd
	   * utility, this realName is hashed
	   */
          realName = ap_getword(r->pool, &rpw, '\n');
          apr_table_set(r->headers_in, HDR_YK_AUTH_TYPE, YK_AUTH_TYPE_OF);
	  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
			LOG_PREFIX "The looked up realname is: %s", realName);
	  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
			LOG_PREFIX "The looked up userPassword is: %s", userPassword);
	  /* this results in username:password as it should be entered in the install dialog */
	  if (userPassword) {
	    unPw = apr_pstrcat(r->pool, user, ":", userPassword, NULL);
	    apr_table_set(r->headers_in, HDR_YK_AUTH_TYPE, YK_AUTH_TYPE_TF);
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
			LOG_PREFIX "The built un:pw combo is: %s", unPw);
	  }
	  /* If there is a password set, use the username:password combo,
	   * else just compare the username
	   */
	  status = apr_password_validate(userPassword?unPw:user, realName);

	  if (status == APR_SUCCESS) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
			    LOG_PREFIX "Could map ID %s to User: %s", w, user);
	    userWasFound = TRUE;
	    break;
	  }   
        }	
    }
    ap_cfg_closefile(f);

    return userWasFound;
}

/* This does some initial checking, like if we're running on a SSL line or not */
static int checkInitial(request_rec *r) 
{
  yubiauth_dir_cfg *cfg = ap_get_module_config(r->per_dir_config, &authn_yubikey_module);
  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                LOG_PREFIX "requireSecure: %d", cfg->requireSecure);
  /* If no securiy is wanted or scheme is already https */
    if (!cfg->requireSecure || !strncmp(ap_http_scheme(r), "https", 5)) {
      return OK;
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		  LOG_PREFIX "The server is configured to use HTTPS on URI: %s", r->uri);
    if(cfg->externalErrorPage == TRUE){
      /* We explicitly want that to be overridable */
      //return HTTP_BAD_REQUEST;
      return HTTP_NOT_ACCEPTABLE;
    } 
      
    /* Tell the user/admin what's going on instead of just showing BAD_REQUEST */
    ap_rputs(DOCTYPE_HTML_4_0T, r);
    ap_set_content_type(r, "text/html;");
    ap_rputs(ERROR_TEXT, r);
    ap_finalize_request_protocol(r);
    return HTTP_BAD_REQUEST;
}

static authn_status authn_check_otp(request_rec *r, const char *user,
                                    const char *password)
{
    apr_status_t rv;
    apr_dbm_t *userDbm = NULL;
    yubiauth_dir_cfg *cfg = ap_get_module_config(r->per_dir_config, &authn_yubikey_module);

    apr_datum_t key,dbUserRecord;
    key.dptr = NULL;
    dbUserRecord.dptr = NULL;

    char *lookedUpToken = NULL;
    char *lookedUpPassword = NULL; //This is the OTP token
    apr_size_t passwordLength = 0;
    apr_time_t lookedUpDate = 0;



    /* No username and no password is set */
    if (!*user || !*password)
        return AUTH_DENIED;

    /* Since the password field contains possibly a password and the OTP token, we 
     * have to break that up here
     */
    passwordLength = (apr_size_t) strlen(password) - YUBIKEY_TOKEN_LENGTH;

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                  LOG_PREFIX "Username is: %s and password is: %s", user, &password[passwordLength]);

    /* Now open the User DB and see if the user really is one of us.
     * for that we save the 12char token:username combo.
     * Ideally we can fill that with the htpasswd utility
     * NOTE: enter full password here
     */
    if (!isUserValid(user, password, cfg, r)) {
      return AUTH_DENIED;
    }

    openDb(&userDbm, cfg->tmpAuthDbFilename, r);

    key = string2datum(user, r);
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Fetching token (pw:time) for user %s from db ...", user);
    rv = apr_dbm_fetch(userDbm, key, &dbUserRecord);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOG_PREFIX "unable to fetch the user (%s) from the"
                      "Database, better abort here.", user);
        closeDb(userDbm, r);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (dbUserRecord.dptr != NULL) {

        /* it's separated pw:time here */
        const char *sep = ":";
        char *time;

        lookedUpToken = apr_pstrmemdup(r->pool, dbUserRecord.dptr, dbUserRecord.dsize);
        /* Break down the token into it's pw:time components */
        lookedUpPassword = apr_strtok(lookedUpToken, sep, &time);
        lookedUpDate = (apr_time_t) apr_atoi64(time);


        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                      LOG_PREFIX "We could extrace these values from the token:");
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                      LOG_PREFIX "The looked up token for the user: %s",
                      user);
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                      LOG_PREFIX "The looked up password: %s",
                      lookedUpPassword);
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                      LOG_PREFIX "The looked up time: %" APR_TIME_T_FMT,
                      lookedUpDate);
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r,
                      LOG_PREFIX "The looked up token: %s",
                      lookedUpToken);
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_DEBUG, 0, r, LOG_PREFIX "Fetched token (%s) ...", lookedUpToken);

    /* password has to be set, if the pw content is NULL or empty, we have 
     * catched that earlier ...
     */
    if (lookedUpPassword != NULL && !strcmp(lookedUpPassword, &password[passwordLength])) {
        /* The date expired */
        if (passwordExpired(user, lookedUpDate, cfg->timeoutSeconds, r)) {
            /* Delete user record */
            deleteKeyFromDb(userDbm, user, r);
            closeDb(userDbm, r);
            return AUTH_DENIED;
        }
        else {
            closeDb(userDbm, r);
            return AUTH_GRANTED;
        }
    }
    else {
        int authenticationSuccessful = 0;
        int ret = YUBIKEY_CLIENT_BAD_OTP;
        /* We could not lookup the password, verify the sent password */
        ret = yubikey_client_simple_request(&password[passwordLength], 1, 0, NULL);
            if (ret == YUBIKEY_CLIENT_OK) {
                authenticationSuccessful = 1;
            } else {
	      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              LOG_PREFIX "Authentication failed, reason: %s",
                              yubikey_client_strerror(ret));
                return AUTH_DENIED;
	    }

        /* We could successfully authenticate the user */
        if (authenticationSuccessful) {
            /* Try to write the user into the db */
            if (setUserInDb(userDbm, user, &password[passwordLength], r) 
		!= APR_SUCCESS) {
                /* Abort, we could not write the user into the db after
                 * authenticating him ...
                 */
                closeDb(userDbm, r);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* User could be written to the db*/
            closeDb(userDbm, r);
            return AUTH_GRANTED;
        }

        /* Could not authenticate successful */
        closeDb(userDbm, r);
        return AUTH_DENIED;
    }

    /* Something went wrong or we did not think about it, better deny */
    closeDb(userDbm, r);
    return AUTH_DENIED;
}

/* This provides a simple UI for accessing the key database 
 * used to grant access to users owning a yubikey or not.
 *
 * This is primarily a web version of htaccess.
 */
static int authn_yubikey_handler(request_rec *r)
{
    ap_configfile_t *f;
    char l[MAX_STRING_LEN];
    apr_status_t status;
    char *file_password = NULL;
    char *yubiKeyId = NULL;
    char *realName = NULL;
    apr_file_t *dbFormFile = NULL;
    yubiauth_dir_cfg *cfg = ap_get_module_config(r->per_dir_config, &authn_yubikey_module);

    if (strcmp(r->handler, "authn_yubikey")) {
        return DECLINED;
    }
    r->content_type = "text/html";

    /* Post back */
    if (r->method_number == M_POST) {
      const char *postbackContent = NULL;
      char *tmp = NULL;
      char buffer[1024];
      //Read the POST data sent from the client
      ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);

      if ( ap_should_client_block(r) == 1 ) {
              while ( ap_get_client_block(r, buffer, 1024) > 0 ) {
		postbackContent = apr_pstrcat(r->pool, buffer, tmp, NULL);
		//tmp = apr_pstrdup(r->pool, postbackContent);
	          }
      }
      else {
	        ap_rputs("No POST data available",r);
      }
      //We have the data now, now process it and save it into the db
      

      ap_set_content_type(r, "text/plain;");
      ap_rprintf(r, "Postback content: %s", postbackContent);

      return OK;
    }

    /* Serve content if it's a GET request */
    if (!r->header_only) {
      ap_rputs("<html><head><title>YubiAuth user management</title></head><body>", r);
      ap_rputs("<h1>Welcome to the YubiAuth user Mgmt.</h1><br>", r);
      ap_rputs("The following users could be found inside the database:<br>", r);
      //Open userDb file for looped output
      status = ap_pcfg_openfile(&f, r->pool, cfg->userAuthDbFilename);
      if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                      LOG_PREFIX "Could not open YubiAuthUserDb file: %s", 
		      cfg->userAuthDbFilename);
        return HTTP_INTERNAL_SERVER_ERROR;
      }
      ap_rputs("<table><thead><tr><th>TokenId</th><th>Real Name</th></tr></thead><tbody>\n", r);
      while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        const char *rpw, *w;

        /* Skip # or blank lines. */
        if ((l[0] == '#') || (!l[0])) {
	  continue;
        }

        rpw = l;
        w = ap_getword(r->pool, &rpw, ':');
	//yubiKeyId = apr_pstrndup(r->pool, password, (apr_size_t) 12);
        //realName = ap_getword(r->pool, &rpw, ':');
	ap_rputs("<tr>", r);
	ap_rprintf(r, "<td>%s</td>", w);
	ap_rprintf(r, "<td>%s</td>\n", rpw);
	ap_rputs("</tr>", r);
      }
      ap_cfg_closefile(f);
      ap_rputs("</tbody></table>", r);
      ap_rputs("<h1>Want to add a user?</h1>.", r);
      ap_rputs("<form name=\"addUser\" method=\"POST\" action=\"/authme\">", r);
      ap_rputs("<input type=\"text\" name=\"tokenId\">", r);
      ap_rputs("<input type=\"text\" name=\"realUser\">", r);
      ap_rputs("<input type=\"submit\" value=\"Add User\">", r);
      ap_rputs("</form>", r);
      ap_rputs("</body></html>", r);
    }

    //If we receive a POST to this location, we probably want to update the userdb
    //be sure to check if there is a user set and that this user is allowed to change information
    // inside the userdb, we cn authenticate the user with the OTP token here too.
    //We should make the administrative user configurable, by specifying the token which is allowed
    // access ...
    return OK;
}

static const authn_provider authn_yubikey_provider = {
    &authn_check_otp,
    NULL
};

static int init_mod_yk(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{ 
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 LOG_PREFIX "Version [" MOD_AUTHN_YUBIKEY_VERSION "] initialized");

    ap_add_version_component(pconf, MOD_AUTHN_YUBIKEY_NAME "/" MOD_AUTHN_YUBIKEY_VERSION);

    return OK;
}

static void authn_yubikey_register_hooks(apr_pool_t *p)
{
    //static const char *const aszSucc[] = { "mod_authz_user.c", NULL };

    
    //ap_hook_auth_checker(authz_check_yubi_user, NULL, aszSucc, APR_HOOK_MIDDLE);
    /* No content handler for this one */
    //ap_hook_handler(authn_yubikey_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_header_parser(checkInitial, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "yubikey", "0", &authn_yubikey_provider);
    ap_hook_post_config(init_mod_yk, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec authn_yubikey_cmds[] = {
    AP_INIT_TAKE1("AuthYubiKeyTmpFile", ap_set_file_slot,
                  (void*) APR_OFFSETOF(yubiauth_dir_cfg, tmpAuthDbFilename),
		  ACCESS_CONF, "The temporary filename for authenticated users"),
    AP_INIT_TAKE1("AuthYubiKeyUserFile", ap_set_file_slot,
                  (void*) APR_OFFSETOF(yubiauth_dir_cfg, userAuthDbFilename),
                  ACCESS_CONF, "The filename for allowed users"),
    AP_INIT_TAKE1("AuthYubiKeyTimeout", ap_set_int_slot,
                  (void*) APR_OFFSETOF(yubiauth_dir_cfg, timeoutSeconds),
                  ACCESS_CONF, "The timeout when users have to reauthenticate (Default 43200 seconds [12h])"),
    //AP_INIT_TAKE1("AuthYkValidationUrl", ap_set_int_slot,
    //              (void*) APR_OFFSETOF(yubiauth_dir_cfg, validationUrl),
    //              ACCESS_CONF, "The URL of the location where the key can be" \
    //		  "authenticated"),
    AP_INIT_FLAG("AuthYubiKeyExternalErrorPage", ap_set_flag_slot,
                  (void*) APR_OFFSETOF(yubiauth_dir_cfg, externalErrorPage),
                  ACCESS_CONF, "If SSL is required display internal error page, or display custom (406) error" \
		  "page (Default Off)"),
    AP_INIT_FLAG("AuthYubiKeyRequireSecure", ap_set_flag_slot,
                  (void*) APR_OFFSETOF(yubiauth_dir_cfg, requireSecure),
                  ACCESS_CONF|RSRC_CONF, 
		 "Whether or not a secure site is required to pass authentication (Default On)"),
    {NULL}
};

static void *create_yubiauth_dir_cfg(apr_pool_t *pool, char *x)
{
    yubiauth_dir_cfg *dir = apr_pcalloc(pool, sizeof (yubiauth_dir_cfg));
    /* Set defaults configuration here
     */
    dir->timeoutSeconds = UNSET;
    dir->requireSecure = UNSET;
    dir->externalErrorPage = UNSET;

    dir->tmpAuthDbFilename = NULL;
    dir->userAuthDbFilename = NULL;

    return dir;
}

static void *merge_yubiauth_dir_cfg(apr_pool_t *pool, void *BASE, void *ADD)
{
  yubiauth_dir_cfg *base = BASE;
  yubiauth_dir_cfg *add = ADD;
  yubiauth_dir_cfg *dir = apr_pcalloc(pool, sizeof (yubiauth_dir_cfg));

  /* merge */
  dir->timeoutSeconds = (add->timeoutSeconds == UNSET) ? base->timeoutSeconds : add->timeoutSeconds; 
  dir->requireSecure = (add->requireSecure == UNSET) ? base->requireSecure : add->requireSecure;
  dir->externalErrorPage = (add->externalErrorPage == UNSET) ? base->externalErrorPage : add->externalErrorPage;
  
  dir->userAuthDbFilename = (add->userAuthDbFilename == NULL) ? base->userAuthDbFilename : add->userAuthDbFilename;
  dir->tmpAuthDbFilename = (add->tmpAuthDbFilename == NULL) ? base->tmpAuthDbFilename : add->tmpAuthDbFilename;

  /* Set defaults configuration here
   */
  if (dir->timeoutSeconds == UNSET) {
    dir->timeoutSeconds = DEFAULT_TIMEOUT;
  }
  if (dir->requireSecure == UNSET) {
    dir->requireSecure = DEFAULT_REQUIRE_SECURE;
  }
  if (dir->externalErrorPage == UNSET) {
    dir->externalErrorPage = DEFAULT_EXTERNAL_ERROR_PAGE;
  }
  if (dir->userAuthDbFilename == NULL) {
    dir->userAuthDbFilename = ap_server_root_relative(pool, DEFAULT_USER_DB);
  }
  if (dir->tmpAuthDbFilename == NULL) {
    dir->tmpAuthDbFilename = ap_server_root_relative(pool, DEFAULT_TMP_DB);
  }
  return dir;
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA authn_yubikey_module = {
    STANDARD20_MODULE_STUFF,
    &create_yubiauth_dir_cfg,   /* create per-dir    config structures */
    &merge_yubiauth_dir_cfg,    /* merge  per-dir    config structures */
    NULL, /* create per-server config structures */
    NULL, /* merge  per-server config structures */
    authn_yubikey_cmds, /* table of config file commands       */
    authn_yubikey_register_hooks /* register hooks                      */
};

