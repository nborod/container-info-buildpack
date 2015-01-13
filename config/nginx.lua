local adobe = require 'adobe_utils'
local cjson = require 'cjson'

-- -*- mode: lua; -*-
-- Version:
-- Error Messages per service

service = {
 error_auth_failed = 'Authentication failed',
 error_auth_missing = 'Authentication parameters missing',
 auth_failed_headers = 'text/plain; charset=us-ascii',
 auth_missing_headers = 'text/plain; charset=us-ascii',
 error_no_match = 'No rule matched',
 no_match_headers = 'text/plain; charset=us-ascii',
 no_match_status = 404,
 auth_failed_status = 403,
 auth_missing_status = 403,
 oauth_authorization = 'Basic bmZzYXBpOm5mc2FwaTEyMyE=',
 nfs_authorization = 'Bearer c1e8f40b15d55a9d5190a69f8e9555bec03e89af',
 get_token_params = {
   grant_type = 'client_credentials',
   response_type = 'token'
 }
}

local auth_strat = "oauth"

--[[

  Mapping between url path to adobe methods. In here you must output the usage string encoded as a query_string param.
  Here there is an example of 2 resources (word, and sentence) and 3 methods. The complexity of this function depends
  on the level of control you want to apply. If you only want to report hits for any of your methods it would be as simple
  as this:

  function extract_usage(request)
    return "usage[hits]=1&"
  end

  In addition. You do not have to do this on LUA, you can do it straight from the nginx conf via the location. For instance:

  location ~ ^/v1/word {
                set $provider_key null;
                set $app_id null;
                set $app_key null;
                set $usage "usage[hits]=1&";

                access_by_lua_file /Users/solso/adobe/proxy/nginx_sentiment.lua;

                proxy_pass http://sentiment_backend;
                proxy_set_header  X-Real-IP  $remote_addr;
                proxy_set_header  Host  $host;
        }

        This is totally up to you. We prefer to keep the nginx conf as clean as possible. But you might already have declared
        the resources there, in this case, it's better to declare the $usage explicitly

]]--

-- matched_rules2 = ""

--[[
  Authorization logic
]]--

function get_access_token(params, service)
  if params["access_token"] == nil then -- TODO: check where the params come
    adobe.error_no_credentials(service)
  end
end


function authorize(auth_strat, params, service)
  local request_headers = ngx.req.get_headers()
  if(request_headers == nil or request_headers["Authorization"] == nil) then
    adobe.error_no_credentials(service)
  elseif(request_headers["Authorization"] ~= service.oauth_authorization) then
    adobe.error_authorization_failed(service)
  end

  if auth_strat == 'oauth' then
    return oauth(service)
  else
    -- TO DO authrep(params, service)
  end
end

function oauth(service)
    local res = ngx.location.capture("/oauth/token", { method = ngx.HTTP_POST, body = adobe.build_query(service.get_token_params)})
    if res.status ~= 200   then
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      adobe.error_authorization_failed(service)
    else
      local response = cjson.decode(res.body)
      get_access_token(response, service)
      return response
      -- ngx.print("Token : "..res.body.."\n")
    end
end

function call_service(query, params, adobe_token, authorization_header)
    if authorization_header ~= nil then
      ngx.req.set_header("Authorization", authorization_header)
    end
    local http_method = "HTTP_"..ngx.req.get_method()
    local res = ngx.location.capture("/_service"..query, { method = ngx[http_method], body = adobe.build_query(params)} )
    if res.status ~= 200   then
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      ngx.print(res.body)
      ngx.exit(ngx.status)
    else
      ngx.header.content_type = "application/json"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    end
end

-- ngx.say(headers.Authorization)
-- ngx.print(ngx.req.get_method())
-- ngx.exit(ngx.HTTP_OK)
-- local host = ngx.req.get_headers()["Host"]
local query = adobe.split(ngx.var.request, " ")[2]
local params = adobe.get_params(nil, ngx.req.get_method())
local service_api = adobe.split(query, "/")[2].."_authorization"
local auth_response = authorize(auth_strat, params, service)
call_service(query, params, auth_response.access_token, service[service_api])

-- END OF SCRIPT