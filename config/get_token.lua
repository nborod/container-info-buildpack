local cjson = require 'cjson'
local adobe = require 'adobe_utils'
local redis = require 'resty.redis'
local red = redis:new()

local function store_token(access_token, value, expires_in)
  adobe.connect_redis(red)
  local key = ngx.hmac_sha1(ngx.var.hash_key, access_token)
  res, err = red:set(key, value)
  if not res then
    adobe.log("Failed to set token "..access_token)
    adobe.log(err)
  else
    exp, err = red:expire(key, expires_in)
    if not exp then
      adobe.log("Failed to associate expiry time to key "..key)
      adobe.log(err)
    end
  end
end

local function get_token(access_token)
  local result = ngx.null
  adobe.connect_redis(red)
  local key = ngx.hmac_sha1(ngx.var.hash_key, access_token)
  res, err = red:get(key)
  if not res then
    adobe.log("Failed to get token "..access_token)
    adobe.log(err)
  else
    result = res
  end

  return result
end

local function delete_token(access_token)
  adobe.connect_redis(red)
  local key = ngx.hmac_sha1(ngx.var.hash_key, access_token)
  res, err = red:del(key)
  if not res then
    adobe.log("Failed to delete key "..key.." either key not found or already expired.")
    adobe.log(err)
  end
end

function validate_token(params)
  local result = ngx.null
  local auth_code_required_params = {'token'}
  if adobe.required_params_present(auth_code_required_params, params) and string.len(params['token']) >= 1 then
    local res = ngx.location.capture("/_oauth/check_token", { method = ngx.HTTP_POST, body = "token="..params.token})
    if res.status ~= 200 then
      adobe.log("HTTP Status : "..res.status)
      ngx.header.content_type = "application/json; charset=utf-8"
      adobe.log(res.body)
    else
      token = cjson.decode(res.body)
      if token.error == "invalid_token" then
        adobe.log(token.error.." : "..token.error_description)
        adobe.log(res.body)
        return token.error
      elseif token.grant_type == "client_credentials" then
          result = res.body
      else
        adobe.log("Token doesn't exists on oauth server")
        adobe.log(res.body)
      end
    end
  else
    adobe.log("NOPE")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  return result
end

function generate_token(params)
  local auth_code_required_params = {'client_id', 'client_secret', 'grant_type', 'response_type'}
  local auth_code_header_required_params = {'grant_type', 'response_type'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}

  if (adobe.required_params_present(auth_code_required_params, params) or adobe.required_params_present(auth_code_header_required_params, params)) and params['grant_type'] == 'client_credentials' then

    if params.client_id ~= nil and params.client_secret ~= nil then
      local authorization = ngx.encode_base64(params.client_id..":"..params.client_secret)
      ngx.req.set_header("Authorization", "Basic "..authorization)
    end

    local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, body = "grant_type="..params.grant_type.."&response_type="..params.response_type})

    if res.status ~= 200 then
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      token = cjson.decode(res.body)
      access_token = token.access_token
      store_token(access_token, res.body, token.expires_in)
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.header["X-Adobe-Token"] = access_token
      ngx.print(res.body)
    end

  elseif adobe.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token' then
    local authorization = ngx.encode_base64(params.client_id..":"..params.client_secret)
    ngx.req.set_header("Authorization", "Basic "..authorization)
    local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, body = "grant_type="..params.grant_type.."&refresh_token="..params.refresh_token})
    if res.status ~= 200 then
      ngx.status = res.status
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.print(res.body)
      ngx.exit(ngx.HTTP_OK)
    else
      token = cjson.decode(res.body)
      access_token = token.access_token
      expires_in = token.expires_in
      refresh_token = token.refresh_token
      store_token(access_token, res.body, token.expires_in)
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.header["X-Adobe-Token"] = access_token
      ngx.print(res.body)
    end
  else
    adobe.log("NOPE")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

end

local params = adobe.get_params(nil, ngx.req.get_method())
local headers = ngx.req.get_headers()
if headers["X-Adobe-Token"] ~= nil then
  local access_token = headers["X-Adobe-Token"]
  local response = get_token(access_token)
  if response == ngx.null then
    adobe.log("Token "..access_token.." not found.")
    local s = generate_token(params)
  else
    adobe.log("Token exists in Redis and now going to validate the same token")
    result = validate_token({token = access_token})
    if result == ngx.null then
      adobe.log("Token doesn't exists on Oauth, hence deleting the keys from redis if exists and generating new one")
      delete_token(access_token)
      local s = generate_token(params)
    else
      adobe.log("Validated the token successfully by all workflow")
      ngx.header.content_type = "application/json; charset=utf-8"
      ngx.header["X-Adobe-Token"] = access_token
      ngx.print(response)
      ngx.exit(ngx.HTTP_OK)
    end
  end
else
  local s = generate_token(params)
end