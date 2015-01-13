-- adobe_utils.lua
local M = {} -- public interface

-- private
-- Logging Helpers
function M.show_table(t, ...)
   local indent = 0 --arg[1] or 0
   local indentStr=""
   for i = 1,indent do indentStr=indentStr.."  " end

   for k,v in pairs(t) do
     if type(v) == "table" then
        msg = indentStr .. M.show_table(v or '', indent+1)
     else
        msg = indentStr ..  k .. " => " .. v
     end
     M.log_message(msg)
   end
end

function M.log_message(str)
   ngx.log(0, str)
end

function M.newline()
   ngx.log(0,"  ---   ")
end

function M.log(content)
  if type(content) == "table" then
     M.log_message(M.show_table(content))
  else
     M.log_message(content)
  end
  M.newline()
end

-- End Logging Helpers

-- Table Helpers
function M.keys(t)
   local n=0
   local keyset = {}
   for k,v in pairs(t) do
      n=n+1
      keyset[n]=k
   end
   return keyset
end
-- End Table Helpers


function M.dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. M.dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function M.sha1_digest(s)
   local str = require "resty.string"
   return str.to_hex(ngx.sha1_bin(s))
end

-- returns true iif all elems of f_req are among actual's keys
function M.required_params_present(f_req, actual)
   local req = {}
   for k,v in pairs(actual) do
      req[k] = true
   end
   for i,v in ipairs(f_req) do
      if not req[v] then
         return false
      end
   end
   return true
end

function M.connect_redis(red)
   local ok, err = red:connect("127.0.0.1", 6379)
   if not ok then
      ngx.say("failed to connect: ", err)
      ngx.exit(ngx.HTTP_OK)
   end
   return ok, err
end

--[[
  String Methods
]]--

function M.split(str, delimiter)
  local result = { }
  local from = 1
  local delim_from, delim_to = string.find( str, delimiter, from )
  while delim_from do
    table.insert( result, string.sub( str, from , delim_from-1 ) )
    from = delim_to + 1
    delim_from, delim_to = string.find( str, delimiter, from )
  end
  table.insert( result, string.sub( str, from ) )
  return result
end

function M.first_values(a)
  r = {}
  for k,v in pairs(a) do
    if type(v) == "table" then
      r[k] = v[1]
    else
      r[k] = v
    end
  end
  return r
end

function M.set_or_inc(t, name, delta)
  return (t[name] or 0) + delta
end

function M.build_querystring(query)
  local qstr = ""

  for i,v in pairs(query) do
    qstr = qstr .. 'usage[' .. i .. ']' .. '=' .. v .. '&'
  end
  return string.sub(qstr, 0, #qstr-1)
end

---
-- Builds a query string from a table.
--
-- This is the inverse of <code>parse_query</code>.
-- @param query A dictionary table where <code>table['name']</code> =
-- <code>value</code>.
-- @return A query string (like <code>"name=value2&name=value2"</code>).
-----------------------------------------------------------------------------
function M.build_query(query)
  local qstr = ""

  for i,v in pairs(query) do
    qstr = qstr .. i .. '=' .. v .. '&'
  end
  return string.sub(qstr, 0, #qstr-1)
end

-- Error Codes,  errors and exist
function M.error_no_credentials(service)
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  M.log(ngx.req.get_headers())
  M.log(service.error_auth_missing)
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

function M.error_authorization_failed(service)
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  M.log(ngx.req.get_headers())
  M.log(service.error_auth_failed)
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

function M.error_no_match(service)
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  M.log(ngx.req.get_headers())
  M.log(service.error_no_match)
  ngx.print(service.error_no_match)
  ngx.exit(ngx.HTTP_OK)
end
function M.error(text)
   ngx.say(text)
   ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

function M.missing_args(text)
   ngx.say(text)
   ngx.exit(ngx.HTTP_OK)
end

-- Print the array and other useful methods

function M.print_r(arr, indentLevel)
    local str = ""
    local indentStr = "#"

    if(indentLevel == nil) then
        ngx.print(M.print_r(arr, 0))
        return
    end

    for i = 0, indentLevel do
        indentStr = indentStr.."\t"
    end

    for index,value in pairs(arr) do
        if type(value) == "table" then
            str = str..indentStr..index..": \n"..M.print_r(value, (indentLevel + 1))
        else
            str = str..indentStr..index..": "..value.."\n"
        end
    end
    return str
end

function M.add_trans(usage)
  local us = usage:split("&")
  local ret = ""
  for i,v in ipairs(us) do
    ret =  ret .. "transactions[0][usage]" .. string.sub(v, 6) .. "&"
  end
    return string.sub(ret, 1, -2)
end

function M.get_debug_value()
  local h = ngx.req.get_headers()
  if h["X-adobe-debug"] == '' then
    return true
  else
    return false
  end
end

function M.get_params(where, method)
  local params = {}
  if where == "headers" then
    params = ngx.req.get_headers()
  elseif method == "GET" then
    params = ngx.req.get_uri_args()
  else
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  end

  return M.first_values(params)
end

function M.extract_usage_service(request)

  local t = M.split(request," ")
  local method = t[1]
  local path = t[2]
  local found = false
  local usage_t =  {}
  local m = ""
  local matched_rules = {}
  local params = {}

  local args = M.get_params(nil, method)

  -- mapping rules go here, e.g
  local m =  ngx.re.match(path,[=[^/]=])
  if (m and method == "GET") then
     -- rule: / --
     table.insert(matched_rules, "/")

     usage_t["hits"] = M.set_or_inc(usage_t, "hits", 1)
     found = true
  end

  -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
  if found then
    matched_rules2 = table.concat(matched_rules, ", ")
    return M.build_querystring(usage_t)
  else
    return nil
  end
end


return M

-- -- Example usage:
-- local MM = require 'mymodule'
-- MM.bar()