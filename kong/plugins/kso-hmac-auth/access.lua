local utils = require "kong.tools.utils"
local singletons = require "kong.singletons"
local ck = require("resty.cookie")
local str = require("resty.string")
local constants = require "kong.constants"

local response = kong.response
local ngx_get_headers = kong.request.get_headers
local ngx_get_method = kong.request.get_method
local split = utils.split
local log = kong.log
local ngx_set_header = kong.response.set_header

local _M = {}

local AUTHORIZATION = "WPSVASDevToken"
local CLIENTTYPE_HEADER = "Client-Type"
local CONTENTMD5_HEADER = "Content-MD5"
local CONTENTTYPE_HEADER = "Content-Type"
local DATE_HEADER = "Date"
local SIGNATURE_NOT_VALID = "Kso HMAC signature cannot be verified"
local SIGNATURE_NOT_SAME = "Kso HMAC signature does not match"

local function retrieve_hmac_fields(headers)
    local hmac_params = {}
    local authorization_header = headers[AUTHORIZATION]
    if authorization_header then
        local wps_token = split(authorization_header, ":")
        if #wps_token ~= 4 then
            log.debug("WPSVASDevToken format error.")
            return nil, false
        end
        hmac_params.accesskey = wps_token[3]
        hmac_params.signature = wps_token[4]
    end

    return hmac_params, true
end

local function check_header_date(http_date)
    local time = ngx.parse_http_time(http_date)
    local interval_sec = 15 * 60 -- 15 min
    local now_time = ngx.time()
    if not string.match(http_date, "GMT$") then
        now_time = now_time + (8 * 60 * 60) -- GMT +8h
    end
    local left_t = now_time - interval_sec
    local right_t = now_time + interval_sec
    log.debug("http_date:", http_date, " time:", time, " now_time:", now_time, " left_t:", left_t, " right_t:", right_t)
    if time >= left_t and time <= right_t then
        return true
    end
    return false
end

local function validate_params(params, headers, conf)
    if not params.accesskey or not params.signature then
        return nil, "accesskey or signature missing"
    end

    local date = headers[DATE_HEADER]
    if not date then
        return nil, "header date missing"
    end

    if not check_header_date(date) then
        return nil, "header date is invalid."
    end

    local _, err = ngx.req.get_uri_args()
    if err == "truncated" then
        log.debug("ngx.req.get_uri_args error")
        return nil, "query args invalid"
    end

    if not headers[CLIENTTYPE_HEADER] then
        return nil, "header client type missing"
    end

    local content_md5 = headers[CONTENTMD5_HEADER]
    if conf.is_verify_content_md5 and content_md5 ~= "" then
        ngx.req.read_body()
        local data = ngx.req.get_body_data()
        if not data then
            return nil, "content-md5 is invalid."
        end
        local digest = ngx.md5(data)
        local s_content_md5 = ngx.encode_base64(digest)
        log.debug("s_content_md5: ", s_content_md5, " c_content_md5: ", content_md5)
        if s_content_md5 ~= content_md5 then
            return nil, "content-md5 not equal to server calculate value."
        end
    end

    return true
end

local function load_credential_into_memory(accesskey)
    local keys, err = singletons.dao.kso_hmacauth_credentials:find_all {accesskey = accesskey}
    if err then
        return nil, err
    end
    return keys[1]
end

local function load_credential(accesskey)
    local credential, err
    if accesskey then
        local credential_cache_key = singletons.dao.kso_hmacauth_credentials:cache_key(accesskey)
        credential, err = singletons.cache:get(credential_cache_key, nil, load_credential_into_memory, accesskey)
    end
    if err then
        return response.exit(501, err)
    end

    return credential
end

local function pairs_by_keys(t, f)
    local a = {}
    for n in pairs(t) do
        table.insert(a, n)
    end
    table.sort(a, f)
    local i = 0 -- iterator variable
    local iter = function()
        -- iterator function
        i = i + 1
        if a[i] == nil then
            return nil
        else
            return a[i], t[a[i]]
        end
    end
    return iter
end

local function get_wps_sid_from_cookie()
    local cookie, err = ck:new()
    if not cookie then
        log.err(err)
        return ""
    end
    local wps_sid, err = cookie:get("wps_sid")
    if not wps_sid then
        log.debug(err)
        return ""
    end
    return wps_sid
end

local function retrieve_kso_strtosign(hamc_params, headers)
    local strtosign = {}
    local method = string.upper(ngx_get_method())
    local content_md5 = ""
    local content_type
    local date = headers[DATE_HEADER]
    local uri_path = kong.request.get_path()
    local query_params = ""
    local client_type = string.lower(headers[CLIENTTYPE_HEADER])
    local wps_sid = ""

    content_md5 = headers[CONTENTMD5_HEADER]
    if not content_md5 then
        content_md5 = ""
    else
        content_md5 = string.lower(content_md5)
    end

    content_type = headers[CONTENTTYPE_HEADER]
    if not content_type then
        content_type = ""
    else
        content_type = string.lower(content_type)
    end

    local args, _ = ngx.req.get_uri_args()
    for key, value in pairs_by_keys(args) do
        if type(value) == "table" then
            for vkey, val in pairs(value) do
                query_params = query_params .. key .. "=" .. val
                query_params = query_params .. "&"
            end
            query_params = string.sub(query_params, 1, #query_params - 1)
        else
            query_params = query_params .. key .. "=" .. value
        end
        query_params = query_params .. "&"
    end
    query_params = string.sub(query_params, 1, #query_params - 1)
    log.debug("uri query params:", query_params)

    wps_sid = get_wps_sid_from_cookie()
    if not wps_sid then
        wps_sid = ""
    end

    table.insert(strtosign, method)
    table.insert(strtosign, "\n")
    table.insert(strtosign, content_md5)
    table.insert(strtosign, "\n")
    table.insert(strtosign, content_type)
    table.insert(strtosign, "\n")
    table.insert(strtosign, date)
    table.insert(strtosign, "\n")
    table.insert(strtosign, uri_path)
    table.insert(strtosign, "\n")
    table.insert(strtosign, query_params)
    table.insert(strtosign, "\n")
    table.insert(strtosign, hamc_params.accesskey)
    table.insert(strtosign, "\n")
    table.insert(strtosign, client_type)
    table.insert(strtosign, "\n")
    table.insert(strtosign, wps_sid)

    return table.concat(strtosign)
end

local function validate_signature(params, headers)
    local strtosign = retrieve_kso_strtosign(params, headers)
    log.debug("kso_hmac_auth strtosign: " .. strtosign)

    local digest = ngx.hmac_sha1(params.secretkey, strtosign)
    local server_signature = ngx.encode_base64(str.to_hex(digest))
    log.debug("kso_hmac_auth server_signature: " .. server_signature)
    log.debug("recv client signature: " .. params.signature)

    if server_signature == params.signature then
        return true
    end

    return false
end

local function load_consumer_into_memory(consumer_id, anonymous)
    local result, _ = singletons.db.consumers:select {id = consumer_id}
    return result
end

local function set_consumer(consumer, credential)
    ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    ngx.ctx.authenticated_consumer = consumer
    if credential then
        ngx.ctx.kso_authenticated_credential = credential
    end
end

local function do_authentication(conf)
    local headers = ngx_get_headers()
    local http_code = conf.code
    if not http_code then
        http_code = 401
    end
    -- exist header token?
    if not headers[AUTHORIZATION] then
        return false, {status = http_code}
    end

    local hmac_params, ok = retrieve_hmac_fields(headers)
    if not ok then
        return false, {status = http_code}
    end

    local ok, err = validate_params(hmac_params, headers, conf)
    if not ok then
        log.debug(err)
        return false, {status = http_code, message = SIGNATURE_NOT_VALID}
    end

    local credential = load_credential(hmac_params.accesskey)
    if not credential then
        log.debug("failed to retrieve kso credential for ", hmac_params.accesskey)
        return false, {status = http_code, message = SIGNATURE_NOT_VALID}
    end

    hmac_params.secretkey = credential.secretkey
    if not validate_signature(hmac_params, headers) then
        return false, {status = http_code, message = SIGNATURE_NOT_SAME}
    end

    -- Retrieve consumer
    local consumer_cache_key = singletons.db.consumers:cache_key(credential.consumer_id)
    local consumer, err =
        singletons.cache:get(consumer_cache_key, nil, load_consumer_into_memory, credential.consumer_id)
    if err then
        return response.exit(500, err)
    end

    set_consumer(consumer, credential)

    return true
end

function _M.execute(conf)
    if ngx.ctx.kso_authenticated_credential then
        log.debug("kso_authenticated_credential already auth ok.")
        return
    end
    local ok, err = do_authentication(conf)
    if not ok then
        log.debug("do_authentication auth failed, err: ", err)
        return response.exit(err.status, err.message)
    end
end

return _M
