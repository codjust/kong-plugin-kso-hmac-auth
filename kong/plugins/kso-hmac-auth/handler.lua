-- Copyright (C) Kong Inc. author: codjust

local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.kso-hmac-auth.access"

local KsoHmacAuthHandler = BasePlugin:extend()

-- TODO: setting PRIORITY
KsoHmacAuthHandler.PRIORITY = 1001
KsoHmacAuthHandler.VERSION = "0.1.0"

function KsoHmacAuthHandler:new()
    KsoHmacAuthHandler.super.new(self, "kso-hmac-auth")
end

function KsoHmacAuthHandler:access(conf)
    KsoHmacAuthHandler.super.access(self)
    access.execute(conf)
end


return KsoHmacAuthHandler
