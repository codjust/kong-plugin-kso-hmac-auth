local utils = require "kong.tools.utils"

local SCHEMA = {
    primary_key = {"id"},
    table = "kso_hmacauth_credentials",
    cache_key = {"accesskey"},
    fields = {
        id = {type = "id", dao_insert_value = true},
        created_at = {type = "timestamp", immutable = true, dao_insert_value = true},
        consumer_id = {type = "id", required = true, foreign = "consumers:id"},
        accesskey = {type = "string", required = true, unique = true},
        secretkey = {type = "string", default = utils.random_string}
    },
}

return {kso_hmacauth_credentials = SCHEMA}