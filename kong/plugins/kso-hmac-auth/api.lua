local crud = require "kong.api.crud_helpers"

return{
  ["/consumers/:username_or_id/kso-hmac-auth/"] = {
    before = function(self, dao_factory, helpers)
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
      self.params.consumer_id = self.consumer.id
    end,

    GET = function(self, dao_factory)
      crud.paginated_set(self, dao_factory.kso_hmacauth_credentials)
    end,

    PUT = function(self, dao_factory)
     crud.put(self.params, dao_factory.kso_hmacauth_credentials)
    end,

    POST = function(self, dao_factory)
     crud.post(self.params, dao_factory.kso_hmacauth_credentials)
    end
  },

  ["/consumers/:username_or_id/kso-hmac-auth/:kso_hmac_accesskey_or_id"]  = {
    before = function(self, dao_factory, helpers)
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
      self.params.consumer_id = self.consumer.id

      local credentials, err = crud.find_by_id_or_field(
        dao_factory.kso_hmacauth_credentials,
        { consumer_id = self.params.consumer_id },
        ngx.unescape_uri(self.params.kso_hmac_accesskey_or_id),
        "accesskey"
      )

      if err then
        return helpers.yield_error(err)
      elseif next(credentials) == nil then
        return helpers.responses.send_HTTP_NOT_FOUND()
      end
      self.params.kso_hmac_accesskey_or_id = nil

      self.kso_hmacauth_credentials = credentials[1]
    end,

    GET = function(self, dao_factory, helpers)
      return helpers.responses.send_HTTP_OK(self.kso_hmacauth_credentials)
    end,

    PATCH = function(self, dao_factory)
      crud.patch(self.params, dao_factory.kso_hmacauth_credentials, self.kso_hmacauth_credentials)
    end,

    DELETE = function(self, dao_factory)
      crud.delete(self.kso_hmacauth_credentials, dao_factory.kso_hmacauth_credentials)
    end
  },
  ["/kso-hmac-auths/"] = {
    GET = function(self, dao_factory)
      crud.paginated_set(self, dao_factory.kso_hmacauth_credentials)
    end
  },
  ["/kso-hmac-auths/:kso_hmac_accesskey_or_id/consumer"] = {
    before = function(self, dao_factory, helpers)
      local credentials, err = crud.find_by_id_or_field(
        dao_factory.kso_hmacauth_credentials,
        {},
        ngx.unescape_uri(self.params.kso_hmac_accesskey_or_id),
        "accesskey"
      )

      if err then
        return helpers.yield_error(err)
      elseif next(credentials) == nil then
        return helpers.responses.send_HTTP_NOT_FOUND()
      end

      self.params.kso_hmac_accesskey_or_id = nil
      self.params.username_or_id = credentials[1].consumer_id
      crud.find_consumer_by_username_or_id(self, dao_factory, helpers)
    end,

    GET = function(self, dao_factory,helpers)
      return helpers.responses.send_HTTP_OK(self.consumer)
    end
  }
}
