require 'omniauth-oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class PrivatbankUa < OmniAuth::Strategies::OAuth2
      class NoCustomerError < StandardError; end
      option :name, 'privatbank-ua'

      OAUTH_DOMAIN = 'https://bankid.org.ua'
      DATA_DOMAIN = 'https://biprocessing.org.ua'

      option :client_options, {
        site: OAUTH_DOMAIN,
        authorize_url: '/DataAccessService/das/authorize',
        token_url: '/DataAccessService/oauth/token',
        token_method: :get
      }

      option :data_site, DATA_DOMAIN

      uid { raw_info['inn'] }

      info do
        {
          :inn => raw_info['inn'],
          :first_name => raw_info['firstName'],
          :last_name => raw_info['lastName'],
          :middle_name => raw_info['middleName'],
          :email => raw_info['email'],
          :phone => raw_info['phone']
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def raw_info
        @raw_info ||= customer_data
      end

      def callback_url
        full_host + script_name + callback_path # + query_string
      end

      protected

      def build_access_token
        verifier = request.params['code']
        calculated_secret = Digest::SHA1.hexdigest "#{options.client_id}#{options.client_secret}#{verifier}"
        client = ::OAuth2::Client.new(options.client_id, calculated_secret, deep_symbolize(options.client_options))
        client.auth_code.get_token(verifier,
          {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)),
          deep_symbolize({header_format: "Bearer %s, Id #{options.client_id}"}))
      end

      private

      def customer_data
        data = request_customer_data
        if data['state'] == 'ok'
          person = data['customer']
          if person['type'] == 'physical'
            decrypt_customer_data(person)
          end
          person
        else
          raise NoCustomerError.new(data.to_s)
        end
      end

      def request_customer_data
        access_token.post("#{options.data_site}/ResourceService/checked/data",
          {
            headers: {
              'Content-Type' => "application/json",
              'Accept' => "application/json"
            },
            body: customer_data_post_params.to_json
          }
        ).parsed
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def decrypt_customer_data(person)
        if person['signature'].present?
          fields = ['inn', 'firstName', 'middleName', 'lastName', 'phone', 'email']
          fields.each do |field_name|
            begin
              person[field_name] = decrypt(person[field_name])
            rescue Exception => e
              OmniAuth.config.logger.error("#{self.class} could not decrypt field: #{field_name}, because: #{e.message}")
            end
          end
        end
      end

      def decrypt(field_value)
        private_key.private_decrypt(Base64::decode64(field_value))
      end

      def private_key
        @private_key ||= OpenSSL::PKey::RSA.new(File.read(options.private_key_path))
      end

      def customer_data_post_params
        {
          "type" => "physical",
          "fields" => [
            "firstName",
            "middleName",
            "lastName",
            "phone",
            "inn",
            "clId",
            "clIdText",
            "birthDay",
            "email",
            "sex",
            "resident",
            "dateModification"
          ]
        }
      end
    end

    class PrivatbankUaSandbox < OmniAuth::Strategies::PrivatbankUa
      #for some reason in development we get ssl verification errors
      require 'openssl'
      OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
      # for testing against their test servers,
      # to test data decryption make sure you have the PrivatBank public/secret keys from  production
      SANDBOX_OAUTH_DOMAIN = 'https://bankid.privatbank.ua'
      SANDBOX_DATA_DOMAIN =  'https://bankid.privatbank.ua'
      default_options[:client_options][:site] = SANDBOX_OAUTH_DOMAIN
      default_options[:data_site] = SANDBOX_DATA_DOMAIN
    end
  end
end

OmniAuth.config.add_camelization "privatbank-ua", "PrivatbankUa"
