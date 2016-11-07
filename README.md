# OmniAuth privatbank.ua

## Using This Strategy

First start by adding this gem to your Gemfile:

```ruby
gem 'omniauth-privatbank-ua'
```

Next, tell OmniAuth about this provider. For a Rails app, your `config/initializers/omniauth.rb` file should look like this:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  if Rails.env.production?
    provider :'privatbank-ua', ENV['ua_privatbank_client_id'], ENV['ua_privatbank_client_secret'],
      private_key_path: ENV['ua_privatbank_client_private_key_path']
  else
    #for some reason in development we get ssl verification errors
    require 'openssl'
    OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
    provider OmniAuth::Strategies::PrivatbankUaSandbox, ENV['ua_privatbank_client_id'], ENV['ua_privatbank_client_secret'],
      private_key_path: ENV['ua_privatbank_client_private_key_path']
  end
end
```

