require 'sinatra/base'
require 'weary/request'
require 'weary/middleware'

module BlogHu2Tumblr
  class Authentication < Sinatra::Base
    HOST = "http://www.tumblr.com/oauth"

    enable :sessions
    set :credential_path, nil

    get '/' do
      response = request_token.perform
      if response.success?
        result = Rack::Utils.parse_query(response.body)
        logger.info(request.host)
        session[:request_token_secret] = result["oauth_token_secret"]
        redirect to("#{HOST}/authorize?oauth_token=#{result['oauth_token']}")
      else
        status response.status
        erb response.body
      end
    end

    get "/auth" do
      halt 401, erb(:error) if params.empty?
      token = params["oauth_token"]
      verifier = params["oauth_verifier"]
      response = access_token(token, session[:request_token_secret], verifier).perform
      if response.success?
        require 'tumblr/credentials'
        result = Rack::Utils.parse_query(response.body)
        credentials = Tumblr::Credentials.new(settings.credential_path)
        credentials.write session[:consumer_key],
                          session[:consumer_secret],
                          result["oauth_token"],
                          result["oauth_token_secret"]
        @credential_path = credentials.path
        status response.status
        erb :success
      else
        status response.status
        erb response.body
      end
    end

    private

    def consumer_key
      ENV.fetch('CONSUMER_KEY')
    end

    def consumer_secret
      ENV.fetch('CONSUMER_SECRET')
    end

    def request_token
      Weary::Request.new "#{HOST}/request_token", :POST do |req|
        req.params oauth_callback: url("/auth")
        req.use Weary::Middleware::OAuth, consumer_key: consumer_key,
                                          consumer_secret: consumer_secret
      end
    end

    def access_token(token, token_secret, verifier)
      Weary::Request.new "#{HOST}/access_token", :POST do |req|
        req.use Weary::Middleware::OAuth, token: token,
                                          token_secret: token_secret,
                                          verifier: verifier,
                                          consumer_key: consumer_key,
                                          consumer_secret: consumer_secret
      end
    end

  end
end
