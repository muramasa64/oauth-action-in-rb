require 'sinatra'
require 'sinatra/reloader'
require 'sinatra/config_file'
require 'uri'
require 'logger'
require 'concurrent'

class AuthorizationServer < Sinatra::Base
    # config file
    register Sinatra::ConfigFile
    config_file './config.yaml'

    # auto reload
    register Sinatra::Reloader

    # sinatra settings
    configure :production, :development do
        set :views, settings.root + '/views/as'
        set :cache, Concurrent::Hash.new(0)
        enable :logging
    end
    logger = Logger.new(STDOUT)

    # functions
    def get_client(client_id)
        settings.clients.find {|c| c['client_id'] == client_id}
    end

    def valid_redirect_uri?(client, redirect_uri)
        return false unless redirect_uri
        client['redirect_uris'].include?(redirect_uri)
    end

    def valid_scope(requested_scope, client_scope)
        diff_scope = requested_scope - client_scope
        !(diff_scope.size > 0)
    end

    def parse_scope(scopes)
        return [] unless scopes
        scopes.split(' ')
    end

    def generate_request_id
        Random.urandom(8)
    end

    # routing
    get '/' do
        erb :index, :locals => {:clients => settings.clients, :auth_server => settings.auth_server}
    end

    get '/authorize' do
        client = get_client(params['client_id'])
        redirect_uri = params['redirect_uri'] ? params['redirect_uri'] : ''
        logger.debug client

        if !client
            logger.info "Unknown client: #{client}"
            erb :error, :locals => {:error => 'Unknown client'}
        else
            is_valid_redirect_uri = valid_redirect_uri?(client, redirect_uri)
            if !is_valid_redirect_uri
                logger.info "Mismatched redirect URI, expected #{client['redirect_uris']} got #{redirect_uri}"
                erb :error, :locals => {:error => 'Invalid redirect URI'}
            else
                requested_scope = parse_scope(params['scope'])
                client_scope = parse_scope(client['scope'])
                is_valid_scope = valid_scope(requested_scope, client_scope)
                unless is_valid_scope
                    logger.info "Invalid scope"
                    uri = URI.parse(params['redirect_uri'])
                    uri.query = "error=invalid_scope"
                    redirect uri
                else
                    request_id = generate_request_id
                    settings.cache[request_id] = request.query_string
                    erb :approve, :locals => {:client => client, :scope => requested_scope, :request_id => request_id}
                end
            end
        end
    end
end
