require 'sinatra'
require 'sinatra/reloader'
require 'sinatra/config_file'
require 'uri'
require 'logger'
require 'moneta'
require 'securerandom'

class AuthorizationServer < Sinatra::Base
  # config file
  register Sinatra::ConfigFile
  config_file './config.yaml'

  # auto reload
  register Sinatra::Reloader

  # sinatra settings
  configure :production, :development do
    set :views, settings.root + '/views/as'
    set :cache, Moneta.new(:File, dir: 'tmp')
    enable :logging
  end
  logger = Logger.new(STDOUT)

  # Struct
  AuthorizationRequest = Struct.new(:query, :scope, :user)

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
    SecureRandom.hex(8)
  end

  def generate_code
    SecureRandom.hex(10)
  end

  def error_response(uri_str, error_msg)
    uri = URI.parse(uri_str)
    uri.query = "error=#{error_msg}"
    uri
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
          redirect error_response(params['redirect_uri'], "invalid_scope")
        else
          request_id = generate_request_id
          settings.cache[request_id] = request.query_string
          erb :approve, :locals => {:client => client, :scope => requested_scope, :request_id => request_id}
        end
      end
    end
  end

  get '/approve' do
    redirect '/'
  end

  post '/approve' do
    request_id = params['request_id']
    query = Rack::Utils.parse_query(settings.cache.delete(request_id))

    unless query
      return erb :error, :locals => {:error => 'No matching authorization request'}
    end

    unless params['approve']
      redirect error_response(query['redirect_uri'], "access_denied")
    end

    case params['response_type']
    when 'code'
      code = generate_code
      user = params['user']
      request_scope = params.select {|k,v| k.start_with?('scope_')}.transform_keys{|k| k.sub(/^scope_/, '')}.keys
      client = get_client(query['client_id'])
      client_scope = parse_scope(client['scope'])

      unless valid_scope(request_scope, client_scope)
        redirect error_response(query['redirect_uri'], "invalid_scope")
      end

      settings.cache[code] = AuthorizationRequest.new(query, request_scope, user)
      uri = URI.parse(query['redirect_uri'])
      uri.query_string = "code=#{code}&state=#{query['state']}"
      redirect uri
    else
      redirect error_response(query['redirect_uri'], "unsupported_response_type")
    end

    redirect '/'
  end
end
