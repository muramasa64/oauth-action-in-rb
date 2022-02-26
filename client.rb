require 'sinatra'
require 'sinatra/reloader'

# sinatra settings
set :views, settings.root + '/views/client'
set :port, settings.port = 4568

# data structure
Client = Struct.new(:client_id, :client_secret, :redirect_uris)

# local values
client = Client.new("", "", ["http://localhost:4568/callback"])
protected_resouce = "http://localhost:4569/resource"
state = nil
access_token = nil
scope = nil

# routing
get '/' do
  erb :index, :locals => {:access_token => access_token, :scope => scope}
end

get '/authorize' do
  # send the user to the authorization serer
end

get '/callback' do
  # parse the response from the authorization server and get a token
end

get '/fetch_resource' do
  # use the access token to call the resource server
end
