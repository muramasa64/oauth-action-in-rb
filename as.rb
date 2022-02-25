require 'sinatra'
require 'sinatra/reloader'

Client = Struct.new(:client_id, :client_secret, :redirect_uris, :scope)
AuthServer = Struct.new(:authorization_endpoint, :token_endpoint)

clients = [Client.new("oauth-client-1", "oauth-client-secret-1", ["http://localhost:4568/callback"], "foo bar")]
auth_server = AuthServer.new("http://localhost:4567/authorize", "http://localhost:4567/token")

get '/' do
    erb :index, :locals => {:clients => clients, :auth_server => auth_server}
end
