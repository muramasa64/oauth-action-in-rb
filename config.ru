#\ -p 4567
require 'bundler'
Bundler.require

require 'rack/cache/moneta'
use Rack::Cache,
  metastore: 'moneta://File?expires=true'
  entitystore: 'moneta://File?expires=true'

require './as'
run AuthorizationServer
