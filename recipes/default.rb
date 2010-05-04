package "apache2" do
  name "apache2"
  #version node[:apache][:version]
end

service "apache2" do
  name "apache2"
  supports :restart => true, :reload => true
  action :enable
end

package "apache2-prefork-dev"

directory "#{node[:apache][:dir]}/ssl" do
  action :create
  mode 0755
  owner "root"
  group "root"
end

template "apache2.conf" do
  path "#{node[:apache][:dir]}/apache2.conf"
  source "apache2.conf.erb"
  owner "root"
  group "root"
  mode 0644
  notifies :reload, resources(:service => "apache2")
end

template "#{node[:apache][:dir]}/ports.conf" do
  source "ports.conf.erb"
  group "root"
  owner "root"
  variables :apache_listen_ports => node[:apache][:listen_ports]
  mode 0644
end

template "#{node[:apache][:dir]}/mods-available/deflate.conf" do
  source "deflate.conf.erb"
  owner "root"
  group "root"
  mode 0644
  variables(:mime_types => node[:apache][:deflate][:mime_types].join(" "))
  notifies :reload, resources(:service => "apache2")
end

%w(headers expires status info).each do |mod|
  template "#{node[:apache][:dir]}/mods-available/#{mod}.conf" do
    source "#{mod}.conf.erb"
    owner "root"
    group "root"
    mode 0644
    notifies :reload, resources(:service => "apache2")
  end
end

include_recipe "apache2::mod_status"
include_recipe "apache2::mod_alias"
include_recipe "apache2::mod_auth_basic"
include_recipe "apache2::mod_authn_file"
include_recipe "apache2::mod_authz_default"
include_recipe "apache2::mod_authz_groupfile"
include_recipe "apache2::mod_authz_host"
include_recipe "apache2::mod_authz_user"
include_recipe "apache2::mod_autoindex"
include_recipe "apache2::mod_dir"
include_recipe "apache2::mod_env"
include_recipe "apache2::mod_mime"
include_recipe "apache2::mod_negotiation"
include_recipe "apache2::mod_setenvif"
include_recipe "apache2::mod_expires"
include_recipe "apache2::mod_headers"
include_recipe "apache2::mod_ssl"
include_recipe "apache2::mod_proxy_http"

apache_site "default" do
  enable false
end

service "apache2" do
  action :start
end
