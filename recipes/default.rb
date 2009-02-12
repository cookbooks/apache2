package "apache2" do
  case node[:platform]
  when "centos","redhat","fedora","suse"
    name "httpd"
  when "debian","ubuntu"
    name "apache2"
  end
  action :install
end

service "apache2" do
  case node[:platform]
  when "centos","redhat","fedora","suse"
    name "httpd"
  when "debian","ubuntu"
    name "apache2"
  end
  supports :restart => true, :reload => true
  action :enable
end

if platform?("centos", "redhat", "fedora", "suse")
  directory node[:apache][:log_dir] do
    mode 0755
    action :create
  end
  
  remote_file "/usr/local/bin/apache2_module_conf_generate.pl" do
    source "apache2_module_conf_generate.pl"
    mode 0755
    owner "root"
    group "root"
  end

  %w{sites-available sites-enabled mods-available mods-enabled}.each do |dir|
    directory "#{node[:apache][:dir]}/#{dir}" do
      mode 0755
      owner "root"
      group "root"
      action :create
    end
  end
    
  execute "generate-module-list" do
    command "/usr/local/bin/apache2_module_conf_generate.pl /usr/#{node[:architecture]}/httpd/modules /etc/httpd/mods-available"  
    action :run
  end
  
  %w{a2ensite a2dissite s2enmod s2dismod}.each do |modscript|
    template "/usr/sbin/#{modscript}" do
      source "#{modscript}.erb"
      mode 0755
      owner "root"
      group "root"
    end  
  end
end

directory "#{node[:apache][:dir]}/ssl" do
  action :create
  mode 0755
  owner "root"
  group "root"
end

template "apache2.conf" do
  case node[:platform]
  when "centos","redhat","fedora"
    path "#{node[:apache][:dir]}/conf/httpd.conf"
  when "debian","ubuntu"
    path "#{node[:apache][:dir]}/apache2.conf"
  end
  source "apache2.conf.erb"
  owner "root"
  group "root"
  mode 0644
end

template "#{node[:apache][:dir]}/ports.conf" do
  source "ports.conf.erb"
  group "root"
  owner "root"
  variables :apache_listen_ports => node[:apache][:listen_ports]
  mode 0644
end

template "#{node[:apache][:dir]}/sites-available/default" do
  source "default-site.erb"
  owner "root"
  group "root"
  mode 0644
  notifies :restart, resources(:service => "apache2")
end


template "#{node[:apache][:dir]}/mods-available/deflate.conf" do
  source "deflate.conf.erb"
  owner "root"
  group "root"
  mode 0644
  variables(:mime_types => node[:apache][:deflate][:mime_types].join(" "))
  notifies :reload, resources(:service => "apache2")
end

%w(headers expires).each do |mod|
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
include_recipe "apache2::mod_deflate"
include_recipe "apache2::mod_expires"
include_recipe "apache2::mod_headers"
include_recipe "apache2::mod_log_config" if platform?("centos", "redhat", "suse")

service "apache2" do
  action :start
end
