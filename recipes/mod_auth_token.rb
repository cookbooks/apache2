require_recipe "apache2"

remote_directory "/usr/local/build/mod_auth_token" do
  source "mod_auth_token"
end

execute "build and install mod_auth_token" do
  command "cd /usr/local/build/mod_auth_token && apxs2 -ci mod_auth_token.c"
  not_if { File.exists?("/usr/lib/apache2/modules/mod_auth_token.so") }
end

template "/etc/apache2/mods-available/auth_token.load" do
  source 'auth_token.load.erb'
end

apache_module "auth_token"