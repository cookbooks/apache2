package "libcurl3"

package "libcurl4-openssl-dev"

remote_file "/usr/lib/apache2/modules/mod_authn_yubikey.so" do
  source "mod_authn_yubikey.so"
end

file "/etc/apache2/conf.d/yubikey_owner" do
  action :create
  owner "www-data"
  mode 0640
end

file "/etc/apache2/conf.d/yubikey_tmp" do
  action :create
  owner "www-data"
  mode 0640
end

template "/etc/apache2/mods-available/authn_yubikey.load" do
  source 'authn_yubikey.load.erb'
end

apache_module "authn_yubikey"