package "libcurl3"
package "libcurl4-openssl-dev"

remote_directory "/usr/local/build/mod_authn_yubikey" do
  source "mod_authn_yubikey"
end

execute "build and install mod_authn_yubikey" do
  command "cd /usr/local/build/mod_authn_yubikey && apxs2 -DYK_PACKAGE=\\\"mod_authn_yubikey\\\" -DYK_PACKAGE_VERSION=\\\"0.1\\\" -I. -Wc -c -lcurl mod_authn_yubikey.c libykclient.c libykclient.slo mod_authn_yubikey.slo && apxs2 -i mod_authn_yubikey.la"
  not_if { File.exists?("/usr/lib/apache2/modules/mod_authn_yubikey.so") }
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