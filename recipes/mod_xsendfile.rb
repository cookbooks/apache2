require_recipe "apache2"

remote_directory "/usr/local/build/mod_xsendfile" do
  source "mod_xsendfile"
end

execute "build and install mod_xsendfile" do
  command "cd /usr/local/build/mod_xsendfile && apxs2 -ci mod_xsendfile.c"
  not_if { File.exists?("/usr/lib/apache2/modules/mod_xsendfile.so") }
end

template "/etc/apache2/mods-available/xsendfile.load" do
  source 'xsendfile.load.erb'
end

apache_module "xsendfile"