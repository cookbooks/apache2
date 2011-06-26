#
# Cookbook Name:: apache2
# Recipe:: proxy_virtualhost
#
# Copyright 2011, Craig S. Cottingham
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

node[:apache][:proxy][:reverse].each do | pvh |
  
  proxy_name = pvh[:servername]
  conf_filename = "proxy-#{proxy_name.gsub('.', '_')}.conf"
  
  template "#{node[:apache][:dir]}/sites-available/#{conf_filename}" do
    source "proxy_virtualhost.conf.erb"
    owner "root"
    group "root"
    mode 0644
    variables(
      :proxy_name => proxy_name,
      :url_map => pvh[:url_map]
    )
    if ::File.exists?("#{node[:apache][:dir]}/sites-enabled/#{conf_filename}")
      notifies :reload, resources(:service => "apache2"), :delayed
    end
  end
  
  apache_site conf_filename do
    enable enable_setting
  end
  
end