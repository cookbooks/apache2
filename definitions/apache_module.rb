define :apache_module, :enable => true do
  include_recipe "apache2"
  
  if params[:enable]
    execute "a2enmod #{params[:name]}" do
      command "/usr/sbin/a2enmod #{params[:name]}"
      notifies :restart, resources(:service => "apache2")
      not_if do File.symlink?("#{node[:apache][:dir]}/mods-enabled/#{params[:name]}.load") end
    end    
  else
    execute "a2dismod #{params[:name]}" do
      command "/usr/sbin/a2dismod #{params[:name]}"
      notifies :restart, resources(:service => "apache2")
      only_if do File.symlink?("#{node[:apache][:dir]}/mods-enabled/#{params[:name]}.load") end
    end
  end
end
