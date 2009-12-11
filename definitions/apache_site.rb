define :apache_site, :enable => true, :number => "000" do
  include_recipe "apache2"

  if params[:config_path]
    link "#{node[:apache][:dir]}/sites-available/#{params[:name]}" do
      to params[:config_path]
      only_if { File.exists?(params[:config_path]) }
    end
  end
  
  if params[:enable]
    execute "a2ensite #{params[:name]}" do
      command "/usr/sbin/a2ensite #{params[:name]}"
      notifies :restart, resources(:service => "apache2")
      only_if { File.exists?("#{node[:apache][:dir]}/sites-available/#{params[:name]}") }
      not_if do File.symlink?("#{node[:apache][:dir]}/sites-enabled/#{params[:name]}") end
    end
  else
    execute "a2dissite #{params[:name]}" do
      command "/usr/sbin/a2dissite #{params[:name]}"
      notifies :restart, resources(:service => "apache2")
      only_if do File.symlink?("#{node[:apache][:dir]}/sites-available/#{params[:name]}") || File.symlink?("#{node[:apache][:dir]}/sites-available/#{params[:number]}-#{params[:name]}") end
    end
  end
end
