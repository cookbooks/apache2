define :add_htpasswd_users do
  params[:users].each do |user, pass|
    execute "htpasswd add #{user}" do
      command "/usr/bin/htpasswd -b #{params[:name]} #{user} #{pass}"
    end
  end
end