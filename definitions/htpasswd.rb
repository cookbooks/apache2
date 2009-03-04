define :htpasswd_file, :entries => {"default" => "04j9j02kv"} do
  template params[:name] do
    owner "www-data"
    mode 0750
    source "htpasswd.erb"
    variables(:entries => params[:entries])
  end
end