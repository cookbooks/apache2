apache Mash.new unless attribute?("apache")

# Where the various parts of apache are
case platform
when "redhat","centos","fedora","suse"
  apache[:dir]     = "/etc/httpd"
  apache[:log_dir] = "/var/log/httpd"
  apache[:user]    = "apache"
  apache[:binary]  = "/usr/sbin/httpd"
  apache[:icondir] = "/var/www/icons"
when "debian","ubuntu"
  apache[:dir]     = "/etc/apache2" 
  apache[:log_dir] = "/var/log/apache2"
  apache[:user]    = "www-data"
  apache[:binary]  = "/usr/sbin/apache2"
  apache[:icondir] = "/usr/share/apache2/icons"
else
  apache[:dir]     = "/etc/apache2" 
  apache[:log_dir] = "/var/log/apache2"
  apache[:user]    = "www-data"
  apache[:binary]  = "/usr/sbin/apache2"
  apache[:icondir] = "/usr/share/apache2/icons"
end

###
# These settings need the unless, since we want them to be tunable,
# and we don't want to override the tunings.
###

# General settings
apache[:listen_ports] = [ "80","443","444" ]#     unless apache.has_key?(:listen_ports)
apache[:contact] = "sysadmins@37signals.com" unless apache.has_key?(:contact)
apache[:timeout] = 300               unless apache.has_key?(:timeout)
apache[:keepalive] = "On"            unless apache.has_key?(:keepalive)
apache[:keepaliverequests] = 100     unless apache.has_key?(:keepaliverequests)
apache[:keepalivetimeout] = 5        unless apache.has_key?(:keepalivetimeout)

# Prefork Attributes
apache[:prefork] = Mash.new unless apache.has_key?(:prefork)
apache[:prefork][:startservers] = 16      unless apache[:prefork].has_key?(:prefork_startservers)
apache[:prefork][:minspareservers] = 16   unless apache[:prefork].has_key?(:prefork_minspareservers)
apache[:prefork][:maxspareservers] = 32   unless apache[:prefork].has_key?(:prefork_maxspareservers)
apache[:prefork][:maxclients] = 400       unless apache[:prefork].has_key?(:prefork_maxclients)
apache[:prefork][:maxrequestsperchild] = 10000 unless apache[:prefork].has_key?(:prefork_maxrequestsperchild)

# Worker Attributes
apache[:worker] = Mash.new unless apache.has_key?(:worker)
apache[:worker][:startservers] = 4        unless apache[:worker].has_key?(:startservers)
apache[:worker][:maxclients] = 1024       unless apache[:worker].has_key?(:maxclients)
apache[:worker][:minsparethreads] = 64    unless apache[:worker].has_key?(:minsparethreads)
apache[:worker][:maxsparethreads] = 192   unless apache[:worker].has_key?(:maxsparethreads)
apache[:worker][:threadsperchild] = 64    unless apache[:worker].has_key?(:threadsperchild)
apache[:worker][:maxrequestsperchild] = 0 unless apache[:worker].has_key?(:maxrequestsperchild)

# Module configuration
apache[:deflate] = Mash.new unless apache.has_key?(:deflate)
apache[:deflate][:mime_types] = %w(text/html text/plain text/xml application/xml application/xhtml+xml
                                text/javascript application/x-javascript application/javascript text/css) unless apache[:deflate].has_key?(:mime_types)

apache[:expires] = Mash.new unless apache.has_key?(:expires)
apache[:expires][:default] = "access plus 1 year" unless apache[:expires].has_key?(:default)                                
apache[:expires][:match] = "\.(ico|gif|jpe?g|png|js|css)$" unless apache[:expires].has_key?(:match)
apache[:expires][:set] = {"Cache-Control" => "public"} unless apache[:expires].has_key?(:set)
apache[:expires][:unset] = %w(Last-Modified ETag) unless apache[:expires].has_key?(:unset)
apache[:expires][:file_etag] = "None" unless apache[:expires].has_key?(:file_etag)
