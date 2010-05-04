default.apache[:dir]     = "/etc/apache2" 
default.apache[:log_dir] = "/var/log/apache2"
default.apache[:user]    = "www-data"
default.apache[:binary]  = "/usr/sbin/apache2"
default.apache[:icondir] = "/usr/share/apache2/icons"
default.apache[:version] = "2.2.12-1ubuntu2"

default.apache[:listen_ports] = ["80"]     
default.apache[:contact] = "sysadmins@37signals.com" 
default.apache[:timeout] = 300
default.apache[:keepalive] = "Off"
default.apache[:keepaliverequests] = 12
default.apache[:keepalivetimeout] = 2

default.apache[:prefork] = Mash.new 
default.apache[:prefork][:startservers] = 16
default.apache[:prefork][:minspareservers] = 16
default.apache[:prefork][:maxspareservers] = 32
default.apache[:prefork][:maxclients] = 256
default.apache[:prefork][:maxrequestsperchild] = 10000

default.apache[:worker] = Mash.new
default.apache[:worker][:serverlimit] = 16
default.apache[:worker][:startservers] = 4
default.apache[:worker][:maxclients] = 1024
default.apache[:worker][:minsparethreads] = 64
default.apache[:worker][:maxsparethreads] = 192
default.apache[:worker][:threadsperchild] = 64
default.apache[:worker][:maxrequestsperchild] = 0

default.apache[:deflate][:mime_types] = %w(text/html text/plain text/xml application/xml application/xhtml+xml
                                           text/javascript application/x-javascript application/javascript text/css)
default.apache[:deflate][:disable] = false

default.apache[:expires][:default] = "access plus 1 year"
default.apache[:expires][:match] = "\.(ico|gif|jpe?g|png|js|css)$"
default.apache[:expires][:set] = {"Cache-Control" => "public"}
default.apache[:expires][:unset] = %w(Last-Modified ETag)
default.apache[:expires][:file_etag] = "None"
