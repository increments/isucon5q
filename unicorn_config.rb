worker_processes 4
preload_app true
listen 8080
if ['ISUCON_LOCAL']
  pid 'unicorn.pid'
else
  pid "/home/isucon/webapp/ruby/unicorn.pid"
end
