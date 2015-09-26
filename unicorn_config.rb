worker_processes 4
preload_app true
<<<<<<< HEAD
listen '/tmp/unicorn.sock'
if ['ISUCON_LOCAL']
  pid 'unicorn.pid'
else
  pid "/home/isucon/webapp/ruby/unicorn.pid"
end
