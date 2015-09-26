require 'shellwords'

%w(comments entries new_footprints profiles relations users).each do |table|
  sql = "select sum(id) from #{table};"
  system("mysql -u root isucon5q #{sql.shellescape}")
end
