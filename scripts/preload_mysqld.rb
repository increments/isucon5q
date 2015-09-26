require 'shellwords'

%w(comments entries new_footprints profiles relations users).each do |table|
  sql = <<-END
    CREATE TABLE _preload LIKE #{table};
    ALTER TABLE  _preload ENGINE = BLACKHOLE;
    INSERT INTO  _preload SELECT * FROM #{table};
    DROP TABLE   _preload;
  END

  system("echo #{sql.shellescape} | mysql -u root isucon5q")
end
