require 'sinatra/base'
require 'mysql2'
require 'mysql2-cs-bind'
require 'tilt/erubis'
require 'erubis'

module Isucon5
  class AuthenticationError < StandardError; end
  class PermissionDenied < StandardError; end
  class ContentNotFound < StandardError; end
  module TimeWithoutZone
    def to_s
      strftime("%F %H:%M:%S")
    end
  end
  ::Time.prepend TimeWithoutZone
end

class Isucon5::WebApp < Sinatra::Base
  use Rack::Session::Cookie

  set :erb, escape_html: true
  set :public_folder, File.expand_path('../../static', __FILE__)
  #set :sessions, true
  set :session_secret, ENV['ISUCON5_SESSION_SECRET'] || 'beermoris'
  set :protection, true

  helpers do
    def config
      @config ||= {
        db: {
          host: ENV['ISUCON5_DB_HOST'] || 'localhost',
          port: ENV['ISUCON5_DB_PORT'] && ENV['ISUCON5_DB_PORT'].to_i,
          username: ENV['ISUCON5_DB_USER'] || 'root',
          password: ENV['ISUCON5_DB_PASSWORD'],
          database: ENV['ISUCON5_DB_NAME'] || 'isucon5q',
        },
      }
    end

    def db
      return Thread.current[:isucon5_db] if Thread.current[:isucon5_db]
      client = Mysql2::Client.new(
        host: config[:db][:host],
        port: config[:db][:port],
        username: config[:db][:username],
        password: config[:db][:password],
        database: config[:db][:database],
        reconnect: true,
      )
      client.query_options.merge!(symbolize_keys: true)
      Thread.current[:isucon5_db] = client
      client
    end

    def authenticate(email, password)
      query = <<-SQL
        SELECT id
        FROM users
        WHERE email = ? AND passhash = SHA2(CONCAT(?, salt), 512)
      SQL
      result = db.xquery(query, email, password).first
      unless result
        raise Isucon5::AuthenticationError
      end
      session[:user_id] = result[:id]
      result
    end

    def current_user
      return @user if @user
      unless session[:user_id]
        return nil
      end
      @user = db.xquery('SELECT id, account_name, nick_name, email FROM users WHERE id=?', session[:user_id]).first
      unless @user
        session[:user_id] = nil
        session.clear
        raise Isucon5::AuthenticationError
      end
      @user
    end

    def authenticated!
      unless current_user
        redirect '/login'
      end
    end

    def get_user(user_id)
      user = db.xquery('SELECT * FROM users WHERE id = ?', user_id).first
      raise Isucon5::ContentNotFound unless user
      user
    end

    def user_from_account(account_name)
      user = db.xquery('SELECT * FROM users WHERE account_name = ?', account_name).first
      raise Isucon5::ContentNotFound unless user
      user
    end

    def is_friend?(another_id)
      user_id = session[:user_id]
      return false if user_id == another_id
      one, another = user_id < another_id ? [another_id, user_id] : [user_id, another_id]
      !!db.xquery('SELECT 1 FROM relations WHERE one = ? AND another = ?', one, another).first
    end

    def is_friend_account?(account_name)
      is_friend?(user_from_account(account_name)[:id])
    end

    def permitted?(another_id)
      another_id == current_user[:id] || is_friend?(another_id)
    end

    def mark_footprint(user_id)
      return if user_id == current_user[:id]

      check_sql = <<-SQL
        select 1
        from new_footprints
        where user_id = #{user_id}
        and owner_id = #{current_user[:id]}
        and date(created_at) = date(now())
        limit 1
      SQL
      if db.query(check_sql).first
        db.query("update new_footprints set created_at = now() where user_id = #{user_id} and owner_id = #{current_user[:id]}")
      else
        db.query("INSERT INTO new_footprints (user_id,owner_id) VALUES (#{user_id},#{current_user[:id]})")
      end
    end

    PREFS = %w(
      未入力
      北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 新潟県 富山県
      石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 奈良県 和歌山県 鳥取県 島根県
      岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 熊本県 大分県 宮崎県 鹿児島県 沖縄県
    )
    def prefectures
      PREFS
    end
  end

  error Isucon5::AuthenticationError do
    session[:user_id] = nil
    halt 401, erubis(:login, layout: false, locals: { message: 'ログインに失敗しました' })
  end

  error Isucon5::PermissionDenied do
    halt 403, erubis(:error, locals: { message: '友人のみしかアクセスできません' })
  end

  error Isucon5::ContentNotFound do
    halt 404, erubis(:error, locals: { message: '要求されたコンテンツは存在しません' })
  end

  get '/login' do
    session.clear
    erb :login, layout: false, locals: { message: '高負荷に耐えられるSNSコミュニティサイトへようこそ!' }
  end

  post '/login' do
    authenticate params['email'], params['password']
    redirect '/'
  end

  get '/logout' do
    session[:user_id] = nil
    session.clear
    redirect '/login'
  end

  get '/' do
    authenticated!

    entries_query = 'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
    entries = db.xquery(entries_query, current_user[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }

    comments_for_me_query = <<-SQL
      SELECT
        users.account_name as account_name,
        users.nick_name as nick_name,
        comments.comment as comment,
        comments.created_at as created_at
      FROM comments, users
      WHERE entry_user_id = ?
      and comments.user_id = users.id
      ORDER BY comments.created_at DESC
      LIMIT 10
    SQL
    comments_for_me = db.xquery(comments_for_me_query, current_user[:id])

    friends_hash = {}
    another_frields_sql =<<-SQL
      select users.*
      from relations, users
      where one = #{current_user[:id]}
      and another = users.id
    SQL
    db.query(another_frields_sql).each do |record|
      friends_hash[record[:id]] = record
    end
    one_frields_sql =<<-SQL
      select users.*
      from relations, users
      where another = #{current_user[:id]}
      and one = users.id
    SQL
    db.query(one_frields_sql).each do |record|
      friends_hash[record[:id]] = record
    end
    friends_count = friends_hash.size

    # (1, 2, 3)
    friend_ids_str = "(#{friends_hash.keys.join(',')})"

    entries_of_friends_sql = <<-SQL
      select id, user_id, body, created_at
      from entries
      where user_id in #{friend_ids_str}
      order by created_at desc
      limit 10
    SQL
    entries_of_friends = db.query(entries_of_friends_sql).map do |entry|
      entry[:title] = entry[:body].split(/\n/).first
      entry
    end

    comments_of_friends_sql = <<-SQL
      select
        comments.id as id,
        comments.comment as comment,
        comments.user_id as user_id,
        comments.created_at as created_at,
        comments.entry_user_id as entry_user_id
      from comments
      where user_id in #{friend_ids_str}
      order by comments.created_at desc
      limit 10
    SQL
    comments_of_friends = db.query(comments_of_friends_sql)

    entry_owner_ids = comments_of_friends.map do |record|
      record[:entry_user_id]
    end.join(',')
    entry_owners_sql =<<-SQL
      select id, account_name, nick_name
      from users
      where id in (#{entry_owner_ids})
    SQL
    entry_owners_hash = {}
    db.query(entry_owners_sql).each do |record|
      entry_owners_hash[record[:id]] = record
    end

    footprints_sql = <<-SQL
      SELECT users.account_name as account_name, users.nick_name as nick_name, new_footprints.created_at as created_at
      FROM
        new_footprints,
        users
      WHERE
        user_id = #{current_user[:id]}
      AND
        users.id = owner_id
      ORDER BY new_footprints.created_at DESC
      LIMIT 10
    SQL
    footprints = db.query(footprints_sql)

    locals = {
      entries: entries,
      comments_for_me: comments_for_me,
      entries_of_friends: entries_of_friends,
      entry_owners_hash: entry_owners_hash,
      comments_of_friends: comments_of_friends,
      friends_count: friends_count,
      friends_hash: friends_hash,
      footprints: footprints
    }
    erb :index, locals: locals
  end

  get '/profile/:account_name' do
    authenticated!
    owner = user_from_account(params['account_name'])
    query = if permitted?(owner[:id])
              'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5'
            else
              'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :profile, locals: { owner: owner, entries: entries, private: permitted?(owner[:id]) }
  end

  post '/profile/:account_name' do
    authenticated!
    if params['account_name'] != current_user[:account_name]
      raise Isucon5::PermissionDenied
    end

    query = <<-SQL
      UPDATE users
      SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
      WHERE id = ?
    SQL
    db.xquery(
      query,
      params['first_name'],
      params['last_name'],
      params['sex'],
      params['birthday'],
      params['pref'],
      current_user[:id]
    )
    redirect "/profile/#{params['account_name']}"
  end

  get '/diary/entries/:account_name' do
    authenticated!
    owner = user_from_account(params['account_name'])
    query = if permitted?(owner[:id])
              'SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
            else
              'SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20'
            end
    entries = db.xquery(query, owner[:id])
      .map{ |entry| entry[:is_private] = (entry[:private] == 1); entry[:title], entry[:content] = entry[:body].split(/\n/, 2); entry }
    mark_footprint(owner[:id])
    erb :entries, locals: { owner: owner, entries: entries, myself: (current_user[:id] == owner[:id]) }
  end

  get '/diary/entry/:entry_id' do
    authenticated!
    entry = db.xquery('SELECT * FROM entries WHERE id = ?', params['entry_id']).first
    raise Isucon5::ContentNotFound unless entry
    entry[:title], entry[:content] = entry[:body].split(/\n/, 2)
    entry[:is_private] = (entry[:private] == 1)
    owner = get_user(entry[:user_id])
    if entry[:is_private] && !permitted?(owner[:id])
      raise Isucon5::PermissionDenied
    end

    comments_sql =<<-SQL
      select
        comments.comment as comment,
        comments.created_at as created_at,
        users.account_name as account_name,
        users.nick_name as nick_name
      from comments, users
      where user_id = users.id
      and entry_id = #{entry[:id]}
    SQL
    comments = db.query(comments_sql)

    mark_footprint(owner[:id])
    erb :entry, locals: { owner: owner, entry: entry, comments: comments }
  end

  post '/diary/entry' do
    authenticated!
    query = 'INSERT INTO entries (user_id, private, body) VALUES (?,?,?)'
    body = (params['title'] || "タイトルなし") + "\n" + params['content']
    db.xquery(query, current_user[:id], (params['private'] ? 1 : 0), body)
    redirect "/diary/entries/#{current_user[:account_name]}"
  end

  post '/diary/comment/:entry_id' do
    authenticated!
    entry = db.xquery('SELECT * FROM entries WHERE id = ?', params['entry_id']).first
    unless entry
      raise Isucon5::ContentNotFound
    end
    entry[:is_private] = (entry[:private] == 1)
    if entry[:is_private] && !permitted?(entry[:user_id])
      raise Isucon5::PermissionDenied
    end
    query = 'INSERT INTO comments (entry_id, user_id, comment, entry_user_id) VALUES (?,?,?,?)'
    db.xquery(query, entry[:id], current_user[:id], params['comment'], entry[:user_id])
    redirect "/diary/entry/#{entry[:id]}"
  end

  get '/footprints' do
    authenticated!
    footprints_sql = <<-SQL
      SELECT users.account_name as account_name, users.nick_name as nick_name, new_footprints.created_at as created_at
      FROM
        new_footprints,
        users
      WHERE
        user_id = #{current_user[:id]}
      AND
        users.id = owner_id
      ORDER BY new_footprints.created_at DESC
      LIMIT 10
    SQL
    footprints = db.query(footprints_sql)
    erb :footprints, locals: { footprints: footprints }
  end

  get '/friends' do
    authenticated!

    friends = db.query("select another as user_id, created_at from relations where one = #{current_user[:id]}").map do |record|
      [record[:user_id], record[:created_at]]
    end
    friends += db.query("select one as user_id, created_at from relations where another = #{current_user[:id]}").map do |record|
      [record[:user_id], record[:created_at]]
    end
    friends_list = friends.sort_by(&:last).reverse

    user_ids = friends.map(&:first)
    users = {}
    db.query("select id, account_name, nick_name from users where id in (#{user_ids.join(',')})").each do |record|
      users[record[:id]] = { account_name: record[:account_name], nick_name: record[:nick_name] }
    end

    erb :friends, locals: { friends_list: friends_list, users: users }
  end

  post '/friends/:account_name' do
    authenticated!
    unless is_friend_account?(params['account_name'])
      user = user_from_account(params['account_name'])
      unless user
        raise Isucon5::ContentNotFound
      end
      user_id = current_user[:id]
      another_id = user[:id]
      one, another = user_id < another_id ? [another_id, user_id] : [user_id, another_id]
      db.query("INSERT INTO relations (one, another) VALUES (#{one},#{another})")
      redirect '/friends'
    end
  end

  get '/initialize' do
    db.query("DELETE FROM relations WHERE id > 500000")
    db.query("DELETE FROM new_footprints WHERE id > 500000")
    db.query("DELETE FROM entries WHERE id > 500000")
    db.query("DELETE FROM comments WHERE id > 1500000")
  end
end
