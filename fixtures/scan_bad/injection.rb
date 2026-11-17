# Deliberately unsafe Ruby SQL string concatenation / interpolation and shell
# execution (CWE-89 / CWE-78): user input is spliced into query strings and
# shell commands instead of bind parameters / argument arrays.

def find_user(name)
  User.where("name = " + params[:name])
end

def count_rows(id)
  ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE a = " + id)
end

def get_user(name)
  User.find_by_sql("SELECT * FROM users WHERE name = '" + name + "'")
end

def update_project(val)
  Project.exec_query("UPDATE p SET x = " + val)
end

def wipe_logs(dir)
  system("rm -rf " + dir)
end

def run_cmd(cmd)
  exec("sh -c " + cmd)
end

def cat_file(file)
  `cat #{file}`
end

def grep_term(term)
  IO.popen("grep #{term}")
end

def list_dir(dir)
  Open3.capture2("ls " + dir)
end
