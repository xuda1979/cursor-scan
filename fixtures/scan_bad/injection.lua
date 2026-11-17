-- Deliberately unsafe Lua SQL string splicing and shell execution
-- (CWE-89 / CWE-78): user-controlled values are concatenated into query
-- strings with Lua's `..` operator or string.format() verbs and handed to
-- LuaSQL / LuaSQLite3 receivers, and shell commands go through os.execute /
-- io.popen with a `..`- or string.format()-built command string, instead of
-- parameterized ? placeholders / static command strings.
local luasql = require("luasql.sqlite3")
local env = assert(luasql.sqlite3())
local conn = assert(env:connect("t.db"))
local sqlite3 = require("lsqlite3")
local db = assert(sqlite3.open("t.db"))

-- FINDING 1: `..` concatenation splices user input into the SQL.
local res = conn:execute("SELECT * FROM users WHERE name = '" .. name .. "'")

-- FINDING 2: string.format() fills a %s verb inside the SQL literal.
local res2 = conn:execute(string.format("DELETE FROM logs WHERE id = %s", id))

-- FINDING 3: `..` concatenation builds the command passed to os.execute.
os.execute("rm -rf /tmp/" .. dir)

-- FINDING 4: string.format() builds the command passed to io.popen.
local out = io.popen(string.format("ls -la %s", dir)):read("*a")

-- NOT findings: parameterized ? placeholders and static command strings.
-- conn:execute("SELECT ... ?", name) binds the value separately through the
-- driver; db:exec with a plain ? placeholder is the parameterized LuaSQLite3
-- bind form.  A static query literal has no splice, and os.execute / io.popen
-- called with a static command have nothing runtime to interpolate.
local ok = conn:execute("SELECT * FROM users WHERE name = ?", name)
local ok2 = db:exec("DELETE FROM logs WHERE id = ?", id)
local static = conn:execute("SELECT COUNT(*) FROM logs")
os.execute("true")
local when = io.popen("date"):read("*a")
local eq = "SELECT * FROM t WHERE a = " .. "1"
