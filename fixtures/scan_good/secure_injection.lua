-- Secure LuaSQL / LuaSQLite3 usage (no findings): every query is sent
-- through parameterized ? placeholders with values bound separately by the
-- driver, and every shell invocation passes a static command string with
-- nothing to interpolate at runtime.
local luasql = require("luasql.sqlite3")
local env = assert(luasql.sqlite3())
local conn = assert(env:connect("secure.db"))
local sqlite3 = require("lsqlite3")
local db = assert(sqlite3.open("secure.db"))

local res = conn:execute("SELECT * FROM users WHERE name = ?", name)

local res2 = db:exec("DELETE FROM logs WHERE id = ?", id)

local res3 = conn:execute("SELECT COUNT(*) FROM logs")

local res4 = db:exec("UPDATE accounts SET balance = ? WHERE id = ?", amount, id)

os.execute("true")
local when = io.popen("date"):read("*a")
os.execute("echo cleanup && rm /tmp/*.tmp")

-- A static concat into a local variable is not a fall-through receiver call:
-- the fragment below is a constant (no runtime splice), and the os/io calls
-- on the following lines all pass static command strings.
local eq = "SELECT * FROM t WHERE a = " .. "1"
