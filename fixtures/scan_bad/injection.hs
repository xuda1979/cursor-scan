{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Database.PostgreSQL.Simple as PG
import Database.SQLite.Simple (exec, query_)
import Control.Concurrent.Async.Utils (callCommand, runCommand)

-- ++-concatenated query string fed to PG.execute
main :: IO ()
main = do
  uid <- getLine
  PG.execute conn "SELECT * FROM users WHERE id = " ++ uid

-- ++-concatenated query string fed to sqlite exec
  amt <- getLine
  exec conn2 "UPDATE accounts SET balance = " ++ show amt

-- ++-concatenated query string fed to query_
  lid <- getLine
  query_ conn3 "DELETE FROM sessions WHERE lid = " ++ lid

-- ++-concatenated query string via rawSql sink
  name <- getLine
  rawSql conn4 "SELECT * FROM orders WHERE uid = " ++ name

-- ++-concatenated command string fed to callCommand
  dir <- getLine
  callCommand ("ls " ++ dir)

-- ++-concatenated command string fed to runCommand
  file <- getLine
  runCommand ("cat " ++ file)

-- ++-concatenated command string fed to system
  host <- getLine
  system ("ping " ++ host)
