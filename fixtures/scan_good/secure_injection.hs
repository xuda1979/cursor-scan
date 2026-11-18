{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Database.PostgreSQL.Simple as PG
import Database.SQLite.Simple (exec, query_)
import Control.Concurrent.Async.Utils (callCommand, runCommand)

-- Parameterized query: ?-placeholder, bind args passed separately.
main :: IO ()
main = do
  uid <- getLine
  PG.execute conn "SELECT * FROM users WHERE id = ?" (Only uid)

-- Parameterized query: ?-placeholder with named binds.
  amt <- getLine
  exec conn2 "UPDATE accounts SET balance = ?" (Only amt)

-- Static SQL literal, no concatenation.
  query_ conn3 "SELECT 1"

-- Static command string, no concatenation.
  callCommand ("ls -la /tmp")

-- Static command string via system, no concatenation.
  system "mkdir -p /tmp/app"
