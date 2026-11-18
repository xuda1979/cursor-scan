(ns app.db
  (:require [next.jdbc :as jdbc]
            [clojure.java.shell :refer [sh]]))

;; Parameterized query: ?-placeholder, bind args passed as a vector.
(defn run-query [conn id]
  (jdbc/execute! conn ["SELECT * FROM users WHERE id = ?" id]))

;; Parameterized query with named binds.
(defn update-balance [conn amt]
  (next.jdbc/execute-one! conn ["UPDATE accounts SET balance = ?" amt]))

;; Static SQL literal, no concatenation.
(jdbc/query conn "SELECT 1")

;; Static command with argument list, no string concat.
(sh "ls" "-la" "/tmp")

;; Static command string, no concatenation.
(clojure.java.shell/sh "mkdir -p /tmp/app")
