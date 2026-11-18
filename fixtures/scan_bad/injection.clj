(ns app.db
  (:require [next.jdbc :as jdbc]
            [clojure.java.shell :refer [sh]]))

;; (str ...)-concatenated query string fed to next.jdbc execute!
(defn run-query [conn id]
  (jdbc/execute! conn (str "SELECT * FROM users WHERE id = " id)))

;; (str ...)-concatenated query string fed to next.jdbc/execute-one!
(defn update-balance [conn amt]
  (next.jdbc/execute-one! conn (str "UPDATE accounts SET balance = " amt)))

;; (format ...)-concatenated query string fed to jdbc/query
(defn delete-session [conn sid]
  (jdbc/query conn (format "DELETE FROM sessions WHERE sid = %s" sid)))

;; def-assigned (str ...) build consumed by a DB call on a later line
(def sql (str "SELECT * FROM orders WHERE uid = " uid))

;; (str ...)-built command string fed to clojure.java.shell/sh
(defn list-dir [dir]
  (clojure.java.shell/sh (str "ls -la " dir)))

;; (format ...)-built command string fed to shell/sh
(defn show-file [file]
  (sh (format "cat %s" file)))

;; (str ...)-built command string fed to aliased sh
(defn ping-host [host]
  (sh (str "ping -c 1 " host)))
